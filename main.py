import datetime
import json
import logging
import os
import pathlib
import queue
import re
import subprocess
import sys
import threading
import time
import types
import typing
from dataclasses import dataclass
from urllib.request import Request, urlopen

import psutil
import pythoncom
import wmi as wmilib

logger = logging.getLogger(__name__)
PLINK_VERSION = "0.76"

VmGuid = str


@dataclass
class VMInfo:
    id: VmGuid
    name: str
    serial_port_path: str


class DownloadService:
    @staticmethod
    def get(url):
        with urlopen(url) as response:
            return response.read()

    @classmethod
    def save(cls, url, filename):
        path = cls._script_directory() / filename
        if not path.parent.is_dir():
            path.parent.mkdir()

        logger.info("Downloading %s", url)
        request = Request(
            url,
            data=None,
        )

        with urlopen(request) as response:
            with open(path, "wb") as f:
                while data := response.read(4 * 1024 * 1024):
                    logger.info("Wrote %d bytes to %s", len(data), filename)
                    f.write(data)

    @staticmethod
    def _script_directory():
        return pathlib.Path(os.path.realpath(__file__)).parent


class LogShipper:
    """
    Send logs over tcp
    """

    def __init__(self):
        self.queue = queue.Queue()
        self._socket_mutex = threading.Lock()
        self._worker = threading.Thread(target=self._process_events)

    def start(self):
        self._worker.start()

    def stop(self):
        self.queue.put(None)

    def _process_events(self):
        while event := self.queue.get():
            payload = json.dumps(event).encode("utf-8")
            # with self._socket_mutex:
            self._write(payload)

    @staticmethod
    def _write(data):
        urlopen(
            Request(
                url=f"http://{sys.argv[1]}",
                method="POST",
                headers={"Content-Type": "application/json"},
                data=data,
            )
        )


class MachineEventManager:
    """
    Process VM change events using WMI event subscription
    """

    ENUMS = {
        "Msvm_ComputerSystem": {
            "EnabledState": {
                0: "Unknown",
                1: "Other",
                2: "Enabled",
                3: "Disabled",
                4: "Shutting Down",
                5: "Not Applicable",
                6: "Enabled but Offline",
                7: "In Test",
                8: "Deferred",
                9: "Quiesce",
                10: "Starting",
            },
            "HealthState": {
                5: "OK",
                20: "Major Failure",
                25: "Critical Failure",
            },
            "OperationalStatus": {
                2: "OK",
                3: "Degraded",
                5: "Predictive Failure",
                10: "Stopped",
                11: "In Service",
                15: "Dormant",
            },
        }
    }

    ENUMS["Msvm_ComputerSystem"]["RequestedState"] = ENUMS["Msvm_ComputerSystem"][
        "EnabledState"
    ]

    def __init__(self):
        self.wmi = wmilib.WMI(namespace=r"root\virtualization\v2")
        self.watcher = self.wmi.ExecNotificationQuery(
            """
            SELECT *
            FROM __InstanceModificationEvent
            WITHIN 2
            WHERE
                TargetInstance ISA 'MSVM_ComputerSystem'
            """
            # OR TargetInstance ISA 'Msvm_SerialPortSettingData'
        )

    def events(self) -> typing.Generator[VMInfo, None, None]:
        while e := self.watcher.NextEvent():
            inst = e.TargetInstance
            # TODO hard code list of attributes actually used
            attrs = [
                a
                for a in dir(inst)
                if not a.endswith("_")
                and not a.startswith("_")
                and not isinstance(getattr(inst, a), types.MethodType)
            ]
            raw_data = {a: getattr(inst, a) for a in attrs}
            if inst.Path_.Class == "Msvm_ComputerSystem":
                data = {
                    k: self.ENUMS["Msvm_ComputerSystem"][k][v]
                    for k, v in raw_data.items()
                    if k in ["HealthState", "EnabledState", "RequestedState"]
                } | {k: v for k, v in raw_data.items() if k in ["ElementName", "Name"]}

                # Only running machines have serial ports
                if data["EnabledState"] not in ["Starting", "Enabled"]:
                    continue

                data["ComPort1Path"] = self._get_serial_path(data["Name"])

                yield VMInfo(
                    id=data["Name"],
                    name=data["ElementName"],
                    serial_port_path=data["ComPort1Path"],
                )
            else:
                logger.info("%s", json.dumps(raw_data))

    def _get_serial_path(self, vm_id: VmGuid) -> str:
        if not re.match(r"^[A-Fa-f0-9-]+$", vm_id):
            logger.warning("Not a VmGuid %s", vm_id)
            raise ValueError("VM GUID required")

        serial_port_path = ""
        try:
            serial_port_path = (
                (
                    [
                        p
                        for p in self.wmi.Msvm_ComputerSystem(Name=vm_id)[
                            0
                        ].associators(wmi_result_class="Msvm_SerialPort")
                        if p.Caption == "COM 1"
                    ]
                    + [None]
                )[0]
                .associators(wmi_result_class="Msvm_SerialPortSettingData")[0]
                .Connection[0]
            )
        except AttributeError as e:
            logger.warning("Couldn't get serial port data for %s", vm_id)
            logger.error(e)

        return serial_port_path


class SerialWatcher:
    PATH = r"vendor/plink.exe"

    def __init__(self, message_q: queue.Queue):
        self._download()
        self._processes = {}
        self._shutdown = threading.Event()
        self._queue = message_q

    def shutdown(self):
        self._shutdown.set()

    def watch(self, vm: VMInfo) -> None:
        if vm.id in self._processes:
            if self._processes[vm.id].is_alive():
                logger.warning("Logger already running for %s", vm.id)
                return

            logger.info(
                "Serial watcher is terminated for %s",
                vm.id,
            )
            self._processes[vm.id].join()
            del self._processes[vm.id]

        out_t = threading.Thread(
            target=self._watch_events,
            kwargs=dict(
                vm=vm,
                out_q=self._queue,
                shutdown=self._shutdown,
            ),
        )

        out_t.start()
        self._processes[vm.id] = out_t

    @classmethod
    def _download(cls):
        if pathlib.Path(cls.PATH).is_file():
            logger.info("%s already exists", cls.PATH)
            return

        DownloadService.save(
            f"https://the.earth.li/~sgtatham/putty/{PLINK_VERSION}/w64/plink.exe",
            cls.PATH,
        )

    @staticmethod
    def _start_plink(vm: VMInfo) -> subprocess.Popen:
        candidates = psutil.process_iter(["pid", "name", "cmdline"])

        logger.info("%s", candidates)

        for c in candidates:
            if f"-serial {vm.serial_port_path}" in c.cmdline():
                logger.info("Killing orphaned plink %d %s", c.pid(), c.cmdline())
                c.kill()
                c.wait(timeout=10)

        logger.info("Starting plink process")
        args = [
            r"vendor\plink.exe",
            "-batch",
            "-v",
            "-serial",
            vm.serial_port_path,
            "-sercfg",
            "115200,8,1,N,N",
        ]
        logger.info("%s", " ".join(args))
        process = subprocess.Popen(  # pylint: disable=consider-using-with
            args,
            stdout=subprocess.PIPE,
            bufsize=16 * 1024 * 1024,  # 16mb
            text=True,
        )

        return process

    @classmethod
    def _watch_events(cls, vm: VMInfo, out_q: queue.Queue, shutdown: threading.Event):
        logger.info("Checking for orphaned plink processes")
        pythoncom.CoInitialize()  # needed for hyper-v vm status

        while not shutdown.is_set():
            process = cls._start_plink(vm)

            while process.poll() is None:
                event = process.stdout.readline().rstrip()
                if not event:
                    time.sleep(0.5)
                    continue

                out_q.put(
                    {
                        "time": datetime.datetime.now().isoformat(),
                        "id": vm.id,
                        "hostname": vm.name,
                        "message": event,
                    }
                )

            vm_data = wmilib.WMI(
                namespace=r"root\virtualization\v2"
            ).Msvm_ComputerSystem(Name=vm.id)[0]

            if vm_data.EnabledState not in [2, 10]:
                break

            logger.info("plink exited with %s", str(process.poll()))
            logger.info("VM is %d--restarting plink", vm_data.EnabledState)

        if process.poll() is not None:
            process.terminate()


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s:%(levelname)1s:%(process)8d:%(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        level=logging.INFO,
    )

    manager = MachineEventManager()
    events = manager.events()
    shipper = LogShipper()
    shipper.start()
    watcher = SerialWatcher(shipper.queue)

    while True:
        event = next(events)
        logger.info("Got event %s", event)

        if not event.serial_port_path:
            logger.warning("No serial port found for %s", event.name)
            continue

        watcher.watch(event)
