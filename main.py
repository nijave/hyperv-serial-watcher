import datetime
import io
import json
import logging
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

import wmi as wmilib

logger = logging.getLogger(__name__)

VmGuid = str


@dataclass
class VMInfo:
    id: VmGuid
    name: str
    serial_port_path: str


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
            self._write(payload)

    @staticmethod
    def _write(data):
        # TODO, check for errors? retry? use requests module?
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
    Process VM change events using WMI vm_event subscription
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
        # TODO probably can be replaced with Register-WmiEvent outputting
        # json lines to remove wmi dep
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

    def list_virtual_machine_ports(self):
        vm_data = self._ps_exec(
            "Get-VM"
            " | Select Id, VMName, @{n='Path'; e={$_.ComPort1.Path}}"
            " | Where-Object {$_.Path}"
            " | ConvertTo-Json"
        )

        return [
            VMInfo(
                id=vm["Id"],
                name=vm["VMName"],
                serial_port_path=vm["Path"],
            )
            for vm in vm_data
        ]

    def _get_serial_path(self, vm_id: VmGuid) -> str:
        if not re.match(r"^[A-Fa-f0-9-]+$", vm_id):
            logger.warning("Not a VmGuid %s", vm_id)
            raise ValueError("VM GUID required")

        serial_port_path = ""
        try:
            serial_port_path = self._ps_exec(
                f"(Get-VM -Id {vm_id}).ComPort1.Path"
            )
        except AttributeError as e:
            logger.warning("Couldn't get serial port data for %s", vm_id)
            logger.error(e)

        return serial_port_path

    @staticmethod
    def _ps_exec(command: str):
        start = time.time()
        exec_result = subprocess.check_output(
            ["powershell", "-Command", command], text=True
        ).strip()

        decoded_result = json.loads(exec_result)
        logger.debug("Completed `%s` in %d", command, time.time() - start)
        return decoded_result


class SerialWatcher:
    def __init__(self, message_q: queue.Queue):
        self._watchers = {}
        self._shutdown = threading.Event()
        self._queue = message_q

    def shutdown(self) -> None:
        self._shutdown.set()

    def watch(self, vm: VMInfo) -> None:
        logger.info("Attempting to start watcher for %s", vm.name)
        if vm.id in self._watchers:
            if self._watchers[vm.id].is_alive():
                logger.warning("Logger already running for %s", vm.id)
                return

            logger.info(
                "Serial watcher is terminated for %s and will be replaced",
                vm.name,
            )
            self._watchers[vm.id].join()
            del self._watchers[vm.id]

        out_t = threading.Thread(
            target=self._watch_events,
            kwargs=dict(
                vm=vm,
                out_q=self._queue,
                shutdown=self._shutdown,
            ),
        )

        out_t.start()
        self._watchers[vm.id] = out_t
        self._prune_watchers()

    @classmethod
    def _watch_events(cls, vm: VMInfo, out_q: queue.Queue, shutdown: threading.Event):
        try:
            with open(vm.serial_port_path, "r") as pipe:
                while not shutdown.is_set() and (event := pipe.readline()):
                    out_q.put(
                        {
                            "time": datetime.datetime.now().isoformat(),
                            "id": vm.id,
                            "hostname": vm.name,
                            "message": event,
                        }
                    )
        # Not sure if there's any other case this can happen besides VM is powered off
        except FileNotFoundError:
            # These cases can be ignored since the event watching code will catch startup events and retry
            # the port watcher thread for that VM
            logger.error(
                "Pipe %s doesn't currently exist. VM likely isn't running",
                vm.serial_port_path,
            )
        # TODO handle OSError 22/ctypes.WinError() 6 when pipe is already opened somewhere else
        # There are probably other reasons to get this generic error besides ^^
        except OSError as e:
            logger.debug("Error attributes %s", dir(e))
            logger.exception(e)

    def _prune_watchers(self):
        for vm_id in list(self._watchers.keys()):
            if not self._watchers[vm_id].is_alive():
                logger.warning("Removing dead watcher for %s", vm_id)
                del self._watchers[vm_id]


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s:%(levelname)1s:%(process)8d:%(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        level=logging.DEBUG,
    )

    manager = MachineEventManager()
    events = manager.events()
    shipper = LogShipper()
    shipper.start()
    watcher = SerialWatcher(shipper.queue)

    vm_list = manager.list_virtual_machine_ports()
    logger.info("Found %s with COM ports", [v.name for v in vm_list])
    for vm_info in vm_list:
        watcher.watch(vm_info)

    # TODO event watcher should start before static list to avoid race condition
    # e.g. VM start after list before event watcher is started
    while True:
        vm_event = next(events)
        logger.info("Got vm_event %s", vm_event)

        if not vm_event.serial_port_path:
            logger.warning("No serial port found for %s", vm_event.name)
            continue

        watcher.watch(vm_event)
