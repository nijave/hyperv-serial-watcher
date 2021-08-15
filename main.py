import asyncio
import datetime
import json
import logging
import queue
import re
import sys
import threading
import time
import typing
from dataclasses import dataclass
import requests

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

    def __init__(self, start: bool = False):
        self.queue = queue.Queue()
        self._socket_mutex = threading.Lock()
        self._worker = threading.Thread(target=self._process_events)
        self._session = requests.Session()
        if start:
            self._worker.start()

    def start(self):
        self._worker.start()

    def stop(self):
        logger.debug("Putting log shipper stop message")
        self.queue.put(None)
        logger.info("Waiting for log queue to empty")
        self._worker.join()
        logger.debug("Log queue is empty")

    def _process_events(self):
        while event := self.queue.get():
            self._write(event)

    def _write(self, data):
        # TODO, check for errors? retry?
        self._session.post(
            f"http://{sys.argv[1]}",
            json=data,
        )


class MachineEventEmitter:
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
        self.watcher = None
        self.ready = asyncio.Event()

    async def events(self) -> typing.AsyncGenerator[VMInfo, None]:
        await self._create_event_monitor_process()

        logger.info("Processing events")
        while True:
            logger.debug("Waiting for event")
            # TODO handle powershell crashes
            event = await self.watcher.stdout.readline()
            event = event.decode()
            if not event:
                break
            event = event.strip()
            if event[0] != "{" or event[-1] != "}":
                logger.debug("%s", event)
                continue
            logger.info("Got event %s", event)
            data = json.loads(event)

            data["ComPort1Path"] = await self._get_serial_path(data["Name"])

            yield VMInfo(
                id=data["Name"],
                name=data["ElementName"],
                serial_port_path=data["ComPort1Path"],
            )

    async def list_virtual_machine_ports(self):
        vm_data = await self._ps_exec(
            "Get-VM"
            " | Select Id, VMName, @{n='Path'; e={$_.ComPort1.Path}}"
            " | Where-Object {$_.Path}"
        )

        return [
            VMInfo(
                id=vm["Id"],
                name=vm["VMName"],
                serial_port_path=vm["Path"],
            )
            for vm in vm_data
        ]

    async def _signal_ready(self):
        # WMI Event subscription has 2 second interval
        await asyncio.sleep(2)
        logger.info("Setting event watcher task ready")
        self.ready.set()

    async def _create_event_monitor_process(self):
        logger.info("Creating event watcher process")
        self.watcher = await asyncio.create_subprocess_exec(
            "powershell",
            "-Command",
            "-",
            stdin=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )

        logger.info("Registering WMI event")
        event_command = r"""
            $ew = Register-WmiEvent 
              -Namespace root\virtualization\v2 
              -Query "SELECT * FROM __InstanceModificationEvent WITHIN 2 WHERE TargetInstance ISA 'Msvm_ComputerSystem' AND TargetInstance.EnabledState = 2" 
              -Action {
                $e = $EventArgs.NewEvent.TargetInstance | Select HealthState, EnabledState, RequestedState, ElementName, Name;
                Write-Host ($e | ConvertTo-Json -Compress)
              }
        """.replace(
            "\n", ""
        ).encode()
        logger.debug("Event command %s", event_command)
        self.watcher.stdin.write(event_command)
        self.watcher.stdin.write(b"\r\n")

        logger.debug("Waiting for watcher process stdin to drain")
        await self.watcher.stdin.drain()

        async def check_errors():
            while not self.watcher.stderr.at_eof():
                err = await self.watcher.stderr.readline()
                err = err.decode().strip()
                if err:
                    logger.warning("%s", err)
                if " FullyQualifiedErrorId " in err:
                    logger.error(
                        "Event watcher process logged an error. Terminating process"
                    )
                    self.watcher.terminate()

        asyncio.create_task(check_errors())
        await self._signal_ready()

    async def _get_serial_path(self, vm_id: VmGuid) -> str:
        if not re.match(r"^[A-Fa-f0-9-]+$", vm_id):
            logger.warning("Not a VmGuid %s", vm_id)
            raise ValueError("VM GUID required")

        serial_port_path = ""
        try:
            serial_port_path = await self._ps_exec(
                f"(Get-VM -Id {vm_id}).ComPort1.Path"
            )
        except AttributeError as e:
            logger.warning("Couldn't get serial port data for %s", vm_id)
            logger.error(e)

        return serial_port_path

    @staticmethod
    async def _ps_exec(command: str) -> str:
        command += " | ConvertTo-Json"
        logger.debug("PS EXEC %s", command)
        start = time.time()
        exec_result = await asyncio.create_subprocess_exec(
            "powershell", "-Command", command, stdout=asyncio.subprocess.PIPE
        )

        stdout, _ = await exec_result.communicate()
        stdout = stdout.decode().strip()
        for line in stdout.splitlines():
            logger.debug("PS OUT %s", line)

        rc = exec_result.returncode
        if rc != 0:
            logger.warning("PS ERR %d", rc)
            decoded_result = ""
        else:
            decoded_result = json.loads(stdout)

        logger.debug("Completed `%s` in %.2f seconds", command, time.time() - start)
        return decoded_result


class SerialTail:
    def __init__(self, *, message_queue: queue.Queue):
        self._watchers = {}
        self._queue = message_queue

    def shutdown(self):
        self._prune_watchers(prune_all=True)

    def watch(self, vm: VMInfo) -> None:
        logger.info("Attempting to start watcher for %s (%s)", vm.name, vm.id)
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
            ),
        )

        out_t.daemon = True

        out_t.start()
        self._watchers[vm.id] = out_t
        self._prune_watchers()

    @classmethod
    def _watch_events(cls, vm: VMInfo, out_q: queue.Queue):
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        initial_tries = 10
        remaining_tries = initial_tries
        while remaining_tries > 0:
            try:
                with open(vm.serial_port_path, "r") as pipe:
                    logger.info("Successfully opened %s", vm.serial_port_path)
                    # TODO convert to async so reading pipe doesn't block shutdown event
                    while event := pipe.readline():
                        message = ansi_escape.sub("", event.strip("\r\n"))
                        logger.debug("Got %s", message)
                        if not message:
                            continue
                        out_q.put(
                            {
                                "time": datetime.datetime.now().isoformat(),
                                "id": vm.id,
                                "hostname": vm.name,
                                "message": message,
                            }
                        )
            # Not sure if there's any other case this can happen besides VM is powered off
            except FileNotFoundError:
                # These cases can be ignored since the event watching code will catch startup events and retry
                # the port watcher thread for that VM
                logger.info(
                    "Pipe %s (for %s/%s) doesn't currently exist. VM likely isn't running",
                    vm.serial_port_path,
                    vm.name,
                    vm.id,
                )
                break
            except OSError as e:
                # When the pipe is already open somewhere else
                if e.errno == 22:
                    remaining_tries -= 1
                    logger.info(
                        "Pipe %s (for %s/%s) isn't available. Retrying",
                        vm.serial_port_path,
                        vm.name,
                        vm.id,
                    )
                    # .05 -> [0.1, 0.2, 0.4, 0.8, 1.6, 3.2, 6.4, 12.8, 25.6]
                    time.sleep(0.05 * 2 ** (initial_tries - remaining_tries))
                    continue

                logger.debug("Error attributes %s", dir(e))
                logger.exception(e)
                break

        if remaining_tries == 0:
            logger.warning(
                "Ran out of retries waiting on %s (for %s/%s)",
                vm.serial_port_path,
                vm.name,
                vm.id,
            )
        else:
            logger.info("Stopping logger for %s", vm.serial_port_path)

    def _prune_watchers(self, prune_all: bool = False):
        for vm_id in list(self._watchers.keys()):
            if not self._watchers[vm_id].is_alive():
                logger.warning("Removing dead watcher for %s", vm_id)
                self._watchers[vm_id].join()
                del self._watchers[vm_id]


async def process_events(*, event_emitter: MachineEventEmitter) -> None:
    event_task = asyncio.create_task(watch_events(event_emitter=event_emitter))

    await event_emitter.ready.wait()
    vm_list = await event_emitter.list_virtual_machine_ports()
    logger.info("Found %s with COM ports", [v.name for v in vm_list])
    for vm_info in vm_list:
        watcher.watch(vm_info)

    logger.info("Waiting on event watcher task")
    await event_task
    logger.info("Event watcher task completed")

async def watch_events(*, event_emitter: MachineEventEmitter) -> None:
    events = event_emitter.events()
    async for vm_event in events:
        logger.info("Got vm_event %s", vm_event)

if __name__ == "__main__":
    import signal

    # see https://stackoverflow.com/a/37420223/2751619
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    if log_level not in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"):
        log_level = "INFO"

    logging.basicConfig(
        format="%(asctime)s:%(levelname)7s:%(process)8d:%(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        level=getattr(logging, log_level),
    )

    mem = MachineEventEmitter()
    shipper = LogShipper(start=True)
    watcher = SerialTail(message_queue=shipper.queue)

    loop = asyncio.get_event_loop()
        loop.run_until_complete(process_events(event_emitter=mem))

    logger.info("Event loop complete")
    logger.info("Shutting down watcher")
    watcher.shutdown()

    logger.info("Shutting down log shipper")
    shipper.stop()
