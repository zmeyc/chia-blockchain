import signal
import asyncio
import logging
import pathlib
import socket
import time
import pkg_resources
from src.util.logging import initialize_logging
from src.util.config import load_config
from typing import List
from src.util.default_root import DEFAULT_ROOT_PATH
from src.util.setproctitle import setproctitle

active_processes: List = []
stopped = False
lock = asyncio.Lock()

log = logging.getLogger(__name__)


async def kill_processes():
    global stopped
    global active_processes
    async with lock:
        stopped = True
        for process, _ in active_processes:
            try:
                process.kill()
            except ProcessLookupError:
                pass


def find_vdf_client():
    p = pathlib.Path(pkg_resources.get_distribution("chiavdf").location) / "vdf_client"
    if p.is_file():
        return p
    raise FileNotFoundError("can't find vdf_client binary")

async def kill_stalled_processes():
    global stopped
    global active_processes
    while not stopped:
        async with self.lock:
            for proc, start_time in self.active_processes:
                if time.time() - start_time > 2 * 3600:
                    # Process is probably stalled, stop it.
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
            self.active_processes = [
                (proc, start_time)
                for proc, start_time in self.active_processes
                if time.time() - start_time <= 2 * 3600
            ]
        await asyncio.sleep(60)

async def spawn_process(host, port, counter):
    global stopped
    global active_processes
    path_to_vdf_client = find_vdf_client()
    cleanup_task = asyncio.create_task(kill_stalled_processes())
    while not stopped:
        try:
            dirname = path_to_vdf_client.parent
            basename = path_to_vdf_client.name
            resolved = socket.gethostbyname(host)
            proc = await asyncio.create_subprocess_shell(
                f"{basename} {resolved} {port} {counter}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"PATH": dirname},
            )
        except Exception as e:
            log.warning(f"Exception while spawning process {counter}: {(e)}")
            continue
        async with lock:
            active_processes.append((proc, time.time()))
        stdout, stderr = await proc.communicate()
        if stdout:
            log.info(f"Stdout:\n{stdout.decode().rstrip()}")
        if stderr:
            log.error(f"Stderr:\n{stderr.decode().rstrip()}")
        log.info(f"Process number {counter} ended.")
        async with lock:
            if proc, start_time in active_processes:
                active_processes.remove((proc, start_time))
        await asyncio.sleep(0.1)
    cleanup_task.cancel()

async def spawn_all_processes(config, net_config):
    await asyncio.sleep(5)
    port = config["port"]
    process_count = config["process_count"]
    awaitables = [spawn_process(net_config["self_hostname"], port, i) for i in range(process_count)]
    await asyncio.gather(*awaitables)


def main():
    root_path = DEFAULT_ROOT_PATH
    setproctitle("chia_timelord_launcher")
    net_config = load_config(root_path, "config.yaml")
    config = net_config["timelord_launcher"]
    initialize_logging("TLauncher", config["logging"], root_path)

    def signal_received():
        asyncio.create_task(kill_processes())

    loop = asyncio.get_event_loop()

    try:
        loop.add_signal_handler(signal.SIGINT, signal_received)
        loop.add_signal_handler(signal.SIGTERM, signal_received)
    except NotImplementedError:
        log.info("signal handlers unsupported")

    try:
        loop.run_until_complete(spawn_all_processes(config, net_config))
    finally:
        log.info("Launcher fully closed.")
        loop.close()


if __name__ == "__main__":
    main()
