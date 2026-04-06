import asyncio
import json
import queue
import subprocess
from datetime import datetime

from backend.collector.dispatcher import EventDispatcher
from backend.collector.online_worker import OnlineWorker
from backend.collector.storage_worker import StorageWorker
from backend.collector.enrichment import enrich_openat_event


OPENAT_BINARY = ["./ebpf/openat"]

PROJECT_ROOT = "/home/yuval/secubernetes"

NOISY_PREFIXES = (
    "/proc/",
    "/sys/",
    f"{PROJECT_ROOT}/backend/",
    f"{PROJECT_ROOT}/ebpf/",
    f"{PROJECT_ROOT}/.git/",
)

NOISY_PATH_CONTAINS = (
    "/__pycache__",
    "/site-packages/",
    "/.venv/",
)

NOISY_COMMS = {
    "containerd-shim",
    "ftdc",
}


def should_skip_event(data: dict) -> bool:
    filename = data.get("filename", "")
    comm = data.get("comm", "")

    if filename.startswith(NOISY_PREFIXES):
        return True

    if any(token in filename for token in NOISY_PATH_CONTAINS):
        return True

    if comm in NOISY_COMMS:
        return True

    return False


def get_ppid_from_pid(pid: int):
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except Exception:
        return None
    return None


def build_event(data: dict) -> dict:
    pid = data["pid"]
    ppid = get_ppid_from_pid(pid)

    return {
        "event_type": "openat",
        "ts": datetime.utcnow(),
        "pid": pid,
        "ppid": ppid,
        "ppid_status": "resolved" if ppid is not None else "pid_disappeared",
        "uid": data["uid"],
        "comm": data["comm"],
        "filename": data["filename"],
        "dfd": data["dfd"],
        "flags": data["flags"],
        "source": "libbpf_perf_buffer",
    }


async def start_openat_process():
    process = subprocess.Popen(
        OPENAT_BINARY,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    await asyncio.sleep(1)

    if process.poll() is not None:
        err = process.stderr.read()
        print("openat userspace binary failed:")
        print(err)
        return None

    return process


async def run_collector():
    print("Starting openat collector from libbpf userspace binary...")

    db_queue = queue.Queue(maxsize=10000)
    online_queue = queue.Queue(maxsize=10000)

    dispatcher = EventDispatcher(db_queue=db_queue, online_queue=online_queue)

    storage_worker = StorageWorker(
        db_queue=db_queue,
        batch_size=20,
        flush_interval=2.0,
    )
    online_worker = OnlineWorker(
        online_queue=online_queue,
        window_seconds=30,
        burst_threshold=8,
    )

    storage_worker.start()
    online_worker.start()

    process = await start_openat_process()
    if process is None:
        return

    try:
        while True:
            line = process.stdout.readline()

            if not line:
                if process.poll() is not None:
                    err = process.stderr.read()
                    print("openat userspace binary exited:")
                    print(err)
                    break
                continue

            line = line.strip()

            if not line.startswith("{"):
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            if should_skip_event(data):
                continue

            event = build_event(data)
            event = enrich_openat_event(event)

            print(
                f"[collector-openat] pid={event['pid']} ppid={event['ppid']} uid={event['uid']} "
                f"{event['comm']} -> {event['filename']} "
                f"container={event.get('container_id')} lineage={event.get('lineage', {}).get('summary')}"
            )

            dispatcher.dispatch(event)

    except KeyboardInterrupt:
        print("Stopping openat collector...")
    finally:
        storage_worker.stop()
        online_worker.stop()
        process.terminate()


if __name__ == "__main__":
    asyncio.run(run_collector())