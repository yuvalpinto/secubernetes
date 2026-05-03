import asyncio
import json
import queue
from datetime import datetime

from backend.collector.dispatcher import EventDispatcher
from backend.collector.online_worker import OnlineWorker
from backend.collector.storage_worker import StorageWorker
from backend.utils.process_lineage import ProcessLineageTracker
from backend.utils.container_resolver import (
    resolve_container_info_from_pid,
    resolve_container_info_from_cgroup_id,
)

from backend.collector.feature_worker import FeatureWorker

EXECVE_BINARY = ["./ebpf/execve"]
OPENAT_BINARY = ["./ebpf/openat"]
CONNECT_BINARY = ["./ebpf/connect"]

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


def get_ppid_from_pid(pid: int):
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except Exception:
        return None
    return None


def enrich_common_fields(event: dict, lineage_tracker) -> dict:
    pid = event.get("pid")
    ppid = event.get("ppid")
    event_type = event.get("event_type")
    cgroup_id = event.get("cgroup_id")

    # כרגע כל אירוע שמגיע עם cgroup_id עובר דרך המסלול החדש.
    # אם resolve_container_info_from_cgroup_id הוא עדיין placeholder,
    # פשוט תקבל resolver_status מתאים בלי container mapping אמיתי.
    if cgroup_id is not None:
        container_info = resolve_container_info_from_cgroup_id(cgroup_id)
    else:
        container_info = resolve_container_info_from_pid(
            pid=pid,
            ppid=ppid,
            allow_parent_fallback=True,
        )

    event.update(container_info)

    if pid is not None:
        event = lineage_tracker.enrich_event(event)

    event.setdefault("container_id", None)
    event.setdefault("pod_uid", None)
    event.setdefault("pod_name", None)
    event.setdefault("namespace", None)
    event.setdefault("container_name", None)
    event.setdefault("runtime", None)
    event.setdefault("resolver_status", None)

    return event


def should_skip_openat(data: dict) -> bool:
    filename = data.get("filename", "")
    comm = data.get("comm", "")

    if filename.startswith(NOISY_PREFIXES):
        return True

    if any(token in filename for token in NOISY_PATH_CONTAINS):
        return True

    if comm in NOISY_COMMS:
        return True

    return False


def build_execve_event(data: dict) -> dict:
    pid = data["pid"]
    ppid = get_ppid_from_pid(pid)

    return {
        "event_type": "execve",
        "ts": datetime.utcnow(),
        "pid": pid,
        "ppid": ppid,
        "ppid_status": "resolved" if ppid is not None else "pid_disappeared",
        "uid": data["uid"],
        "comm": data["comm"],
        "filename": data["filename"],
        "cgroup_id": data.get("cgroup_id"),
        "source": "libbpf_perf_buffer",
    }


def build_openat_event(data: dict) -> dict:
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
        "cgroup_id": data.get("cgroup_id"),
        "dfd": data["dfd"],
        "flags": data["flags"],
        "source": "libbpf_perf_buffer",
    }


def build_connect_event(data: dict) -> dict:
    pid = data["pid"]
    ppid = get_ppid_from_pid(pid)

    return {
        "event_type": "connect",
        "ts": datetime.utcnow(),
        "pid": pid,
        "ppid": ppid,
        "ppid_status": "resolved" if ppid is not None else "pid_disappeared",
        "uid": data["uid"],
        "comm": data["comm"],
        "cgroup_id": data.get("cgroup_id"),
        "fd": data.get("fd"),
        "addrlen": data.get("addrlen"),
        "family": data.get("family"),
        "ip": data.get("ip"),
        "port": data.get("port"),
        "ip_version": data.get("ip_version"),
        "ret": data.get("ret"),
        "success": data.get("success"),
        "source": "libbpf_perf_buffer",
    }


class RuntimeRunner:
    def __init__(self):
        self.db_queue = queue.Queue(maxsize=10000)
        self.online_queue = queue.Queue(maxsize=10000)
        self.feature_queue = queue.Queue(maxsize=10000)

        self.lineage_tracker = ProcessLineageTracker(
            process_ttl_sec=900,
            max_nodes=50000,
            max_ancestors=8,
        )

        self.dispatcher = EventDispatcher(
            db_queue=self.db_queue,
            online_queue=self.online_queue,
            feature_queue=self.feature_queue,
        )

        self.storage_worker = StorageWorker(
            db_queue=self.db_queue,
            batch_size=20,
            flush_interval=2.0,
        )

        self.online_worker = OnlineWorker(
            online_queue=self.online_queue,
            window_seconds=30,
            burst_threshold=8,
        )

        self.feature_worker = FeatureWorker(
            feature_queue=self.feature_queue,
            window_seconds=10,
        )

        self.processes = []

    async def start_binary(self, cmd: list[str], name: str):
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        await asyncio.sleep(1)

        if proc.returncode is not None:
            err = await proc.stderr.read()
            print(f"{name} userspace binary failed:")
            print(err.decode(errors="replace"))
            return None

        self.processes.append((name, proc))
        print(f"[runner] started {name}")
        return proc

    async def read_stream(self, name: str, proc, event_builder, skip_fn=None):
        while True:
            line = await proc.stdout.readline()

            if not line:
                if proc.returncode is not None:
                    err = await proc.stderr.read()
                    print(f"{name} userspace binary exited:")
                    print(err.decode(errors="replace"))
                    break

                await asyncio.sleep(0.05)
                continue

            line = line.decode(errors="replace").strip()

            if not line.startswith("{"):
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            if skip_fn and skip_fn(data):
                continue

            try:
                event = event_builder(data)
                event = enrich_common_fields(event, self.lineage_tracker)
                if name == "connect":
                    print(
                        f"[{name}] pid={event.get('pid')} ppid={event.get('ppid')} "
                        f"uid={event.get('uid')} comm={event.get('comm')} "
                        f"cgroup_id={event.get('cgroup_id')} "
                        f"ip={event.get('ip')} port={event.get('port')} "
                        f"family={event.get('family')} ret={event.get('ret')} "
                        f"success={event.get('success')} "
                        f"container={event.get('container_id')} "
                        f"resolver_status={event.get('resolver_status')} "
                        f"lineage={event.get('lineage', {}).get('summary')}"
                    )
                elif name == "openat":
                    print(
                        f"[{name}] pid={event.get('pid')} ppid={event.get('ppid')} "
                        f"uid={event.get('uid')} comm={event.get('comm')} "
                        f"cgroup_id={event.get('cgroup_id')} "
                        f"filename={event.get('filename')} "
                        f"container={event.get('container_id')} "
                        f"resolver_status={event.get('resolver_status')} "
                        f"lineage={event.get('lineage', {}).get('summary')}"
                    )
                elif name == "execve":
                    print(
                        f"[{name}] pid={event.get('pid')} ppid={event.get('ppid')} "
                        f"uid={event.get('uid')} comm={event.get('comm')} "
                        f"cgroup_id={event.get('cgroup_id')} "
                        f"filename={event.get('filename')} "
                        f"container={event.get('container_id')} "
                        f"resolver_status={event.get('resolver_status')} "
                        f"lineage={event.get('lineage', {}).get('summary')}"
                    )
                else:
                    print(
                        f"[{name}] pid={event.get('pid')} ppid={event.get('ppid')} "
                        f"uid={event.get('uid')} comm={event.get('comm')} "
                        f"cgroup_id={event.get('cgroup_id')} "
                        f"container={event.get('container_id')} "
                        f"resolver_status={event.get('resolver_status')} "
                        f"lineage={event.get('lineage', {}).get('summary')}"
                    )

                self.dispatcher.dispatch(event)

            except Exception as exc:
                print(f"[runner] error processing {name} event: {exc}")

    async def run(self):
        self.storage_worker.start()
        self.online_worker.start()
        self.feature_worker.start()
        execve_proc = await self.start_binary(EXECVE_BINARY, "execve")
        openat_proc = await self.start_binary(OPENAT_BINARY, "openat")
        connect_proc = await self.start_binary(CONNECT_BINARY, "connect")

        tasks = []

        if execve_proc:
            tasks.append(
                asyncio.create_task(
                    self.read_stream(
                        "execve",
                        execve_proc,
                        build_execve_event,
                    )
                )
            )

        if openat_proc:
            tasks.append(
                asyncio.create_task(
                    self.read_stream(
                        "openat",
                        openat_proc,
                        build_openat_event,
                        skip_fn=should_skip_openat,
                    )
                )
            )

        if connect_proc:
            tasks.append(
                asyncio.create_task(
                    self.read_stream(
                        "connect",
                        connect_proc,
                        build_connect_event,
                    )
                )
            )

        if not tasks:
            print("[runner] no binaries started")
            return

        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            print("[runner] stopping...")
        finally:
            await self.shutdown()

    async def shutdown(self):
        self.storage_worker.stop()
        self.online_worker.stop()
        self.feature_worker.stop()

        for name, proc in self.processes:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass

        for name, proc in self.processes:
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass

        self.storage_worker.join(timeout=3)
        self.online_worker.join(timeout=3)
        self.feature_worker.join(timeout=3)

async def main():
    runner = RuntimeRunner()
    await runner.run()


if __name__ == "__main__":
    asyncio.run(main())