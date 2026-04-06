import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple, Any
import time


class ProcessIdentityTracker:
    def __init__(self, ttl_seconds: int = 300):
        self.ttl_seconds = ttl_seconds
        self._by_pid = {}

    def _cleanup(self):
        now = time.time()
        stale_pids = [
            pid for pid, data in self._by_pid.items()
            if (now - data.get("last_seen", now)) > self.ttl_seconds
        ]
        for pid in stale_pids:
            del self._by_pid[pid]

    def get(self, pid: int):
        self._cleanup()
        return self._by_pid.get(pid)

    def register_exec(self, pid: int, ppid: int | None, comm: str | None, filename: str | None):
        self._cleanup()

        process_key = f"host:{pid}"
        parent_process_key = f"host:{ppid}" if ppid is not None else None

        self._by_pid[pid] = {
            "process_key": process_key,
            "parent_process_key": parent_process_key,
            "comm": comm,
            "filename": filename,
            "last_seen": time.time(),
        }

        return self._by_pid[pid]

    def touch(self, pid: int):
        entry = self._by_pid.get(pid)
        if entry:
            entry["last_seen"] = time.time()
        return entry

    def resolve_for_event(self, pid: int, ppid: int | None):
        self._cleanup()

        entry = self._by_pid.get(pid)
        if entry:
            entry["last_seen"] = time.time()
            return {
                "process_key": entry["process_key"],
                "parent_process_key": entry.get("parent_process_key"),
            }

        return {
            "process_key": f"host:{pid}",
            "parent_process_key": f"host:{ppid}" if ppid is not None else None,
        }

def _to_ts(value) -> float:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()

    if isinstance(value, (int, float)):
        return float(value)

    return datetime.now(timezone.utc).timestamp()


@dataclass
class ProcessNode:
    process_key: str
    pid: int
    ppid: Optional[int]
    first_seen_ts: float
    last_seen_ts: float

    comm: Optional[str] = None
    filename: Optional[str] = None
    uid: Optional[int] = None

    parent_process_key: Optional[str] = None
    child_process_keys: Set[str] = field(default_factory=set)

    container_id: Optional[str] = None
    pod_uid: Optional[str] = None

    events_count: int = 0
    last_event_type: Optional[str] = None
    last_filename: Optional[str] = None


class ProcessLineageTracker:
    def __init__(
        self,
        process_ttl_sec: int = 900,
        max_nodes: int = 50000,
        max_ancestors: int = 8,
    ):
        self.process_ttl_sec = process_ttl_sec
        self.max_nodes = max_nodes
        self.max_ancestors = max_ancestors

        self._nodes: Dict[str, ProcessNode] = {}
        self._pid_index: Dict[Tuple[Optional[str], int], List[str]] = {}
        self._lock = threading.Lock()

    def enrich_event(self, event: dict) -> dict:
        now_ts = _to_ts(event.get("ts"))

        with self._lock:
            self._cleanup_locked(now_ts)

            if event.get("event_type") == "execve":
                self._handle_execve_locked(event, now_ts)
            else:
                self._handle_non_exec_locked(event, now_ts)

            self._attach_lineage_locked(event)

        return event

    def _handle_execve_locked(self, event: dict, now_ts: float):
        pid = event.get("pid")
        ppid = event.get("ppid")

        if pid is None:
            return

        container_id = event.get("container_id")
        process_key = self._make_process_key(container_id, pid, now_ts)
        parent_process_key = self._find_parent_process_key_locked(ppid, container_id, now_ts)

        node = ProcessNode(
            process_key=process_key,
            pid=pid,
            ppid=ppid,
            first_seen_ts=now_ts,
            last_seen_ts=now_ts,
            comm=event.get("comm"),
            filename=event.get("filename"),
            uid=event.get("uid"),
            parent_process_key=parent_process_key,
            container_id=container_id,
            pod_uid=event.get("pod_uid"),
            events_count=1,
            last_event_type=event.get("event_type"),
            last_filename=event.get("filename"),
        )

        self._nodes[process_key] = node
        self._add_pid_index_locked(container_id, pid, process_key)

        if parent_process_key and parent_process_key in self._nodes:
            self._nodes[parent_process_key].child_process_keys.add(process_key)

        event["process_key"] = process_key
        event["parent_process_key"] = parent_process_key
    def _handle_non_exec_locked(self, event: dict, now_ts: float):
        pid = event.get("pid")
        ppid = event.get("ppid")
        if pid is None:
            return

        container_id = event.get("container_id")
        process_key = self._find_existing_process_key_locked(pid, container_id)

        if process_key is None:
            process_key = self._make_process_key(container_id, pid, now_ts)
            parent_process_key = self._find_parent_process_key_locked(ppid, container_id, now_ts)

            node = ProcessNode(
                process_key=process_key,
                pid=pid,
                ppid=ppid,
                first_seen_ts=now_ts,
                last_seen_ts=now_ts,
                comm=event.get("comm"),
                filename=event.get("filename"),
                uid=event.get("uid"),
                parent_process_key=parent_process_key,
                container_id=container_id,
                pod_uid=event.get("pod_uid"),
                events_count=1,
                last_event_type=event.get("event_type"),
                last_filename=event.get("filename"),
            )

            self._nodes[process_key] = node
            self._add_pid_index_locked(container_id, pid, process_key)

            if parent_process_key and parent_process_key in self._nodes:
                self._nodes[parent_process_key].child_process_keys.add(process_key)

        else:
            node = self._nodes[process_key]
            node.last_seen_ts = now_ts
            node.events_count += 1
            node.last_event_type = event.get("event_type")
            node.last_filename = event.get("filename") or node.last_filename

            event_comm = event.get("comm")
            if event_comm:
                if not node.comm:
                    node.comm = event_comm
                elif node.comm in {"sh", "bash", "dash", "ash"} and event_comm != node.comm:
                    node.comm = event_comm

        event["process_key"] = process_key
        event["parent_process_key"] = self._nodes[process_key].parent_process_key
    def _attach_lineage_locked(self, event: dict):
        process_key = event.get("process_key")
        if not process_key:
            return

        node = self._nodes.get(process_key)
        if not node:
            return

        ancestors = self._build_ancestors_locked(node)
        current_label = node.comm or f"pid={node.pid}"
        ancestor_labels = [a["comm"] or f"pid={a['pid']}" for a in ancestors]
        summary = " -> ".join(ancestor_labels + [current_label]) if ancestor_labels else current_label

        event["lineage"] = {
            "depth": len(ancestors),
            "summary": summary,
            "ancestors": ancestors,
        }

    def _build_ancestors_locked(self, node: ProcessNode) -> List[dict]:
        result = []
        visited = set()

        current_key = node.parent_process_key
        steps = 0

        while current_key and steps < self.max_ancestors:
            if current_key in visited:
                break

            visited.add(current_key)
            parent = self._nodes.get(current_key)
            if not parent:
                break

            result.append({
                "process_key": parent.process_key,
                "pid": parent.pid,
                "comm": parent.comm,
                "filename": parent.filename,
            })

            current_key = parent.parent_process_key
            steps += 1

        result.reverse()
        return result

    def _find_parent_process_key_locked(
        self,
        ppid: Optional[int],
        container_id: Optional[str],
        now_ts: float,
    ) -> Optional[str]:
        if ppid is None:
            return None

        candidates = self._get_pid_candidates_locked(container_id, ppid)
        best_key = None
        best_age = None

        for key in candidates:
            node = self._nodes.get(key)
            if not node:
                continue

            age = now_ts - node.last_seen_ts
            if age > self.process_ttl_sec:
                continue

            if best_age is None or age < best_age:
                best_age = age
                best_key = key

        return best_key

    def _find_existing_process_key_locked(self, pid: int, container_id: Optional[str]) -> Optional[str]:
        candidates = self._get_pid_candidates_locked(container_id, pid)

        best_key = None
        best_seen = None

        for key in candidates:
            node = self._nodes.get(key)
            if not node:
                continue

            if best_seen is None or node.last_seen_ts > best_seen:
                best_seen = node.last_seen_ts
                best_key = key

        return best_key

    def _get_pid_candidates_locked(self, container_id: Optional[str], pid: int) -> List[str]:
        exact = self._pid_index.get((container_id, pid), [])
        if exact:
            return exact

        return self._pid_index.get((None, pid), [])

    def _add_pid_index_locked(self, container_id: Optional[str], pid: int, process_key: str):
        key = (container_id, pid)
        self._pid_index.setdefault(key, []).append(process_key)

    def _cleanup_locked(self, now_ts: float):
        threshold = now_ts - self.process_ttl_sec

        stale_keys = [
            process_key
            for process_key, node in self._nodes.items()
            if node.last_seen_ts < threshold
        ]

        if not stale_keys and len(self._nodes) <= self.max_nodes:
            return

        if len(self._nodes) > self.max_nodes:
            stale_keys.extend(
                sorted(
                    self._nodes.keys(),
                    key=lambda k: self._nodes[k].last_seen_ts
                )[: len(self._nodes) - self.max_nodes]
            )

        stale_set = set(stale_keys)

        for key in stale_set:
            self._nodes.pop(key, None)

        new_pid_index: Dict[Tuple[Optional[str], int], List[str]] = {}
        for key, node in self._nodes.items():
            idx = (node.container_id, node.pid)
            new_pid_index.setdefault(idx, []).append(key)
        self._pid_index = new_pid_index

        for node in self._nodes.values():
            node.child_process_keys = {k for k in node.child_process_keys if k not in stale_set}
            if node.parent_process_key in stale_set:
                node.parent_process_key = None

    @staticmethod
    def _make_process_key(container_id: Optional[str], pid: int, now_ts: float) -> str:
        container_hint = container_id[:12] if container_id else "host"
        ts_ms = int(now_ts * 1000)
        return f"{container_hint}:{pid}:{ts_ms}"