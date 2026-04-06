import json
import os
import re
import time
import threading
import subprocess
from typing import Any, Dict, Optional


HEX64_RE = re.compile(r"\b([a-f0-9]{64})\b", re.IGNORECASE)
HEX32_RE = re.compile(r"\b([a-f0-9]{32})\b", re.IGNORECASE)

POD_UID_RE = re.compile(
    r"pod([a-f0-9]{8}[-_][a-f0-9]{4}[-_][a-f0-9]{4}[-_][a-f0-9]{4}[-_][a-f0-9]{12})",
    re.IGNORECASE,
)


def _utc_ts() -> float:
    return time.time()


class TTLCache:
    def __init__(self, ttl_seconds: float = 30, max_size: int = 10000):
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self._data: Dict[Any, Any] = {}
        self._lock = threading.Lock()

    def get(self, key: Any):
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None

            value, expires_at = item
            if expires_at < _utc_ts():
                self._data.pop(key, None)
                return None

            return value

    def set(self, key: Any, value: Any):
        with self._lock:
            if len(self._data) >= self.max_size:
                self._evict_some()
            self._data[key] = (value, _utc_ts() + self.ttl_seconds)

    def clear(self):
        with self._lock:
            self._data.clear()

    def _evict_some(self):
        now = _utc_ts()

        expired = [k for k, (_, exp) in self._data.items() if exp < now]
        for k in expired:
            self._data.pop(k, None)

        if len(self._data) < self.max_size:
            return

        for k in list(self._data.keys())[: max(1, self.max_size // 10)]:
            self._data.pop(k, None)


class ContainerResolver:
    def __init__(
        self,
        node_container_name: Optional[str] = None,
        success_ttl_sec: float = 120.0,
        failure_ttl_sec: float = 2.0,
        pod_map_ttl_sec: float = 30.0,
        cgroup_snapshot_ttl_sec: float = 5.0,
        max_size: int = 30000,
        retries: int = 2,
        retry_sleep_sec: float = 0.01,
        docker_timeout_sec: float = 3.0,
        debug: bool = False,
    ):
        self.node_container_name = (
            node_container_name
            or os.environ.get("KIND_NODE_CONTAINER")
            or "secubernetes-control-plane"
        )

        self.node_name = os.environ.get("NODE_NAME")

        self._success_cache = TTLCache(ttl_seconds=success_ttl_sec, max_size=max_size)
        self._failure_cache = TTLCache(ttl_seconds=failure_ttl_sec, max_size=max_size)

        self._cg_success_cache = TTLCache(ttl_seconds=success_ttl_sec, max_size=max_size)
        self._cg_failure_cache = TTLCache(ttl_seconds=failure_ttl_sec, max_size=max_size)

        self._pod_map_cache = TTLCache(ttl_seconds=pod_map_ttl_sec, max_size=max_size)

        self._snapshot_lock = threading.Lock()
        self._cgroup_snapshot: Dict[int, dict] = {}
        self._cgroup_snapshot_expires_at = 0.0
        self.cgroup_snapshot_ttl_sec = cgroup_snapshot_ttl_sec

        self.retries = retries
        self.retry_sleep_sec = retry_sleep_sec
        self.docker_timeout_sec = docker_timeout_sec
        self.debug = debug

    def _log(self, msg: str):
        if self.debug:
            print(f"[RESOLVER] {msg}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve_from_cgroup_id(self, cgroup_id: Optional[int]) -> dict:
        if cgroup_id is None:
            return self._empty_result("cgroup_id_missing")

        cached_success = self._cg_success_cache.get(cgroup_id)
        if cached_success is not None:
            return cached_success

        cached_failure = self._cg_failure_cache.get(cgroup_id)
        if cached_failure is not None:
            return cached_failure

        last_result = None

        for attempt in range(self.retries + 1):
            last_result = self._resolve_from_cgroup_snapshot(cgroup_id)

            status = last_result.get("resolver_status")
            if status in {
                "resolved",
                "resolved_without_pod_mapping",
                "cgroup_id_found_but_no_container_match",
                "cgroup_id_not_found_in_snapshot",
                "docker_exec_permission_denied",
                "docker_not_found",
                "node_container_not_found",
                "snapshot_build_failed",
            }:
                break

            if attempt < self.retries:
                time.sleep(self.retry_sleep_sec)

        result = last_result or self._empty_result("unknown_failure")

        if result.get("container_id"):
            self._cg_success_cache.set(cgroup_id, result)
        else:
            self._cg_failure_cache.set(cgroup_id, result)

        return result

    def resolve_from_pid(
        self,
        pid: Optional[int],
        ppid: Optional[int] = None,
        allow_parent_fallback: bool = True,
    ) -> dict:
        if pid is None:
            return self._empty_result("pid_missing")

        cached_success = self._success_cache.get(pid)
        if cached_success is not None:
            return cached_success

        cached_failure = self._failure_cache.get(pid)
        if cached_failure is not None:
            if allow_parent_fallback and ppid:
                parent_cached = self._success_cache.get(ppid)
                if parent_cached and parent_cached.get("container_id"):
                    inherited = self._clone_with_status(
                        parent_cached, "inherited_from_parent_cache"
                    )
                    return inherited
            return cached_failure

        result = self._resolve_with_retries_by_pid(pid)

        if result.get("container_id"):
            self._success_cache.set(pid, result)
            return result

        if allow_parent_fallback and ppid:
            parent_result = self._resolve_parent(ppid)
            if parent_result.get("container_id"):
                inherited = self._clone_with_status(
                    parent_result, "inherited_from_parent"
                )
                self._success_cache.set(pid, inherited)
                return inherited

        self._failure_cache.set(pid, result)
        return result

    # ------------------------------------------------------------------
    # New resolver path: cgroup_id -> snapshot -> metadata
    # ------------------------------------------------------------------

    def _resolve_from_cgroup_snapshot(self, cgroup_id: int) -> dict:
        snapshot = self._get_or_refresh_cgroup_snapshot()

        if "__snapshot_error__" in snapshot:
            status = snapshot["__snapshot_error__"]
            return self._empty_result(status)

        entry = snapshot.get(int(cgroup_id))
        if not entry:
            out = self._empty_result("cgroup_id_not_found_in_snapshot")
            out["resolved_at"] = _utc_ts()
            out["node_name"] = self.node_name
            return out

        parsed = dict(entry)
        parsed["resolved_at"] = _utc_ts()
        parsed["node_name"] = self.node_name
        parsed["cgroup_id"] = int(cgroup_id)

        if not parsed.get("container_id"):
            parsed["resolver_status"] = "cgroup_id_found_but_no_container_match"
            return parsed

        pod_meta = self._lookup_pod_metadata(parsed["container_id"])
        if pod_meta:
            parsed["pod_name"] = pod_meta.get("pod_name")
            parsed["container_name"] = pod_meta.get("container_name")
            parsed["namespace"] = pod_meta.get("namespace")
            parsed["pod_id"] = pod_meta.get("pod_id")
            parsed["resolver_status"] = "resolved"
        else:
            parsed["resolver_status"] = "resolved_without_pod_mapping"

        return parsed

    def _get_or_refresh_cgroup_snapshot(self) -> Dict[int, dict]:
        now = _utc_ts()

        with self._snapshot_lock:
            if self._cgroup_snapshot and self._cgroup_snapshot_expires_at > now:
                return self._cgroup_snapshot

            snapshot = self._build_cgroup_snapshot()
            self._cgroup_snapshot = snapshot
            self._cgroup_snapshot_expires_at = now + self.cgroup_snapshot_ttl_sec
            return snapshot

    def _build_cgroup_snapshot(self) -> Dict[int, dict]:
        """
        Builds a snapshot from inside the kind node:
        inode(cgroup dir) -> parsed metadata

        We assume inode(/sys/fs/cgroup/<path>) corresponds to bpf_get_current_cgroup_id().
        """
        script = r'''
set -eu

for f in /proc/[0-9]*/cgroup; do
    pid="${f#/proc/}"
    pid="${pid%/cgroup}"

    path="$(awk -F: '$1=="0" {print $3; exit}' "$f" 2>/dev/null || true)"
    if [ -z "$path" ]; then
        path="$(awk -F: 'NR==1 {print $3; exit}' "$f" 2>/dev/null || true)"
    fi

    [ -z "$path" ] && continue

    full="/sys/fs/cgroup${path}"
    [ ! -e "$full" ] && continue

    inode="$(stat -Lc %i "$full" 2>/dev/null || true)"
    [ -z "$inode" ] && continue

    printf '%s\t%s\t%s\n' "$inode" "$pid" "$path"
done | awk '!seen[$1]++'
'''.strip()

        cmd = [
            "docker",
            "exec",
            self.node_container_name,
            "sh",
            "-lc",
            script,
        ]

        result = self._run_subprocess(cmd)
        if result["status"] != "ok":
            self._log(f"snapshot build failed: {result}")
            return {"__snapshot_error__": self._map_snapshot_status(result["status"])}

        snapshot: Dict[int, dict] = {}

        for line in result["stdout"].splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split("\t", 2)
            if len(parts) != 3:
                continue

            inode_str, pid_str, cgroup_path = parts

            try:
                inode = int(inode_str)
            except ValueError:
                continue

            try:
                sample_pid = int(pid_str)
            except ValueError:
                sample_pid = None

            parsed = self._parse_single_cgroup_path(cgroup_path)
            parsed["sample_pid"] = sample_pid
            parsed["cgroup_path"] = cgroup_path
            parsed["cgroup_id"] = inode
            snapshot[inode] = parsed

        return snapshot

    def _map_snapshot_status(self, status: str) -> str:
        mapping = {
            "timeout": "docker_exec_timeout",
            "docker_exec_permission_denied": "docker_exec_permission_denied",
            "docker_not_found": "docker_not_found",
            "node_container_not_found": "node_container_not_found",
        }
        return mapping.get(status, "snapshot_build_failed")

    # ------------------------------------------------------------------
    # Old resolver path: pid -> /proc/<pid>/cgroup
    # ------------------------------------------------------------------

    def _resolve_parent(self, ppid: int) -> dict:
        cached = self._success_cache.get(ppid)
        if cached is not None:
            return cached

        result = self._resolve_with_retries_by_pid(ppid)
        if result.get("container_id"):
            self._success_cache.set(ppid, result)
        else:
            self._failure_cache.set(ppid, result)
        return result

    def _resolve_with_retries_by_pid(self, pid: int) -> dict:
        last_result = None

        for attempt in range(self.retries + 1):
            last_result = self._resolve_from_pid_in_node(pid)

            status = last_result.get("resolver_status")
            if status in {
                "resolved",
                "resolved_without_pod_mapping",
                "cgroup_found_but_no_container_match",
                "docker_exec_permission_denied",
                "docker_not_found",
                "node_container_not_found",
                "proc_or_cgroup_missing",
            }:
                return last_result

            if attempt < self.retries:
                time.sleep(self.retry_sleep_sec)

        return last_result or self._empty_result("unknown_failure")

    def _resolve_from_pid_in_node(self, pid: int) -> dict:
        cgroup_result = self._read_file_from_node(f"/proc/{pid}/cgroup")

        if cgroup_result["status"] != "ok":
            return self._map_read_status_to_empty(cgroup_result["status"])

        cgroup_text = cgroup_result["stdout"]
        lines = [line.strip() for line in cgroup_text.splitlines() if line.strip()]
        if not lines:
            parsed = self._empty_result("cgroup_empty")
            parsed["cgroup_text"] = cgroup_text
            parsed["node_name"] = self.node_name
            parsed["resolved_at"] = _utc_ts()
            return parsed

        parsed = self._parse_cgroup_lines(lines)
        parsed["cgroup_text"] = cgroup_text
        parsed["node_name"] = self.node_name
        parsed["resolved_at"] = _utc_ts()

        if not parsed["container_id"]:
            parsed["resolver_status"] = "cgroup_found_but_no_container_match"
            return parsed

        pod_meta = self._lookup_pod_metadata(parsed["container_id"])
        if pod_meta:
            parsed["pod_name"] = pod_meta.get("pod_name")
            parsed["container_name"] = pod_meta.get("container_name")
            parsed["namespace"] = pod_meta.get("namespace")
            parsed["pod_id"] = pod_meta.get("pod_id")
            parsed["resolver_status"] = "resolved"
        else:
            parsed["resolver_status"] = "resolved_without_pod_mapping"

        return parsed

    # ------------------------------------------------------------------
    # Pod metadata enrichment
    # ------------------------------------------------------------------
    def _lookup_pod_metadata(self, container_id: str) -> Optional[dict]:
        short_id = container_id[:12]

        cached = self._pod_map_cache.get(short_id)
        if cached is not None:
            return cached

        cmd = [
            "docker",
            "exec",
            self.node_container_name,
            "crictl",
            "ps",
            "-o",
            "json",
        ]

        result = self._run_subprocess(cmd)
        if result["status"] != "ok":
            self._log(f"crictl ps -o json failed: {result}")
            return None

        try:
            payload = json.loads(result["stdout"])
        except Exception:
            return None

        containers = payload.get("containers", [])
        for item in containers:
            listed_container_id = item.get("id", "") or ""
            if not listed_container_id.startswith(short_id):
                continue

            labels = item.get("labels", {}) or {}
            metadata = item.get("metadata", {}) or {}
            pod_sandbox_id = item.get("podSandboxId")

            container_name = (
                metadata.get("name")
                or labels.get("io.kubernetes.container.name")
            )

            pod_name = (
                labels.get("io.kubernetes.pod.name")
                or labels.get("kubernetes.io/pod.name")
            )

            namespace = (
                labels.get("io.kubernetes.pod.namespace")
                or labels.get("kubernetes.io/pod.namespace")
            )

            if not namespace and pod_sandbox_id:
                namespace = self._lookup_namespace_for_pod_id(pod_sandbox_id)

            meta = {
                "pod_name": pod_name,
                "container_name": container_name,
                "namespace": namespace,
                "pod_id": pod_sandbox_id,
            }
            self._pod_map_cache.set(short_id, meta)
            return meta

        return None
    def _lookup_namespace_for_pod_id(self, pod_id: str) -> Optional[str]:
        cmd = [
            "docker",
            "exec",
            self.node_container_name,
            "crictl",
            "inspectp",
            pod_id,
        ]

        result = self._run_subprocess(cmd)
        if result["status"] != "ok":
            return None

        try:
            payload = json.loads(result["stdout"])
        except Exception:
            return None

        status = payload.get("status", {}) or {}
        info = payload.get("info", {}) or {}
        config = payload.get("config", {}) or {}
        metadata = config.get("metadata", {}) or {}
        labels = config.get("labels", {}) or {}

        namespace = (
            status.get("namespace")
            or info.get("sandboxNamespace")
            or labels.get("io.kubernetes.pod.namespace")
            or labels.get("kubernetes.io/metadata.name")
        )

        if namespace:
            return namespace

        return None

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_cgroup_lines(self, lines: list[str]) -> dict:
        container_id = None
        pod_uid = None
        runtime = None
        raw_paths = []

        for line in lines:
            parts = line.split(":", 2)
            if len(parts) != 3:
                continue

            _, _, path = parts
            raw_paths.append(path)

            single = self._parse_single_cgroup_path(path)

            if container_id is None and single.get("container_id"):
                container_id = single["container_id"]

            if pod_uid is None and single.get("pod_uid"):
                pod_uid = single["pod_uid"]

            if runtime is None and single.get("runtime"):
                runtime = single["runtime"]

        return {
            "container_id": container_id,
            "pod_uid": pod_uid,
            "pod_name": None,
            "namespace": None,
            "container_name": None,
            "runtime": runtime,
            "raw_cgroup_paths": raw_paths,
            "cgroup_path": raw_paths[0] if raw_paths else None,
            "cgroup_id": None,
            "sample_pid": None,
            "pod_id": None,
        }

    def _parse_single_cgroup_path(self, path: str) -> dict:
        container_id = None
        pod_uid = None
        runtime = None

        lowered = path.lower()

        pod_match = POD_UID_RE.search(path)
        if pod_match:
            pod_uid = pod_match.group(1).replace("_", "-")

        if "cri-containerd" in lowered or "containerd" in lowered:
            runtime = "containerd"
        elif "docker" in lowered:
            runtime = "docker"
        elif "crio" in lowered or "cri-o" in lowered:
            runtime = "cri-o"

        m64 = HEX64_RE.search(path)
        if m64:
            container_id = m64.group(1)
        else:
            m32 = HEX32_RE.search(path)
            if m32:
                container_id = m32.group(1)

        return {
            "container_id": container_id,
            "pod_uid": pod_uid,
            "pod_name": None,
            "namespace": None,
            "container_name": None,
            "runtime": runtime,
            "raw_cgroup_paths": [path],
            "cgroup_path": path,
            "cgroup_id": None,
            "sample_pid": None,
            "pod_id": None,
        }

    # ------------------------------------------------------------------
    # Node file access
    # ------------------------------------------------------------------

    def _read_file_from_node(self, path: str) -> dict:
        cmd = [
            "docker",
            "exec",
            self.node_container_name,
            "cat",
            path,
        ]
        return self._run_subprocess(cmd)

    def _run_subprocess(self, cmd: list[str]) -> dict:
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.docker_timeout_sec,
            )
        except FileNotFoundError:
            return {"status": "docker_not_found", "stdout": "", "stderr": ""}
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "stdout": "", "stderr": ""}
        except Exception as exc:
            return {
                "status": f"subprocess_error:{type(exc).__name__}",
                "stdout": "",
                "stderr": str(exc),
            }

        stdout = completed.stdout or ""
        stderr = completed.stderr or ""

        if completed.returncode == 0:
            return {"status": "ok", "stdout": stdout, "stderr": stderr}

        stderr_lower = stderr.lower()

        if "no such container" in stderr_lower:
            return {"status": "node_container_not_found", "stdout": stdout, "stderr": stderr}

        if "permission denied" in stderr_lower:
            return {"status": "docker_exec_permission_denied", "stdout": stdout, "stderr": stderr}

        if "no such file or directory" in stderr_lower:
            return {"status": "proc_or_cgroup_missing", "stdout": stdout, "stderr": stderr}

        return {"status": "nonzero_exit", "stdout": stdout, "stderr": stderr}

    def _map_read_status_to_empty(self, status: str) -> dict:
        mapping = {
            "proc_or_cgroup_missing": "proc_or_cgroup_missing",
            "timeout": "docker_exec_timeout",
            "docker_exec_permission_denied": "docker_exec_permission_denied",
            "docker_not_found": "docker_not_found",
            "node_container_not_found": "node_container_not_found",
        }
        return self._empty_result(mapping.get(status, status))

    @staticmethod
    def _clone_with_status(data: dict, status: str) -> dict:
        out = dict(data)
        out["resolver_status"] = status
        out["resolved_at"] = _utc_ts()
        return out

    @staticmethod
    def _empty_result(reason: str) -> dict:
        return {
            "container_id": None,
            "pod_uid": None,
            "pod_name": None,
            "namespace": None,
            "container_name": None,
            "runtime": None,
            "raw_cgroup_paths": [],
            "cgroup_text": None,
            "node_name": None,
            "resolved_at": _utc_ts(),
            "resolver_status": reason,
            "cgroup_path": None,
            "cgroup_id": None,
            "sample_pid": None,
            "pod_id": None,
        }


_resolver = ContainerResolver(
    node_container_name=os.environ.get("KIND_NODE_CONTAINER", "secubernetes-control-plane"),
    success_ttl_sec=120.0,
    failure_ttl_sec=2.0,
    pod_map_ttl_sec=30.0,
    cgroup_snapshot_ttl_sec=5.0,
    max_size=30000,
    retries=2,
    retry_sleep_sec=0.01,
    docker_timeout_sec=3.0,
    debug=False,
)


def resolve_container_info_from_pid(
    pid: Optional[int],
    ppid: Optional[int] = None,
    allow_parent_fallback: bool = True,
) -> dict:
    return _resolver.resolve_from_pid(
        pid=pid,
        ppid=ppid,
        allow_parent_fallback=allow_parent_fallback,
    )


def resolve_container_info_from_cgroup_id(
    cgroup_id: Optional[int],
) -> dict:
    return _resolver.resolve_from_cgroup_id(cgroup_id)