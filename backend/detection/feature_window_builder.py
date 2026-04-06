from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


def _parse_ts(value: Any) -> datetime:
    """
    Convert supported timestamp formats into timezone-aware UTC datetime.

    Supported:
    - datetime
    - unix timestamp (int/float)
    - ISO string, with or without trailing Z
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)

    if isinstance(value, str):
        normalized = value.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    raise ValueError(f"Unsupported timestamp format: {type(value)!r}")


def _safe_str(value: Any, default: str = "unknown") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


@dataclass
class WindowState:
    """
    Aggregated counters for a single (namespace, pod_name) time window.
    """
    namespace: str
    pod_name: str
    window_start: datetime
    window_end: datetime

    total_event_count: int = 0
    exec_count_window: int = 0
    sensitive_open_count_window: int = 0
    connect_count_window: int = 0
    failed_connect_count_window: int = 0
    root_event_count_window: int = 0
    unique_destination_count_window: int = 0

    unique_destinations: Set[str] = field(default_factory=set)
    unique_processes: Set[str] = field(default_factory=set)
    unique_commands: Set[str] = field(default_factory=set)

    # Optional extra counters that may be useful later for LOF/statistics
    file_open_count_window: int = 0
    non_sensitive_open_count_window: int = 0

    # Placeholders for future real resource integration
    cpu_usage_sum: float = 0.0
    cpu_usage_samples: int = 0
    memory_usage_sum: float = 0.0
    memory_usage_samples: int = 0

    first_event_ts: Optional[datetime] = None
    last_event_ts: Optional[datetime] = None

    def add_event(self, event: Dict[str, Any], sensitive_paths: Set[str]) -> None:
        self.total_event_count += 1

        event_ts = _parse_ts(event["ts"])
        if self.first_event_ts is None or event_ts < self.first_event_ts:
            self.first_event_ts = event_ts
        if self.last_event_ts is None or event_ts > self.last_event_ts:
            self.last_event_ts = event_ts

        uid = event.get("uid")
        if uid == 0:
            self.root_event_count_window += 1

        process_key = event.get("process_key") or event.get("comm")
        if process_key:
            self.unique_processes.add(str(process_key))

        comm = event.get("comm")
        if comm:
            self.unique_commands.add(str(comm))

        event_type = _safe_str(event.get("event_type"), default="unknown").lower()

        if event_type == "execve":
            self.exec_count_window += 1

        elif event_type == "openat":
            self.file_open_count_window += 1
            filename = _safe_str(event.get("filename"), default="")
            if self._is_sensitive_path(filename, sensitive_paths):
                self.sensitive_open_count_window += 1
            else:
                self.non_sensitive_open_count_window += 1

        elif event_type == "connect":
            self.connect_count_window += 1

            if self._is_failed_connect(event):
                self.failed_connect_count_window += 1

            destination = self._extract_destination_key(event)
            if destination:
                self.unique_destinations.add(destination)
                self.unique_destination_count_window = len(self.unique_destinations)

        cpu_usage_pct = event.get("cpu_usage_pct")
        if isinstance(cpu_usage_pct, (int, float)):
            self.cpu_usage_sum += float(cpu_usage_pct)
            self.cpu_usage_samples += 1

        memory_usage_mb = event.get("memory_usage_mb")
        if isinstance(memory_usage_mb, (int, float)):
            self.memory_usage_sum += float(memory_usage_mb)
            self.memory_usage_samples += 1

    @staticmethod
    def _is_sensitive_path(filename: str, sensitive_paths: Set[str]) -> bool:
        if not filename:
            return False

        for sensitive_prefix in sensitive_paths:
            if filename == sensitive_prefix or filename.startswith(sensitive_prefix):
                return True
        return False

    @staticmethod
    def _is_failed_connect(event: Dict[str, Any]) -> bool:
        """
        Flexible detection because schemas vary across collectors.
        """
        if event.get("connect_success") is False:
            return True

        if event.get("status") in {"failed", "error"}:
            return True

        errno = event.get("errno")
        if isinstance(errno, int) and errno != 0:
            return True

        result = event.get("result")
        if isinstance(result, int) and result < 0:
            return True

        return False

    @staticmethod
    def _extract_destination_key(event: Dict[str, Any]) -> Optional[str]:
        ip = (
            event.get("destination_ip")
            or event.get("ip")
            or event.get("remote_ip")
        )
        port = event.get("destination_port") or event.get("port") or event.get("remote_port")

        if ip and port is not None:
            return f"{ip}:{port}"
        if ip:
            return str(ip)
        return None

    def to_feature_vector(self) -> Dict[str, Any]:
        duration_seconds = max(
            0.0,
            (self.window_end - self.window_start).total_seconds()
        )

        cpu_usage_pct = (
            self.cpu_usage_sum / self.cpu_usage_samples
            if self.cpu_usage_samples > 0 else 0.0
        )
        memory_usage_mb = (
            self.memory_usage_sum / self.memory_usage_samples
            if self.memory_usage_samples > 0 else 0.0
        )

        return {
            "namespace": self.namespace,
            "pod_name": self.pod_name,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "window_seconds": duration_seconds,

            # Core requested features
            "exec_count_window": self.exec_count_window,
            "sensitive_open_count_window": self.sensitive_open_count_window,
            "connect_count_window": self.connect_count_window,
            "failed_connect_count_window": self.failed_connect_count_window,
            "root_event_count_window": self.root_event_count_window,
            "unique_destination_count_window": self.unique_destination_count_window,
            "cpu_usage_pct": round(cpu_usage_pct, 4),
            "memory_usage_mb": round(memory_usage_mb, 4),

            # Useful extra features
            "total_event_count_window": self.total_event_count,
            "file_open_count_window": self.file_open_count_window,
            "non_sensitive_open_count_window": self.non_sensitive_open_count_window,
            "unique_process_count_window": len(self.unique_processes),
            "unique_command_count_window": len(self.unique_commands),

            # Optional context
            "first_event_ts": self.first_event_ts,
            "last_event_ts": self.last_event_ts,
            "ts": self.window_end
        }


class FeatureWindowBuilder:
    """
    Build window-based feature vectors from a live stream of events.

    Grouping key:
        (namespace, pod_name)

    Windowing model:
        Fixed windows of `window_seconds`, aligned per first event seen for that pod.

    Behavior:
        - process_event(event) returns 0..N completed feature vectors
        - flush_expired(now) closes windows older than `now`
        - flush_all() closes everything
    """

    DEFAULT_SENSITIVE_PATHS = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh",
        "/root/.ssh",
        "/home",
        "/var/run/secrets",
        "/run/secrets",
        "/etc/kubernetes",
        "/etc/ssl/private",
        "/root/.kube",
    }

    def __init__(
        self,
        window_seconds: int = 10,
        sensitive_paths: Optional[Set[str]] = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")

        self.window_seconds = window_seconds
        self.sensitive_paths = sensitive_paths or set(self.DEFAULT_SENSITIVE_PATHS)
        self._windows: Dict[Tuple[str, str], WindowState] = {}

    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process one event and return completed feature vectors, if any.

        Required event fields:
            - ts
        Recommended:
            - namespace
            - pod_name
            - event_type
            - uid
            - filename (for openat)
            - destination_ip / destination_port (for connect)
        """
        if "ts" not in event:
            raise ValueError("event must include 'ts'")

        event_ts = _parse_ts(event["ts"])
        namespace = _safe_str(event.get("namespace"))
        pod_name = _safe_str(event.get("pod_name"))

        key = (namespace, pod_name)
        completed_vectors: List[Dict[str, Any]] = []

        current_window = self._windows.get(key)

        if current_window is None:
            current_window = self._create_new_window(namespace, pod_name, event_ts)
            self._windows[key] = current_window

        while event_ts >= current_window.window_end:
            completed_vectors.append(current_window.to_feature_vector())
            current_window = self._roll_window_forward(current_window)
            self._windows[key] = current_window

        current_window.add_event(event, self.sensitive_paths)
        return completed_vectors

    def flush_expired(self, now: Optional[Any] = None) -> List[Dict[str, Any]]:
        """
        Flush windows whose end time is <= now.
        Useful if traffic stops and you still want vectors emitted.
        """
        now_dt = _parse_ts(now) if now is not None else datetime.now(timezone.utc)
        completed: List[Dict[str, Any]] = []
        keys_to_delete: List[Tuple[str, str]] = []

        for key, window in list(self._windows.items()):
            current = window

            while now_dt >= current.window_end:
                completed.append(current.to_feature_vector())
                current = self._roll_window_forward(current)

                # If the rolled window is already empty and in the future, keep it.
                if now_dt < current.window_end:
                    self._windows[key] = current
                    break
            else:
                self._windows[key] = current

            # Optional cleanup: remove totally inactive empty windows
            if (
                self._windows[key].total_event_count == 0
                and self._windows[key].first_event_ts is None
                and now_dt < self._windows[key].window_end
            ):
                # Keep it by default for continuity; comment out if you prefer deletion
                pass

        return completed

    def flush_all(self) -> List[Dict[str, Any]]:
        """
        Flush all currently open windows immediately, even if not expired yet.
        Useful on shutdown.
        """
        completed = [window.to_feature_vector() for window in self._windows.values()]
        self._windows.clear()
        return completed

    def get_open_windows_count(self) -> int:
        return len(self._windows)

    def _create_new_window(
        self,
        namespace: str,
        pod_name: str,
        event_ts: datetime,
    ) -> WindowState:
        window_start = event_ts
        window_end = window_start.timestamp() + self.window_seconds
        window_end_dt = datetime.fromtimestamp(window_end, tz=timezone.utc)

        return WindowState(
            namespace=namespace,
            pod_name=pod_name,
            window_start=window_start,
            window_end=window_end_dt,
        )

    def _roll_window_forward(self, window: WindowState) -> WindowState:
        new_start = window.window_end
        new_end = datetime.fromtimestamp(
            new_start.timestamp() + self.window_seconds,
            tz=timezone.utc,
        )

        return WindowState(
            namespace=window.namespace,
            pod_name=window.pod_name,
            window_start=new_start,
            window_end=new_end,
        )