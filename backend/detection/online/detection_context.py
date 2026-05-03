import time
from collections import Counter, deque

from backend.detection.online.sensitive_targets import match_sensitive_openat_target


class DetectionContext:
    """
    Holds short-lived online detection state.

    This object replaces the state that previously lived directly inside OnlineWorker:
    - exec burst window
    - command frequency window
    - recent execve events
    - recent sensitive openat events

    Rules can use this context to correlate:
    execve -> openat -> connect
    """

    def __init__(
        self,
        window_seconds: int = 30,
        correlation_window_seconds: int = 10,
    ):
        self.window_seconds = window_seconds
        self.correlation_window_seconds = correlation_window_seconds

        self.events_window = deque()
        self.command_counter = Counter()

        self.recent_execs = deque()
        self.recent_sensitive_opens = deque()

    def ingest_event(self, event: dict) -> dict:
        """
        Prepares event for detection and updates correlation state when needed.

        The returned metadata is also attached to event["_online"] so rules can reuse it.
        """
        now_ts = time.time()
        event["arrival_ts"] = now_ts

        self.cleanup(now_ts)

        event_type = event.get("event_type")
        metadata: dict = {
            "arrival_ts": now_ts,
        }

        if event_type == "execve":
            metadata.update(self._remember_exec_event(event, now_ts))

        elif event_type == "openat":
            filename = event.get("filename") or ""
            is_sensitive, matched_rule = match_sensitive_openat_target(filename)

            metadata["is_sensitive_openat"] = is_sensitive
            metadata["matched_sensitive_rule"] = matched_rule

            if is_sensitive:
                self._remember_sensitive_open_event(
                    event=event,
                    matched_rule=matched_rule,
                    now_ts=now_ts,
                )

        event["_online"] = metadata
        return metadata

    def cleanup(self, now_ts: float | None = None) -> None:
        now_ts = now_ts or time.time()

        self._cleanup_old_events(now_ts)
        self._cleanup_old_execs(now_ts)
        self._cleanup_old_sensitive_opens(now_ts)

    def _cleanup_old_events(self, now_ts: float) -> None:
        while self.events_window and (now_ts - self.events_window[0]["arrival_ts"]) > self.window_seconds:
            old_event = self.events_window.popleft()
            key = old_event.get("filename") or old_event.get("comm") or "unknown"

            self.command_counter[key] -= 1
            if self.command_counter[key] <= 0:
                del self.command_counter[key]

    def _cleanup_old_execs(self, now_ts: float) -> None:
        while self.recent_execs and (now_ts - self.recent_execs[0]["arrival_ts"]) > self.correlation_window_seconds:
            self.recent_execs.popleft()

    def _cleanup_old_sensitive_opens(self, now_ts: float) -> None:
        while (
            self.recent_sensitive_opens
            and (now_ts - self.recent_sensitive_opens[0]["arrival_ts"]) > self.correlation_window_seconds
        ):
            self.recent_sensitive_opens.popleft()

    def _remember_exec_event(self, event: dict, now_ts: float) -> dict:
        self.events_window.append(event)

        key = event.get("filename") or event.get("comm") or "unknown"
        self.command_counter[key] += 1

        self.recent_execs.append({
            "pid": event.get("pid"),
            "process_key": event.get("process_key"),
            "parent_process_key": event.get("parent_process_key"),
            "comm": event.get("comm"),
            "filename": event.get("filename"),
            "uid": event.get("uid"),
            "container_id": event.get("container_id"),
            "arrival_ts": now_ts,
        })

        return {
            "exec_window_count": len(self.events_window),
            "command_key": key,
            "command_count_in_window": self.command_counter[key],
        }

    def _remember_sensitive_open_event(
        self,
        event: dict,
        matched_rule: str | None,
        now_ts: float,
    ) -> None:
        self.recent_sensitive_opens.append({
            "pid": event.get("pid"),
            "process_key": event.get("process_key"),
            "parent_process_key": event.get("parent_process_key"),
            "comm": event.get("comm"),
            "filename": event.get("filename"),
            "uid": event.get("uid"),
            "container_id": event.get("container_id"),
            "arrival_ts": now_ts,
            "matched_rule": matched_rule,
        })

    def same_execution_context(self, older_event: dict, event: dict) -> bool:
        older_process_key = older_event.get("process_key")
        current_process_key = event.get("process_key")
        current_parent_process_key = event.get("parent_process_key")

        if older_process_key and current_process_key and older_process_key == current_process_key:
            return True

        if older_process_key and current_parent_process_key and older_process_key == current_parent_process_key:
            return True

        if older_event.get("pid") == event.get("pid"):
            return True

        if (
            older_event.get("container_id")
            and event.get("container_id")
            and older_event.get("container_id") == event.get("container_id")
            and older_event.get("uid") == event.get("uid")
        ):
            return True

        return False

    def find_matching_exec(self, event: dict) -> dict | None:
        for exec_event in reversed(self.recent_execs):
            if self.same_execution_context(exec_event, event):
                return exec_event

        return None

    def find_matching_sensitive_open(self, event: dict) -> dict | None:
        for open_event in reversed(self.recent_sensitive_opens):
            if self.same_execution_context(open_event, event):
                return open_event

        return None

    @staticmethod
    def lineage_summary(event: dict) -> str:
        return ((event.get("lineage") or {}).get("summary") or "").lower()

    @staticmethod
    def lineage_ancestors(event: dict) -> list[dict]:
        return ((event.get("lineage") or {}).get("ancestors") or [])

    def lineage_contains_shell(self, event: dict) -> bool:
        summary = self.lineage_summary(event)
        shell_tokens = ("sh", "bash", "dash", "ash")
        return any(token in summary for token in shell_tokens)

    def last_ancestor_comm(self, event: dict) -> str | None:
        ancestors = self.lineage_ancestors(event)
        if not ancestors:
            return None

        return ancestors[-1].get("comm")

    def event_is_shell_related(self, event: dict) -> bool:
        comm = (event.get("comm") or "").lower()
        shell_names = {"sh", "bash", "dash", "ash"}

        if comm in shell_names:
            return True

        return self.lineage_contains_shell(event)