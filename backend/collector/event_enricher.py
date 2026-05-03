from __future__ import annotations

from backend.utils.container_resolver import (
    resolve_container_info_from_pid,
    resolve_container_info_from_cgroup_id,
)


DEFAULT_CONTAINER_FIELDS = {
    "container_id": None,
    "pod_uid": None,
    "pod_name": None,
    "namespace": None,
    "container_name": None,
    "runtime": None,
    "resolver_status": None,
}


class EventEnricher:
    """
    Adds container metadata and process lineage to normalized events.

    Responsibilities:
    - Resolve container/pod context from cgroup_id when available
    - Fallback to pid/ppid resolver when cgroup_id is unavailable
    - Attach process lineage data
    - Ensure container-related fields always exist
    """

    def __init__(self, lineage_tracker):
        self.lineage_tracker = lineage_tracker

    def enrich(self, event: dict) -> dict:
        event = self._attach_container_info(event)
        event = self._attach_lineage(event)
        event = self._ensure_default_fields(event)

        return event

    def _attach_container_info(self, event: dict) -> dict:
        pid = event.get("pid")
        ppid = event.get("ppid")
        cgroup_id = event.get("cgroup_id")

        try:
            if cgroup_id is not None:
                container_info = resolve_container_info_from_cgroup_id(cgroup_id)
            else:
                container_info = resolve_container_info_from_pid(
                    pid=pid,
                    ppid=ppid,
                    allow_parent_fallback=True,
                )

        except Exception as exc:
            container_info = {
                "resolver_status": f"resolver_error:{type(exc).__name__}",
            }

        if container_info:
            event.update(container_info)

        return event

    def _attach_lineage(self, event: dict) -> dict:
        pid = event.get("pid")

        if pid is None:
            return event

        try:
            return self.lineage_tracker.enrich_event(event)

        except Exception as exc:
            event["lineage_error"] = type(exc).__name__
            return event

    @staticmethod
    def _ensure_default_fields(event: dict) -> dict:
        for field, default_value in DEFAULT_CONTAINER_FIELDS.items():
            event.setdefault(field, default_value)

        return event