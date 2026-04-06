from backend.utils.container_resolver import resolve_container_info_from_pid
from backend.utils.process_lineage import ProcessLineageTracker


lineage_tracker = ProcessLineageTracker()


def enrich_execve_event(event: dict) -> dict:
    pid = event.get("pid")
    if pid is not None:
        container_info = resolve_container_info_from_pid(pid)
        event["container_id"] = container_info.get("container_id")
        event["pod_uid"] = container_info.get("pod_uid")
        event["resolver_status"] = container_info.get("resolver_status")
        event["runtime"] = container_info.get("runtime")
        event["pod_name"] = container_info.get("pod_name")
        event["namespace"] = container_info.get("namespace")
        event["container_name"] = container_info.get("container_name")

    return lineage_tracker.enrich_event(event)


def enrich_openat_event(event: dict) -> dict:
    pid = event.get("pid")
    if pid is not None:
        container_info = resolve_container_info_from_pid(pid)
        event["container_id"] = container_info.get("container_id")
        event["pod_uid"] = container_info.get("pod_uid")
        event["resolver_status"] = container_info.get("resolver_status")
        event["runtime"] = container_info.get("runtime")
        event["pod_name"] = container_info.get("pod_name")
        event["namespace"] = container_info.get("namespace")
        event["container_name"] = container_info.get("container_name")

    return lineage_tracker.enrich_event(event)