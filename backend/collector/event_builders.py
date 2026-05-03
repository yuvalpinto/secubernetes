from __future__ import annotations

from datetime import datetime
from typing import Optional


def get_ppid_from_pid(pid: int | None) -> Optional[int]:
    if pid is None:
        return None

    try:
        with open(
            f"/proc/{pid}/status",
            "r",
            encoding="utf-8",
            errors="replace",
        ) as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])

    except Exception:
        return None

    return None


def _ppid_status(ppid: int | None) -> str:
    return "resolved" if ppid is not None else "pid_disappeared"


def build_execve_event(data: dict) -> dict:
    pid = data.get("pid")
    ppid = get_ppid_from_pid(pid)

    return {
        "event_type": "execve",
        "ts": datetime.utcnow(),

        "pid": pid,
        "ppid": ppid,
        "ppid_status": _ppid_status(ppid),

        "uid": data.get("uid"),
        "comm": data.get("comm"),
        "filename": data.get("filename"),

        "cgroup_id": data.get("cgroup_id"),
        "source": "libbpf_perf_buffer",
    }


def build_openat_event(data: dict) -> dict:
    pid = data.get("pid")
    ppid = get_ppid_from_pid(pid)

    return {
        "event_type": "openat",
        "ts": datetime.utcnow(),

        "pid": pid,
        "ppid": ppid,
        "ppid_status": _ppid_status(ppid),

        "uid": data.get("uid"),
        "comm": data.get("comm"),
        "filename": data.get("filename"),

        "cgroup_id": data.get("cgroup_id"),

        "dfd": data.get("dfd"),
        "flags": data.get("flags"),

        "source": "libbpf_perf_buffer",
    }


def build_connect_event(data: dict) -> dict:
    pid = data.get("pid")
    ppid = get_ppid_from_pid(pid)

    return {
        "event_type": "connect",
        "ts": datetime.utcnow(),

        "pid": pid,
        "ppid": ppid,
        "ppid_status": _ppid_status(ppid),

        "uid": data.get("uid"),
        "comm": data.get("comm"),

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