from __future__ import annotations

import re
from pathlib import Path
from typing import Optional


# דפוסים נפוצים של container id בתוך cgroup path
CONTAINER_PATTERNS = [
    r"docker-([a-f0-9]{12,64})\.scope",
    r"cri-containerd-([a-f0-9]{12,64})\.scope",
    r"containerd-([a-f0-9]{12,64})\.scope",
    r"crio-([a-f0-9]{12,64})\.scope",
    r"/([a-f0-9]{64})(?:\.scope)?",
    r"/([a-f0-9]{32,64})$",
]


def read_cgroup(pid: int) -> Optional[str]:
    """
    קורא את /proc/<pid>/cgroup ומחזיר את כל הטקסט.
    מחזיר None אם התהליך כבר לא קיים או שאין הרשאה.
    """
    path = Path(f"/proc/{pid}/cgroup")

    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None


def extract_container_id(cgroup_text: str) -> Optional[str]:
    """
    מנסה לחלץ container id מתוך תוכן cgroup.
    """
    for pattern in CONTAINER_PATTERNS:
        match = re.search(pattern, cgroup_text)
        if match:
            return match.group(1)

    return None


def extract_pod_uid(cgroup_text: str) -> Optional[str]:
    """
    אופציונלי: מנסה לחלץ pod UID מתוך cgroup path של Kubernetes.
    לדוגמה:
    kubepods-burstable-pod<uid>.slice
    """
    pod_patterns = [
        r"pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})",
    ]

    for pattern in pod_patterns:
        match = re.search(pattern, cgroup_text)
        if match:
            return match.group(1).replace("_", "-")

    return None


def resolve_container_info_from_pid(pid: int) -> dict:
    """
    פונקציה ראשית:
    מקבלת PID ומחזירה מידע בסיסי שניתן להוציא מתוך cgroup.
    """
    cgroup_text = read_cgroup(pid)

    if not cgroup_text:
        return {
            "container_id": None,
            "pod_uid": None,
            "cgroup_text": None,
        }

    container_id = extract_container_id(cgroup_text)
    pod_uid = extract_pod_uid(cgroup_text)

    return {
        "container_id": container_id,
        "pod_uid": pod_uid,
        "cgroup_text": cgroup_text,
    }