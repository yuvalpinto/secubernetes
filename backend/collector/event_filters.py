from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


NOISY_PREFIXES = (
    "/proc/",
    "/sys/",
    str(PROJECT_ROOT / "backend") + "/",
    str(PROJECT_ROOT / "ebpf") + "/",
    str(PROJECT_ROOT / ".git") + "/",
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


def should_skip_openat(data: dict) -> bool:
    filename = data.get("filename", "") or ""
    comm = data.get("comm", "") or ""

    if filename.startswith(NOISY_PREFIXES):
        return True

    if any(token in filename for token in NOISY_PATH_CONTAINS):
        return True

    if comm in NOISY_COMMS:
        return True

    return False