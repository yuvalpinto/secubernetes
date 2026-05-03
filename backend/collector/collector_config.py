from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from backend.collector.event_builders import (
    build_execve_event,
    build_openat_event,
    build_connect_event,
)
from backend.collector.event_filters import should_skip_openat


PROJECT_ROOT = Path(__file__).resolve().parents[2]

EXECVE_BINARY = [str(PROJECT_ROOT / "ebpf" / "execve")]
OPENAT_BINARY = [str(PROJECT_ROOT / "ebpf" / "openat")]
CONNECT_BINARY = [str(PROJECT_ROOT / "ebpf" / "connect")]


EventBuilder = Callable[[dict], dict]
SkipFunction = Callable[[dict], bool]


@dataclass(frozen=True)
class EBPFProgram:
    name: str
    cmd: list[str]
    event_builder: EventBuilder
    skip_fn: Optional[SkipFunction] = None


EBPF_PROGRAMS: list[EBPFProgram] = [
    EBPFProgram(
        name="execve",
        cmd=EXECVE_BINARY,
        event_builder=build_execve_event,
    ),
    EBPFProgram(
        name="openat",
        cmd=OPENAT_BINARY,
        event_builder=build_openat_event,
        skip_fn=should_skip_openat,
    ),
    EBPFProgram(
        name="connect",
        cmd=CONNECT_BINARY,
        event_builder=build_connect_event,
    ),
]