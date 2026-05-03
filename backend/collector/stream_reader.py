from __future__ import annotations

import asyncio
import json
from typing import Callable, Optional, Any

from backend.collector.event_enricher import EventEnricher


EventBuilder = Callable[[dict], dict]
SkipFunction = Callable[[dict], bool]


class EventStreamReader:
    """
    Reads stdout from a userspace eBPF binary.

    Pipeline per line:
    raw stdout line
      -> JSON parse
      -> optional noise filter
      -> normalized event builder
      -> enrichment
      -> debug print
      -> dispatcher.dispatch(event)
    """

    def __init__(
        self,
        dispatcher,
        event_enricher: EventEnricher,
        print_events: bool = True,
    ):
        self.dispatcher = dispatcher
        self.event_enricher = event_enricher
        self.print_events = print_events

    async def read_stream(
        self,
        name: str,
        proc: Any,
        event_builder: EventBuilder,
        skip_fn: Optional[SkipFunction] = None,
    ) -> None:
        while True:
            line = await proc.stdout.readline()

            if not line:
                if proc.returncode is not None:
                    err = await proc.stderr.read()
                    print(f"{name} userspace binary exited:")
                    print(err.decode(errors="replace"))
                    break

                await asyncio.sleep(0.05)
                continue

            raw_line = line.decode(errors="replace").strip()

            if not raw_line.startswith("{"):
                continue

            try:
                data = json.loads(raw_line)

            except json.JSONDecodeError:
                continue

            if skip_fn and skip_fn(data):
                continue

            try:
                event = event_builder(data)
                event = self.event_enricher.enrich(event)

                if self.print_events:
                    self._print_event(name, event)

                self.dispatcher.dispatch(event)

            except Exception as exc:
                print(f"[runner] error processing {name} event: {exc}")

    def _print_event(self, name: str, event: dict) -> None:
        if name == "connect":
            self._print_connect_event(name, event)
            return

        if name == "openat":
            self._print_openat_event(name, event)
            return

        if name == "execve":
            self._print_execve_event(name, event)
            return

        self._print_generic_event(name, event)

    @staticmethod
    def _lineage_summary(event: dict) -> str | None:
        return event.get("lineage", {}).get("summary")

    def _print_connect_event(self, name: str, event: dict) -> None:
        print(
            f"[{name}] "
            f"pid={event.get('pid')} "
            f"ppid={event.get('ppid')} "
            f"uid={event.get('uid')} "
            f"comm={event.get('comm')} "
            f"cgroup_id={event.get('cgroup_id')} "
            f"ip={event.get('ip')} "
            f"port={event.get('port')} "
            f"family={event.get('family')} "
            f"ret={event.get('ret')} "
            f"success={event.get('success')} "
            f"container={event.get('container_id')} "
            f"resolver_status={event.get('resolver_status')} "
            f"lineage={self._lineage_summary(event)}"
        )

    def _print_openat_event(self, name: str, event: dict) -> None:
        print(
            f"[{name}] "
            f"pid={event.get('pid')} "
            f"ppid={event.get('ppid')} "
            f"uid={event.get('uid')} "
            f"comm={event.get('comm')} "
            f"cgroup_id={event.get('cgroup_id')} "
            f"filename={event.get('filename')} "
            f"container={event.get('container_id')} "
            f"resolver_status={event.get('resolver_status')} "
            f"lineage={self._lineage_summary(event)}"
        )

    def _print_execve_event(self, name: str, event: dict) -> None:
        print(
            f"[{name}] "
            f"pid={event.get('pid')} "
            f"ppid={event.get('ppid')} "
            f"uid={event.get('uid')} "
            f"comm={event.get('comm')} "
            f"cgroup_id={event.get('cgroup_id')} "
            f"filename={event.get('filename')} "
            f"container={event.get('container_id')} "
            f"resolver_status={event.get('resolver_status')} "
            f"lineage={self._lineage_summary(event)}"
        )

    def _print_generic_event(self, name: str, event: dict) -> None:
        print(
            f"[{name}] "
            f"pid={event.get('pid')} "
            f"ppid={event.get('ppid')} "
            f"uid={event.get('uid')} "
            f"comm={event.get('comm')} "
            f"cgroup_id={event.get('cgroup_id')} "
            f"container={event.get('container_id')} "
            f"resolver_status={event.get('resolver_status')} "
            f"lineage={self._lineage_summary(event)}"
        )