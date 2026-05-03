from __future__ import annotations

import asyncio
import queue

from backend.collector.collector_config import EBPF_PROGRAMS
from backend.collector.dispatcher import EventDispatcher
from backend.collector.event_enricher import EventEnricher
from backend.collector.feature_worker import FeatureWorker
from backend.collector.online_worker import OnlineWorker
from backend.collector.process_manager import EBPFProcessManager
from backend.collector.storage_worker import StorageWorker
from backend.collector.stream_reader import EventStreamReader
from backend.utils.process_lineage import ProcessLineageTracker


class RuntimeRunner:
    """
    Main composition root for the runtime collection pipeline.

    Responsibilities:
    - Create queues
    - Create workers
    - Start eBPF userspace binaries
    - Connect binary stdout streams into the dispatcher
    - Shutdown everything cleanly

    Detection logic lives outside this file.
    Event parsing/enrichment/filtering also lives outside this file.
    """

    def __init__(
        self,
        queue_maxsize: int = 10000,
        target_pod_name: str | None = "test-pod",
        print_events: bool = True,
    ):
        self.db_queue = queue.Queue(maxsize=queue_maxsize)
        self.online_queue = queue.Queue(maxsize=queue_maxsize)
        self.feature_queue = queue.Queue(maxsize=queue_maxsize)

        self.target_pod_name = target_pod_name

        self.lineage_tracker = ProcessLineageTracker(
            process_ttl_sec=900,
            max_nodes=50000,
            max_ancestors=8,
        )

        self.dispatcher = EventDispatcher(
            db_queue=self.db_queue,
            online_queue=self.online_queue,
            feature_queue=self.feature_queue,
        )

        self.storage_worker = StorageWorker(
            db_queue=self.db_queue,
            batch_size=20,
            flush_interval=2.0,
        )

        self.online_worker = OnlineWorker(
            online_queue=self.online_queue,
            window_seconds=30,
            burst_threshold=8,
            target_pod_name=self.target_pod_name,
        )

        self.feature_worker = FeatureWorker(
            feature_queue=self.feature_queue,
            window_seconds=10,
            target_pod_name=self.target_pod_name,
        )

        self.event_enricher = EventEnricher(
            lineage_tracker=self.lineage_tracker,
        )

        self.process_manager = EBPFProcessManager()

        self.stream_reader = EventStreamReader(
            dispatcher=self.dispatcher,
            event_enricher=self.event_enricher,
            print_events=print_events,
        )

    def _start_workers(self) -> None:
        self.storage_worker.start()
        self.online_worker.start()
        self.feature_worker.start()

        print("[runner] workers started")

    def _stop_workers(self) -> None:
        self.storage_worker.stop()
        self.online_worker.stop()
        self.feature_worker.stop()

    def _join_workers(self) -> None:
        self.storage_worker.join(timeout=3)
        self.online_worker.join(timeout=3)
        self.feature_worker.join(timeout=3)

    async def _start_stream_tasks(self) -> list[asyncio.Task]:
        tasks: list[asyncio.Task] = []

        for program in EBPF_PROGRAMS:
            proc = await self.process_manager.start_binary(
                cmd=program.cmd,
                name=program.name,
            )

            if not proc:
                continue

            task = asyncio.create_task(
                self.stream_reader.read_stream(
                    name=program.name,
                    proc=proc,
                    event_builder=program.event_builder,
                    skip_fn=program.skip_fn,
                )
            )

            tasks.append(task)

        return tasks

    async def run(self) -> None:
        self._start_workers()

        tasks = await self._start_stream_tasks()

        if not tasks:
            print("[runner] no binaries started")
            await self.shutdown()
            return

        try:
            await asyncio.gather(*tasks)

        except KeyboardInterrupt:
            print("[runner] stopping...")

        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        print("[runner] shutdown started")

        self._stop_workers()
        await self.process_manager.shutdown()
        self._join_workers()

        print("[runner] shutdown completed")


async def main() -> None:
    runner = RuntimeRunner()
    await runner.run()


if __name__ == "__main__":
    asyncio.run(main())