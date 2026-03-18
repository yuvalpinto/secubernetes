import queue
import threading
import time

from backend.utils.events_repo import insert_events_raw


class StorageWorker(threading.Thread):
    def __init__(self, db_queue: queue.Queue, batch_size: int = 20, flush_interval: float = 2.0):
        super().__init__(daemon=True)
        self.db_queue = db_queue
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._running = True

    def stop(self):
        self._running = False

    async def _flush_batch(self, batch):
        if batch:
            await insert_events_raw(batch)
            print(f"[storage] inserted batch of {len(batch)} events")

    def run(self):
        import asyncio

        asyncio.run(self._run_async())

    async def _run_async(self):
        batch = []
        last_flush = time.time()

        while self._running:
            now = time.time()

            try:
                event = self.db_queue.get(timeout=0.5)
                batch.append(event)
            except queue.Empty:
                pass

            if batch and (
                len(batch) >= self.batch_size or
                (now - last_flush) >= self.flush_interval
            ):
                await self._flush_batch(batch)
                batch = []
                last_flush = time.time()

        # flush אחרון ביציאה
        if batch:
            await self._flush_batch(batch)