import queue
import threading
import time

from backend.utils.events_repo_sync import insert_events_raw_sync


class StorageWorker(threading.Thread):
    def __init__(self, db_queue: queue.Queue, batch_size: int = 20, flush_interval: float = 2.0):
        super().__init__(daemon=True)
        self.db_queue = db_queue
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._running = True

    def stop(self):
        self._running = False

    def _flush_batch(self, batch: list[dict]):
        if not batch:
            return

        inserted = insert_events_raw_sync(batch)
        print(f"[storage] inserted batch of {inserted} events")

    def run(self):
        batch = []
        last_flush = time.time()

        while self._running:
            now = time.time()
            timeout = max(0.1, self.flush_interval - (now - last_flush))

            try:
                event = self.db_queue.get(timeout=timeout)
                batch.append(event)
            except queue.Empty:
                pass

            now = time.time()
            should_flush = (
                len(batch) >= self.batch_size
                or (batch and (now - last_flush) >= self.flush_interval)
            )

            if should_flush:
                try:
                    self._flush_batch(batch)
                except Exception as exc:
                    print(f"[storage] flush failed: {exc}")
                finally:
                    batch = []
                    last_flush = time.time()

        if batch:
            try:
                self._flush_batch(batch)
            except Exception as exc:
                print(f"[storage] final flush failed: {exc}")