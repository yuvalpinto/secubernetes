import queue
import threading
from typing import Optional, Callable, Any

from backend.detection.features.feature_window_builder import FeatureWindowBuilder
from backend.detection.features.feature_vector_processor import FeatureVectorProcessor


class FeatureWorker(threading.Thread):
    """
    Worker responsible only for:
    1. reading normalized events from feature_queue
    2. filtering target pod if configured
    3. passing events into FeatureWindowBuilder
    4. passing completed vectors into FeatureVectorProcessor

    The actual anomaly/risk logic is handled under backend.detection.features.
    """

    def __init__(
        self,
        feature_queue: queue.Queue,
        window_seconds: int = 10,
        stop_event: Optional[threading.Event] = None,
        vector_callback: Optional[Callable[[dict], Any]] = None,
        target_pod_name: str | None = "test-pod",
        builder: FeatureWindowBuilder | None = None,
        processor: FeatureVectorProcessor | None = None,
    ):
        super().__init__(daemon=True)

        self.feature_queue = feature_queue
        self.stop_event = stop_event or threading.Event()
        self.target_pod_name = target_pod_name

        self.builder = builder or FeatureWindowBuilder(
            window_seconds=window_seconds,
        )

        self.processor = processor or FeatureVectorProcessor(
            vector_callback=vector_callback,
        )

    def stop(self) -> None:
        self.stop_event.set()

    def _should_process_event(self, event: dict) -> bool:
        if self.target_pod_name is None:
            return True

        return event.get("pod_name") == self.target_pod_name

    def run(self) -> None:
        print("[feature-worker] started")

        while not self.stop_event.is_set():
            try:
                event = self.feature_queue.get(timeout=1)
            except queue.Empty:
                self._flush_expired_vectors()
                continue

            try:
                print("[feature-worker raw-event]", {
                    "pod_name": event.get("pod_name"),
                    "namespace": event.get("namespace"),
                    "event_type": event.get("event_type"),
                    "ts": event.get("ts"),
                })

                if not self._should_process_event(event):
                    print("[feature-worker skipped-event]", {
                        "pod_name": event.get("pod_name"),
                        "namespace": event.get("namespace"),
                        "event_type": event.get("event_type"),
                    })
                    continue

                vectors = self.builder.process_event(event)

                print("[feature-worker builder]", {
                    "returned_vectors_count": len(vectors),
                    "event_pod": event.get("pod_name"),
                    "event_ts": event.get("ts"),
                })

                for vector in vectors:
                    self.processor.process(vector)

            except Exception as exc:
                print(f"[feature-worker] error while processing event: {exc}")

            finally:
                try:
                    self.feature_queue.task_done()
                except ValueError:
                    pass

        self._shutdown_flush()
        print("[feature-worker] stopped")

    def _flush_expired_vectors(self) -> None:
        try:
            expired_vectors = self.builder.flush_expired()

            for vector in expired_vectors:
                self.processor.process(vector)

        except Exception as exc:
            print(f"[feature-worker] error while flushing expired windows: {exc}")

    def _shutdown_flush(self) -> None:
        try:
            self._flush_expired_vectors()

            remaining_vectors = self.builder.flush_all()
            for vector in remaining_vectors:
                self.processor.process(vector)

        except Exception as exc:
            print(f"[feature-worker] error during shutdown flush: {exc}")