import queue
import threading

from backend.detection.online.online_detector import OnlineDetector
from backend.detection.online.detection_context import DetectionContext
from backend.detection.online.alert_filter import AlertFilter
from backend.detection.online.alert_deduplicator import AlertDeduplicator
from backend.utils.alerts_repo_sync import insert_alerts_sync


class OnlineWorker(threading.Thread):
    """
    Worker responsible only for:
    1. Reading normalized runtime events from online_queue
    2. Sending events to the online detection engine
    3. Filtering/deduplicating produced alerts
    4. Persisting alerts to MongoDB

    Detection logic itself lives under backend.detection.online.
    """

    def __init__(
        self,
        online_queue: queue.Queue,
        window_seconds: int = 30,
        burst_threshold: int = 8,
        correlation_window_seconds: int = 10,
        target_pod_name: str | None = "test-pod",
    ):
        super().__init__(daemon=True)

        self.online_queue = online_queue
        self.target_pod_name = target_pod_name
        self._running = True

        context = DetectionContext(
            window_seconds=window_seconds,
            correlation_window_seconds=correlation_window_seconds,
        )

        self.detector = OnlineDetector.create_default(
            context=context,
            burst_threshold=burst_threshold,
        )

        self.alert_filter = AlertFilter()
        self.alert_deduplicator = AlertDeduplicator()

    def stop(self) -> None:
        self._running = False

    def _should_process_event(self, event: dict) -> bool:
        if self.target_pod_name is None:
            return True

        return event.get("pod_name") == self.target_pod_name

    def run(self) -> None:
        print("[online-worker] started")

        while self._running:
            try:
                event = self.online_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                if not self._should_process_event(event):
                    continue

                alerts = self.detector.detect(event)
                alerts = self.alert_filter.apply(alerts)
                alerts = self.alert_deduplicator.apply(alerts)

                if not alerts:
                    continue

                for alert in alerts:
                    print("[online-detector]", alert)

                try:
                    inserted = insert_alerts_sync(alerts)
                    print(f"[online-detector] inserted {inserted} alerts")
                except Exception as exc:
                    print(f"[online-detector] failed to persist alerts: {exc}")

            except Exception as exc:
                print(f"[online-worker] failed to process event: {exc}")

            finally:
                try:
                    self.online_queue.task_done()
                except ValueError:
                    pass

        print("[online-worker] stopped")