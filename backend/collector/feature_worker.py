import queue
import threading
from typing import Optional, Callable, Any

from backend.detection.adaptive_threshold_detector import AdaptiveThresholdDetector
from backend.detection.feature_window_builder import FeatureWindowBuilder
from backend.utils.feature_vectors_repo_sync import insert_feature_vector_sync
from backend.utils.feature_anomalies_repo_sync import insert_feature_anomaly_sync
class FeatureWorker(threading.Thread):
    """
    Worker dedicated to:
    1. reading normalized events from feature_queue
    2. aggregating them into time windows
    3. emitting feature vectors for later anomaly detection

    This worker is intentionally separated from OnlineWorker so that
    alerting/correlation logic stays lightweight and low-latency.
    """

    def __init__(
        self,
        feature_queue: queue.Queue,
        window_seconds: int = 10,
        stop_event: Optional[threading.Event] = None,
        vector_callback: Optional[Callable[[dict], Any]] = None,
    ):
        super().__init__(daemon=True)
        self.feature_queue = feature_queue
        self.stop_event = stop_event or threading.Event()
        self.builder = FeatureWindowBuilder(window_seconds=window_seconds)
        self.vector_callback = vector_callback

        self.detector = AdaptiveThresholdDetector(
            threshold_k=2.5,
            min_history=5,
            min_std=1.0,
            enabled_features=[
                "exec_count_window",
                "sensitive_open_count_window",
                "connect_count_window",
                "failed_connect_count_window",
                "unique_destination_count_window",
            ],
        )
    def stop(self):
        self.stop_event.set()
    
    def _derive_anomaly_severity(self, max_z_score: float) -> str:
        if max_z_score >= 10:
            return "high"
        if max_z_score >= 5:
            return "medium"
        return "low"

    def run(self):
        print("[feature-worker] started")

        while not self.stop_event.is_set():
            try:
                event = self.feature_queue.get(timeout=1)
            except queue.Empty:
                self._flush_expired_vectors()
                continue

            try:
                if event.get("pod_name") != "test-pod":
                    continue

                vectors = self.builder.process_event(event)

                for vector in vectors:
                    self.handle_feature_vector(vector)

            except Exception as exc:
                print(f"[feature-worker] error while processing event: {exc}")

            finally:
                self.feature_queue.task_done()

        try:
            self._flush_expired_vectors()
            remaining_vectors = self.builder.flush_all()
            for vector in remaining_vectors:
                self.handle_feature_vector(vector)
        except Exception as exc:
            print(f"[feature-worker] error during shutdown flush: {exc}")

        print("[feature-worker] stopped")
    def _flush_expired_vectors(self):
        try:
            expired_vectors = self.builder.flush_expired()
            for vector in expired_vectors:
                self.handle_feature_vector(vector)
        except Exception as exc:
            print(f"[feature-worker] error while flushing expired windows: {exc}")

    def handle_feature_vector(self, vector: dict):
        try:
            insert_feature_vector_sync(vector)

            result = self.detector.process_vector(vector)

            print("[feature-vector saved]", {
                "namespace": vector.get("namespace"),
                "pod_name": vector.get("pod_name"),
                "window_start": vector.get("window_start"),
                "window_end": vector.get("window_end"),
            })

            if result["anomaly_detected"]:
                anomaly_doc = {
                    "ts": result.get("ts"),
                    "detector_type": result.get("detector_type"),
                    "namespace": result.get("namespace"),
                    "pod_name": result.get("pod_name"),
                    "anomaly_detected": result.get("anomaly_detected"),
                    "triggered_features": result.get("triggered_features"),
                    "max_z_score": result.get("max_z_score"),
                    "threshold_k": result.get("threshold_k"),
                    "feature_scores": result.get("feature_scores"),
                    "source_vector": result.get("source_vector"),
                    "severity": self._derive_anomaly_severity(
                        result.get("max_z_score", 0.0)
                    ),
                }

                insert_feature_anomaly_sync(anomaly_doc)

                print("[adaptive-threshold anomaly saved]", {
                    "namespace": anomaly_doc["namespace"],
                    "pod_name": anomaly_doc["pod_name"],
                    "triggered_features": anomaly_doc["triggered_features"],
                    "max_z_score": anomaly_doc["max_z_score"],
                    "severity": anomaly_doc["severity"],
                })

        except Exception as exc:
            print(f"[feature-worker] failed to handle feature vector: {exc}")