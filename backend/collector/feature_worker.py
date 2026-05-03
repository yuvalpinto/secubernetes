import queue
import threading
from typing import Optional, Callable, Any

from backend.detection.lof_detector import LOFDetector, LOFConfig
from backend.detection.adaptive_threshold_detector import AdaptiveThresholdDetector
from backend.detection.feature_window_builder import FeatureWindowBuilder
from backend.detection.risk_score_combiner import RiskScoreCombiner
from backend.detection.sequence_score_helper_sync import SequenceScoreHelperSync

from backend.utils.feature_vectors_repo_sync import insert_feature_vector_sync
from backend.utils.feature_anomalies_repo_sync import insert_feature_anomaly_sync
from backend.utils.container_risk_scores_repo_sync import insert_container_risk_score_sync


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
        self.risk_combiner = RiskScoreCombiner()
        self.builder = FeatureWindowBuilder(window_seconds=window_seconds)
        self.vector_callback = vector_callback
        self.sequence_helper = SequenceScoreHelperSync()

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

        self.lof_detector = LOFDetector(
            LOFConfig(
                k_neighbors=3,
                min_history=5,
                max_history=100,
                anomaly_threshold=1.5,
                enabled_features=[
                    "exec_count_window",
                    "sensitive_open_count_window",
                    "connect_count_window",
                    "failed_connect_count_window",
                    "unique_destination_count_window",
                ],
            )
        )

    def stop(self):
        self.stop_event.set()

    def _derive_anomaly_severity(self, max_z_score: float) -> str:
        if max_z_score >= 10:
            return "high"
        if max_z_score >= 5:
            return "medium"
        return "low"

    def _derive_anomaly_severity_from_lof(self, lof_value: float) -> str:
        if lof_value >= 10:
            return "high"
        if lof_value >= 3:
            return "medium"
        return "low"

    def _derive_combined_risk_severity(self, final_risk_score: float) -> str:
        if final_risk_score >= 80:
            return "critical"
        if final_risk_score >= 60:
            return "high"
        if final_risk_score >= 30:
            return "medium"
        return "low"

    def _build_container_risk_score_doc(
        self,
        vector: dict,
        threshold_result: dict,
        lof_result: dict,
        sequence_context: dict,
        combined_result: dict,
    ) -> dict:
        namespace = combined_result.get("namespace") or vector.get("namespace")
        pod_name = combined_result.get("pod_name") or vector.get("pod_name")
        container_id = (
            vector.get("container_id")
            or vector.get("resolved_container_id")
            or vector.get("source_container_id")
        )

        final_risk_score = combined_result.get("final_risk_score", 0.0)

        return {
            "ts": combined_result.get("ts") or vector.get("window_end") or vector.get("ts"),
            "namespace": namespace,
            "pod_name": pod_name,
            "container_id": container_id,
            "entity_key": f"{namespace}:{pod_name}" if namespace and pod_name else None,
            "window_start": vector.get("window_start"),
            "window_end": vector.get("window_end"),

            "final_risk_score": final_risk_score,
            "final_risk_level": combined_result.get("final_risk_level"),
            "severity": self._derive_combined_risk_severity(final_risk_score),

            "sequence_score": combined_result.get("sequence_score", 0.0),
            "stat_score": combined_result.get("stat_score", 0.0),
            "lof_score": combined_result.get("lof_score", 0.0),

            "alerts_count": sequence_context.get("alerts_count", 0),
            "max_alert": sequence_context.get("max_alert"),

            "threshold_anomaly_detected": threshold_result.get("anomaly_detected"),
            "threshold_max_z_score": threshold_result.get("max_z_score"),
            "threshold_triggered_features": threshold_result.get("triggered_features"),

            "lof_anomaly_detected": lof_result.get("anomaly_detected"),
            "lof_value": lof_result.get("lof_value"),
            "lof_history_size": lof_result.get("history_size"),

            "exec_count_window": vector.get("exec_count_window"),
            "sensitive_open_count_window": vector.get("sensitive_open_count_window"),
            "connect_count_window": vector.get("connect_count_window"),
            "failed_connect_count_window": vector.get("failed_connect_count_window"),
            "unique_destination_count_window": vector.get("unique_destination_count_window"),
        }
    def run(self):
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

                if event.get("pod_name") != "test-pod":
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

            print("[feature-vector saved]", {
                "namespace": vector.get("namespace"),
                "pod_name": vector.get("pod_name"),
                "window_start": vector.get("window_start"),
                "window_end": vector.get("window_end"),
            })

            if self.vector_callback:
                try:
                    self.vector_callback(vector)
                except Exception as exc:
                    print(f"[feature-worker] vector_callback failed: {exc}")

            # ---------------------------
            # Adaptive Threshold
            # ---------------------------
            threshold_result = self.detector.process_vector(vector)

            if threshold_result["anomaly_detected"]:
                threshold_anomaly_doc = {
                    "ts": threshold_result.get("ts"),
                    "detector_type": threshold_result.get("detector_type"),
                    "namespace": threshold_result.get("namespace"),
                    "pod_name": threshold_result.get("pod_name"),
                    "anomaly_detected": threshold_result.get("anomaly_detected"),
                    "triggered_features": threshold_result.get("triggered_features"),
                    "max_z_score": threshold_result.get("max_z_score"),
                    "threshold_k": threshold_result.get("threshold_k"),
                    "feature_scores": threshold_result.get("feature_scores"),
                    "source_vector": threshold_result.get("source_vector"),
                    "severity": self._derive_anomaly_severity(
                        threshold_result.get("max_z_score", 0.0)
                    ),
                }

                insert_feature_anomaly_sync(threshold_anomaly_doc)

                print("[adaptive-threshold anomaly saved]", {
                    "namespace": threshold_anomaly_doc["namespace"],
                    "pod_name": threshold_anomaly_doc["pod_name"],
                    "triggered_features": threshold_anomaly_doc["triggered_features"],
                    "max_z_score": threshold_anomaly_doc["max_z_score"],
                    "severity": threshold_anomaly_doc["severity"],
                })

            # ---------------------------
            # LOF
            # ---------------------------
            lof_result = self.lof_detector.process_vector(vector)

            print("[lof-result]", {
                "namespace": lof_result.get("namespace"),
                "pod_name": lof_result.get("pod_name"),
                "lof_value": lof_result.get("lof_value"),
                "anomaly_detected": lof_result.get("anomaly_detected"),
                "history_size": lof_result.get("history_size"),
                "warming_up": lof_result.get("warming_up", False),
            })

            if lof_result["anomaly_detected"]:
                lof_anomaly_doc = {
                    "ts": lof_result.get("ts"),
                    "detector_type": lof_result.get("detector_type"),
                    "namespace": lof_result.get("namespace"),
                    "pod_name": lof_result.get("pod_name"),
                    "anomaly_detected": lof_result.get("anomaly_detected"),
                    "lof_value": lof_result.get("lof_value"),
                    "threshold": lof_result.get("threshold"),
                    "k_neighbors": lof_result.get("k_neighbors"),
                    "history_size": lof_result.get("history_size"),
                    "enabled_features": lof_result.get("enabled_features"),
                    "source_vector": lof_result.get("source_vector"),
                    "severity": self._derive_anomaly_severity_from_lof(
                        lof_result.get("lof_value", 1.0)
                    ),
                }

                insert_feature_anomaly_sync(lof_anomaly_doc)

                print("[lof anomaly saved]", {
                    "namespace": lof_anomaly_doc["namespace"],
                    "pod_name": lof_anomaly_doc["pod_name"],
                    "lof_value": lof_anomaly_doc["lof_value"],
                    "severity": lof_anomaly_doc["severity"],
                })

            # ---------------------------
            # Sequence score
            # ---------------------------
            sequence_context = self.sequence_helper.compute_for_vector(vector)
            sequence_score = sequence_context["sequence_score"]

            # ---------------------------
            # Combined risk
            # ---------------------------
            combined_result = self.risk_combiner.combine(
                vector=vector,
                threshold_result=threshold_result,
                lof_result=lof_result,
                sequence_score=sequence_score,
                sequence_context=sequence_context,
            )

            print("[combined-risk]", {
                "namespace": combined_result["namespace"],
                "pod_name": combined_result["pod_name"],
                "final_risk_score": combined_result["final_risk_score"],
                "final_risk_level": combined_result["final_risk_level"],
                "sequence_score": combined_result["sequence_score"],
                "stat_score": combined_result["stat_score"],
                "lof_score": combined_result["lof_score"],
                "alerts_count": sequence_context["alerts_count"],
                "max_alert": sequence_context["max_alert"],
            })

            # ---------------------------
            # Save combined risk to Mongo
            # ---------------------------
            container_risk_score_doc = self._build_container_risk_score_doc(
                vector=vector,
                threshold_result=threshold_result,
                lof_result=lof_result,
                sequence_context=sequence_context,
                combined_result=combined_result,
            )

            insert_container_risk_score_sync(container_risk_score_doc)

            print("[container-risk-score saved]", {
                "namespace": container_risk_score_doc["namespace"],
                "pod_name": container_risk_score_doc["pod_name"],
                "final_risk_score": container_risk_score_doc["final_risk_score"],
                "final_risk_level": container_risk_score_doc["final_risk_level"],
                "severity": container_risk_score_doc["severity"],
            })

        except Exception as exc:
            print(f"[feature-worker] failed to handle feature vector: {exc}")