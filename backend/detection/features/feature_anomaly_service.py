from backend.detection.detectors.adaptive_threshold_detector import AdaptiveThresholdDetector
from backend.detection.detectors.lof_detector import LOFDetector, LOFConfig

from backend.detection.scoring.severity import (
    severity_from_z_score,
    severity_from_lof,
)

from backend.utils.feature_anomalies_repo_sync import insert_feature_anomaly_sync


DEFAULT_ENABLED_FEATURES = [
    "exec_count_window",
    "sensitive_open_count_window",
    "connect_count_window",
    "failed_connect_count_window",
    "unique_destination_count_window",
]


class FeatureAnomalyService:
    """
    Responsible for feature-vector anomaly detection.

    Runs:
    1. Adaptive Threshold
    2. LOF

    Also persists anomaly documents when anomalies are detected.
    """

    def __init__(
        self,
        threshold_detector: AdaptiveThresholdDetector | None = None,
        lof_detector: LOFDetector | None = None,
    ):
        self.threshold_detector = threshold_detector or AdaptiveThresholdDetector(
            threshold_k=2.5,
            min_history=5,
            min_std=1.0,
            enabled_features=DEFAULT_ENABLED_FEATURES,
        )

        self.lof_detector = lof_detector or LOFDetector(
            LOFConfig(
                k_neighbors=3,
                min_history=5,
                max_history=100,
                anomaly_threshold=1.5,
                enabled_features=DEFAULT_ENABLED_FEATURES,
            )
        )

    def process(self, vector: dict) -> tuple[dict, dict]:
        threshold_result = self.process_threshold(vector)
        lof_result = self.process_lof(vector)

        return threshold_result, lof_result

    def process_threshold(self, vector: dict) -> dict:
        threshold_result = self.threshold_detector.process_vector(vector)

        if threshold_result.get("anomaly_detected"):
            anomaly_doc = self._build_threshold_anomaly_doc(threshold_result)
            insert_feature_anomaly_sync(anomaly_doc)

            print("[adaptive-threshold anomaly saved]", {
                "namespace": anomaly_doc.get("namespace"),
                "pod_name": anomaly_doc.get("pod_name"),
                "triggered_features": anomaly_doc.get("triggered_features"),
                "max_z_score": anomaly_doc.get("max_z_score"),
                "severity": anomaly_doc.get("severity"),
            })

        return threshold_result

    def process_lof(self, vector: dict) -> dict:
        lof_result = self.lof_detector.process_vector(vector)

        print("[lof-result]", {
            "namespace": lof_result.get("namespace"),
            "pod_name": lof_result.get("pod_name"),
            "lof_value": lof_result.get("lof_value"),
            "anomaly_detected": lof_result.get("anomaly_detected"),
            "history_size": lof_result.get("history_size"),
            "warming_up": lof_result.get("warming_up", False),
        })

        if lof_result.get("anomaly_detected"):
            anomaly_doc = self._build_lof_anomaly_doc(lof_result)
            insert_feature_anomaly_sync(anomaly_doc)

            print("[lof anomaly saved]", {
                "namespace": anomaly_doc.get("namespace"),
                "pod_name": anomaly_doc.get("pod_name"),
                "lof_value": anomaly_doc.get("lof_value"),
                "severity": anomaly_doc.get("severity"),
            })

        return lof_result

    @staticmethod
    def _build_threshold_anomaly_doc(threshold_result: dict) -> dict:
        max_z_score = threshold_result.get("max_z_score", 0.0)

        return {
            "ts": threshold_result.get("ts"),
            "detector_type": threshold_result.get("detector_type"),
            "namespace": threshold_result.get("namespace"),
            "pod_name": threshold_result.get("pod_name"),
            "anomaly_detected": threshold_result.get("anomaly_detected"),
            "triggered_features": threshold_result.get("triggered_features"),
            "max_z_score": max_z_score,
            "threshold_k": threshold_result.get("threshold_k"),
            "feature_scores": threshold_result.get("feature_scores"),
            "source_vector": threshold_result.get("source_vector"),
            "severity": severity_from_z_score(max_z_score),
        }

    @staticmethod
    def _build_lof_anomaly_doc(lof_result: dict) -> dict:
        lof_value = lof_result.get("lof_value", 1.0)

        return {
            "ts": lof_result.get("ts"),
            "detector_type": lof_result.get("detector_type"),
            "namespace": lof_result.get("namespace"),
            "pod_name": lof_result.get("pod_name"),
            "anomaly_detected": lof_result.get("anomaly_detected"),
            "lof_value": lof_value,
            "threshold": lof_result.get("threshold"),
            "k_neighbors": lof_result.get("k_neighbors"),
            "history_size": lof_result.get("history_size"),
            "enabled_features": lof_result.get("enabled_features"),
            "source_vector": lof_result.get("source_vector"),
            "severity": severity_from_lof(lof_value),
        }