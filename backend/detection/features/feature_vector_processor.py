from typing import Callable, Any, Optional

from backend.detection.features.feature_anomaly_service import FeatureAnomalyService
from backend.detection.features.container_risk_service import ContainerRiskService

from backend.utils.feature_vectors_repo_sync import insert_feature_vector_sync
from backend.utils.container_risk_scores_repo_sync import insert_container_risk_score_sync


class FeatureVectorProcessor:
    """
    Handles the full processing pipeline for one completed feature vector:

    1. Save feature vector
    2. Run Adaptive Threshold
    3. Run LOF
    4. Compute sequence score
    5. Compute combined container risk
    6. Save container risk score
    """

    def __init__(
        self,
        anomaly_service: FeatureAnomalyService | None = None,
        container_risk_service: ContainerRiskService | None = None,
        vector_callback: Optional[Callable[[dict], Any]] = None,
    ):
        self.anomaly_service = anomaly_service or FeatureAnomalyService()
        self.container_risk_service = container_risk_service or ContainerRiskService()
        self.vector_callback = vector_callback

    def process(self, vector: dict) -> None:
        try:
            self._save_feature_vector(vector)
            self._run_vector_callback(vector)

            threshold_result, lof_result = self.anomaly_service.process(vector)

            risk_doc, combined_result, sequence_context = self.container_risk_service.compute(
                vector=vector,
                threshold_result=threshold_result,
                lof_result=lof_result,
            )

            self._save_container_risk_score(risk_doc)

        except Exception as exc:
            print(f"[feature-vector-processor] failed to process feature vector: {exc}")

    def _save_feature_vector(self, vector: dict) -> None:
        insert_feature_vector_sync(vector)

        print("[feature-vector saved]", {
            "namespace": vector.get("namespace"),
            "pod_name": vector.get("pod_name"),
            "window_start": vector.get("window_start"),
            "window_end": vector.get("window_end"),
        })

    def _run_vector_callback(self, vector: dict) -> None:
        if not self.vector_callback:
            return

        try:
            self.vector_callback(vector)
        except Exception as exc:
            print(f"[feature-vector-processor] vector_callback failed: {exc}")

    @staticmethod
    def _save_container_risk_score(risk_doc: dict) -> None:
        insert_container_risk_score_sync(risk_doc)

        print("[container-risk-score saved]", {
            "namespace": risk_doc.get("namespace"),
            "pod_name": risk_doc.get("pod_name"),
            "final_risk_score": risk_doc.get("final_risk_score"),
            "final_risk_level": risk_doc.get("final_risk_level"),
            "severity": risk_doc.get("severity"),
        })