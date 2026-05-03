from backend.detection.scoring.risk_score_combiner import RiskScoreCombiner
from backend.detection.scoring.sequence_score_helper_sync import SequenceScoreHelperSync
from backend.detection.features.container_risk_doc_builder import ContainerRiskDocBuilder



class ContainerRiskService:
    """
    Responsible for computing final container/window risk.

    Combines:
    - sequence score
    - adaptive threshold score
    - LOF score

    Then builds the document that will be persisted to MongoDB.
    """

    def __init__(
        self,
        risk_combiner: RiskScoreCombiner | None = None,
        sequence_helper: SequenceScoreHelperSync | None = None,
        doc_builder: ContainerRiskDocBuilder | None = None,
    ):
        self.risk_combiner = risk_combiner or RiskScoreCombiner()
        self.sequence_helper = sequence_helper or SequenceScoreHelperSync()
        self.doc_builder = doc_builder or ContainerRiskDocBuilder()

    def compute(
        self,
        vector: dict,
        threshold_result: dict,
        lof_result: dict,
    ) -> tuple[dict, dict, dict]:
        sequence_context = self.sequence_helper.compute_for_vector(vector)
        sequence_score = sequence_context.get("sequence_score", 0.0)

        combined_result = self.risk_combiner.combine(
            vector=vector,
            threshold_result=threshold_result,
            lof_result=lof_result,
            sequence_score=sequence_score,
            sequence_context=sequence_context,
        )

        print("[combined-risk]", {
            "namespace": combined_result.get("namespace"),
            "pod_name": combined_result.get("pod_name"),
            "final_risk_score": combined_result.get("final_risk_score"),
            "final_risk_level": combined_result.get("final_risk_level"),
            "sequence_score": combined_result.get("sequence_score"),
            "stat_score": combined_result.get("stat_score"),
            "lof_score": combined_result.get("lof_score"),
            "alerts_count": sequence_context.get("alerts_count"),
            "max_alert": sequence_context.get("max_alert"),
        })

        risk_doc = self.doc_builder.build(
            vector=vector,
            threshold_result=threshold_result,
            lof_result=lof_result,
            sequence_context=sequence_context,
            combined_result=combined_result,
        )

        return risk_doc, combined_result, sequence_context