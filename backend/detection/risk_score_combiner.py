from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional


@dataclass
class RiskScoreConfig:
    """
    Weights should sum to 1.0
    """
    sequence_weight: float = 0.4
    stat_weight: float = 0.3
    lof_weight: float = 0.3

    # normalization params
    max_z_for_full_score: float = 10.0
    lof_baseline: float = 1.0
    lof_span_for_full_score: float = 4.0

    # final score thresholds
    critical_threshold: float = 80.0
    high_threshold: float = 60.0
    medium_threshold: float = 35.0

    # safety cap
    max_score: float = 100.0
    min_score: float = 0.0


class RiskScoreCombiner:
    """
    Final container risk combiner.

    Inputs:
    - feature vector
    - adaptive threshold result
    - lof result
    - sequence score (already normalized to 0..100)

    Output:
    - final container/window risk score
    """

    def __init__(self, config: Optional[RiskScoreConfig] = None):
        self.config = config or RiskScoreConfig()
        self._validate_weights()

    def combine(
        self,
        vector: Dict[str, Any],
        threshold_result: Optional[Dict[str, Any]] = None,
        lof_result: Optional[Dict[str, Any]] = None,
        sequence_score: float = 0.0,
        sequence_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        stat_score = self._normalize_threshold_score(threshold_result)
        lof_score = self._normalize_lof_score(lof_result)
        normalized_sequence_score = self._clamp_score(sequence_score)

        final_risk_score = (
            self.config.sequence_weight * normalized_sequence_score +
            self.config.stat_weight * stat_score +
            self.config.lof_weight * lof_score
        )

        final_risk_score = round(self._clamp_score(final_risk_score), 2)
        final_risk_level = self._derive_risk_level(final_risk_score)

        return {
            "ts": vector.get("window_end"),
            "namespace": vector.get("namespace"),
            "pod_name": vector.get("pod_name"),
            "window_start": vector.get("window_start"),
            "window_end": vector.get("window_end"),

            "sequence_score": round(normalized_sequence_score, 2),
            "stat_score": round(stat_score, 2),
            "lof_score": round(lof_score, 2),

            "weights": {
                "sequence_weight": self.config.sequence_weight,
                "stat_weight": self.config.stat_weight,
                "lof_weight": self.config.lof_weight,
            },

            "final_risk_score": final_risk_score,
            "final_risk_level": final_risk_level,

            "contributors": {
                "adaptive_threshold": threshold_result,
                "lof": lof_result,
                "sequence": sequence_context or {
                    "sequence_score": normalized_sequence_score
                },
            },

            "source_vector": vector,
        }

    def _normalize_threshold_score(
        self,
        threshold_result: Optional[Dict[str, Any]],
    ) -> float:
        """
        Convert adaptive threshold result into 0..100 score.
        Uses max_z_score as the main signal.
        """
        if not threshold_result:
            return 0.0

        max_z_score = float(threshold_result.get("max_z_score", 0.0))

        if max_z_score <= 0:
            return 0.0

        normalized = (max_z_score / self.config.max_z_for_full_score) * 100.0
        return self._clamp_score(normalized)

    def _normalize_lof_score(
        self,
        lof_result: Optional[Dict[str, Any]],
    ) -> float:
        """
        Convert LOF value into 0..100 score.

        Example:
        lof = 1.0 -> 0
        lof = 3.0 -> 50 if span=4
        lof = 5.0 -> 100 if span=4
        """
        if not lof_result:
            return 0.0

        lof_value = float(lof_result.get("lof_value", self.config.lof_baseline))

        if lof_value <= self.config.lof_baseline:
            return 0.0

        normalized = (
            (lof_value - self.config.lof_baseline)
            / self.config.lof_span_for_full_score
        ) * 100.0

        return self._clamp_score(normalized)

    def _derive_risk_level(self, final_risk_score: float) -> str:
        if final_risk_score >= self.config.critical_threshold:
            return "critical"
        if final_risk_score >= self.config.high_threshold:
            return "high"
        if final_risk_score >= self.config.medium_threshold:
            return "medium"
        return "low"

    def _clamp_score(self, score: float) -> float:
        return max(self.config.min_score, min(score, self.config.max_score))

    def _validate_weights(self) -> None:
        total = (
            self.config.sequence_weight +
            self.config.stat_weight +
            self.config.lof_weight
        )

        # tolerance for floating point
        if abs(total - 1.0) > 1e-9:
            raise ValueError(
                f"RiskScoreConfig weights must sum to 1.0, got {total}"
            )

    def get_config_dict(self) -> Dict[str, Any]:
        return asdict(self.config)