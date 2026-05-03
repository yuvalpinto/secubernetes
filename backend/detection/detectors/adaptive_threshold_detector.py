from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple


@dataclass
class RunningStats:
    """
    Welford online algorithm for stable running mean/std.
    """
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)


class AdaptiveThresholdDetector:
    """
    Per-(namespace, pod_name), per-feature online statistical detector.

    For each feature:
      - keeps running mean/std
      - computes z-score
      - flags anomaly if z-score > threshold_k

    Notes:
      - detector warms up before alerting
      - stats are updated after evaluation
    """

    DEFAULT_FEATURES = [
        "exec_count_window",
        "sensitive_open_count_window",
        "connect_count_window",
        "failed_connect_count_window",
        "root_event_count_window",
        "unique_destination_count_window",
        "total_event_count_window",
        "file_open_count_window",
        "non_sensitive_open_count_window",
        "unique_process_count_window",
        "unique_command_count_window",
    ]

    def __init__(
        self,
        threshold_k: float = 3.0,
        min_history: int = 5,
        min_std: float = 1.0,
        enabled_features: List[str] | None = None,
    ) -> None:
        self.threshold_k = threshold_k
        self.min_history = min_history
        self.min_std = min_std
        self.enabled_features = enabled_features or list(self.DEFAULT_FEATURES)

        self.stats: Dict[
            Tuple[str, str], Dict[str, RunningStats]
        ] = {}

    def process_vector(self, vector: Dict[str, Any]) -> Dict[str, Any]:
        namespace = str(vector.get("namespace", "unknown"))
        pod_name = str(vector.get("pod_name", "unknown"))
        key = (namespace, pod_name)

        if key not in self.stats:
            self.stats[key] = {
                feature: RunningStats() for feature in self.enabled_features
            }

        pod_stats = self.stats[key]

        triggered_features = []
        feature_scores = {}

        for feature in self.enabled_features:
            value = vector.get(feature)

            if not isinstance(value, (int, float)):
                continue

            stat = pod_stats[feature]

            current_std = max(stat.std, self.min_std)
            enough_history = stat.count >= self.min_history

            z_score = 0.0
            is_anomaly = False

            if enough_history:
                z_score = abs(float(value) - stat.mean) / current_std
                is_anomaly = z_score > self.threshold_k

                feature_scores[feature] = {
                    "value": float(value),
                    "mean": round(stat.mean, 4),
                    "std": round(current_std, 4),
                    "z_score": round(z_score, 4),
                    "is_anomaly": is_anomaly,
                    "history_count": stat.count,
                }

                if is_anomaly:
                    triggered_features.append(feature)
            else:
                feature_scores[feature] = {
                    "value": float(value),
                    "mean": round(stat.mean, 4),
                    "std": round(current_std, 4),
                    "z_score": 0.0,
                    "is_anomaly": False,
                    "history_count": stat.count,
                    "warming_up": True,
                }

            # update after evaluation
            stat.update(float(value))

        max_z = 0.0
        for details in feature_scores.values():
            score = details.get("z_score", 0.0)
            if score > max_z:
                max_z = score

        anomaly_detected = len(triggered_features) > 0

        return {
            "detector_type": "adaptive_threshold",
            "namespace": namespace,
            "pod_name": pod_name,
            "window_start": vector.get("window_start"),
            "window_end": vector.get("window_end"),
            "ts": vector.get("window_end"),
            "anomaly_detected": anomaly_detected,
            "triggered_features": triggered_features,
            "max_z_score": round(max_z, 4),
            "threshold_k": self.threshold_k,
            "feature_scores": feature_scores,
            "source_vector": vector,
        }