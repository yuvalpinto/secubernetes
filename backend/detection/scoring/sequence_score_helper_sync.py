from __future__ import annotations

from typing import Any, Dict

from backend.utils.alerts_repo_sync import get_alerts_for_pod_in_window_sync


class SequenceScoreHelperSync:
    """
    Sync helper for computing sequence score from alerts in the same
    pod/time window.
    """

    def compute_for_vector(self, vector: Dict[str, Any]) -> Dict[str, Any]:
        namespace = vector.get("namespace")
        pod_name = vector.get("pod_name")
        window_start = vector.get("window_start")
        window_end = vector.get("window_end")

        if not namespace or not pod_name or not window_start or not window_end:
            return {
                "sequence_score": 0.0,
                "alerts_count": 0,
                "max_alert": None,
                "alerts": [],
            }

        alerts = get_alerts_for_pod_in_window_sync(
            namespace=namespace,
            pod_name=pod_name,
            window_start=window_start,
            window_end=window_end,
        )

        if not alerts:
            return {
                "sequence_score": 0.0,
                "alerts_count": 0,
                "max_alert": None,
                "alerts": [],
            }

        max_alert = max(alerts, key=lambda a: float(a.get("risk_score", 0.0)))
        sequence_score = float(max_alert.get("risk_score", 0.0))

        return {
            "sequence_score": sequence_score,
            "alerts_count": len(alerts),
            "max_alert": {
                "alert_type": max_alert.get("alert_type"),
                "risk_score": max_alert.get("risk_score"),
                "severity": max_alert.get("severity"),
                "derived_severity": max_alert.get("derived_severity"),
                "ts": max_alert.get("ts"),
            },
            "alerts": alerts,
        }