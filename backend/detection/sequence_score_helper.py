from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend.utils.alerts_repo import get_alerts_for_pod_in_window


class SequenceScoreHelper:
    """
    Compute sequence score for a feature window based on alerts
    belonging to the same pod in the same time window.
    """

    async def compute_for_vector(self, vector: Dict[str, Any]) -> Dict[str, Any]:
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

        alerts = await get_alerts_for_pod_in_window(
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