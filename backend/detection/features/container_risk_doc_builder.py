from backend.detection.scoring.severity import severity_from_container_risk


class ContainerRiskDocBuilder:
    """
    Builds the MongoDB document for collection:
        container_risk_scores
    """

    def build(
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
            "severity": severity_from_container_risk(final_risk_score),

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