import time
from datetime import datetime

from backend.detection.scoring.alert_risk_scorer import AlertRiskScorer


class AlertFactory:
    """
    Responsible for creating alert documents in a consistent format.
    """

    def __init__(self, risk_scorer: AlertRiskScorer | None = None):
        self.risk_scorer = risk_scorer or AlertRiskScorer()

    def create(
        self,
        event: dict,
        alert_type: str,
        severity: str,
        details: dict,
    ) -> dict:
        lineage = event.get("lineage") or {}
        lineage_summary = lineage.get("summary")

        risk_score, risk_factors = self.risk_scorer.calculate(
            event=event,
            alert_type=alert_type,
            details=details,
        )

        derived_severity = self.risk_scorer.derive_final_severity(
            event=event,
            alert_type=alert_type,
            details=details,
            score=risk_score,
        )

        return {
            "ts": datetime.utcnow(),
            "event_type": event.get("event_type"),
            "alert_type": alert_type,

            "severity": severity,
            "derived_severity": derived_severity,
            "risk_score": risk_score,
            "risk_factors": risk_factors,

            "lineage_summary": lineage_summary,
            "details": details,

            "source_event": {
                "pid": event.get("pid"),
                "ppid": event.get("ppid"),
                "ppid_status": event.get("ppid_status"),
                "uid": event.get("uid"),
                "comm": event.get("comm"),
                "filename": event.get("filename"),

                "fd": event.get("fd"),
                "family": event.get("family"),
                "ip": event.get("ip"),
                "port": event.get("port"),
                "ip_version": event.get("ip_version"),
                "ret": event.get("ret"),
                "success": event.get("success"),

                "process_key": event.get("process_key"),
                "parent_process_key": event.get("parent_process_key"),

                "container_id": event.get("container_id"),
                "pod_uid": event.get("pod_uid"),
                "pod_name": event.get("pod_name"),
                "namespace": event.get("namespace"),
                "container_name": event.get("container_name"),
                "runtime": event.get("runtime"),
                "resolver_status": event.get("resolver_status"),

                "lineage": lineage,
                "source": event.get("source"),
            },
        }

    def create_attack_chain_alert(
        self,
        connect_event: dict,
        matched_open: dict,
        matched_exec: dict,
        correlation_window_seconds: int,
    ) -> dict:
        now_ts = connect_event.get("arrival_ts") or time.time()

        exec_delta = round(now_ts - matched_exec["arrival_ts"], 3)
        open_delta = round(now_ts - matched_open["arrival_ts"], 3)

        ip = connect_event.get("ip")
        port = connect_event.get("port")
        family = connect_event.get("family")
        comm = connect_event.get("comm")
        uid = connect_event.get("uid")
        success = connect_event.get("success")
        ret = connect_event.get("ret")

        return self.create(
            event=connect_event,
            alert_type="sensitive_access_and_exfiltration_chain",
            severity="critical",
            details={
                "destination": f"{ip}:{port}",
                "destination_ip": ip,
                "destination_port": port,
                "family": family,
                "comm": comm,
                "uid": uid,
                "connect_success": success,
                "connect_ret": ret,
                "correlation_window_seconds": correlation_window_seconds,
                "time_since_exec_seconds": exec_delta,
                "time_since_sensitive_open_seconds": open_delta,
                "triggering_exec": {
                    "pid": matched_exec.get("pid"),
                    "process_key": matched_exec.get("process_key"),
                    "comm": matched_exec.get("comm"),
                    "filename": matched_exec.get("filename"),
                    "uid": matched_exec.get("uid"),
                    "container_id": matched_exec.get("container_id"),
                },
                "triggering_open": {
                    "pid": matched_open.get("pid"),
                    "process_key": matched_open.get("process_key"),
                    "comm": matched_open.get("comm"),
                    "filename": matched_open.get("filename"),
                    "uid": matched_open.get("uid"),
                    "container_id": matched_open.get("container_id"),
                    "matched_rule": matched_open.get("matched_rule"),
                },
                "lineage_summary": (connect_event.get("lineage") or {}).get("summary"),
            },
        )