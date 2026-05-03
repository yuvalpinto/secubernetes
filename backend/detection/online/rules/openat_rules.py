from backend.detection.online.rules.base_rule import DetectionRule
from backend.detection.online.sensitive_targets import (
    SENSITIVE_EXACT_PATHS,
    SENSITIVE_PREFIXES,
    SUSPICIOUS_FILENAME_TOKENS,
)


class OpenatRule(DetectionRule):
    def supports(self, event: dict) -> bool:
        return event.get("event_type") == "openat"


class SensitiveFileOpenRule(OpenatRule):
    def detect(self, event: dict, context) -> list[dict]:
        filename = event.get("filename") or ""

        if filename not in SENSITIVE_EXACT_PATHS:
            return []

        return [
            self.alert_factory.create(
                event=event,
                alert_type="sensitive_file_open",
                severity="high" if filename == "/etc/shadow" else "medium",
                details={
                    "filename": filename,
                    "comm": event.get("comm"),
                    "uid": event.get("uid"),
                },
            )
        ]


class SensitivePathOpenRule(OpenatRule):
    def detect(self, event: dict, context) -> list[dict]:
        filename = event.get("filename") or ""

        for prefix in SENSITIVE_PREFIXES:
            if filename.startswith(prefix):
                return [
                    self.alert_factory.create(
                        event=event,
                        alert_type="sensitive_path_open",
                        severity="medium",
                        details={
                            "filename": filename,
                            "matched_prefix": prefix,
                            "comm": event.get("comm"),
                            "uid": event.get("uid"),
                        },
                    )
                ]

        return []


class RootOpenUserHomeRule(OpenatRule):
    def detect(self, event: dict, context) -> list[dict]:
        filename = event.get("filename") or ""
        uid = event.get("uid")

        if uid != 0:
            return []

        if not filename.startswith("/home/"):
            return []

        return [
            self.alert_factory.create(
                event=event,
                alert_type="root_open_user_home",
                severity="medium",
                details={
                    "filename": filename,
                    "comm": event.get("comm"),
                    "uid": uid,
                },
            )
        ]


class CredentialRelatedFileOpenRule(OpenatRule):
    def detect(self, event: dict, context) -> list[dict]:
        filename = event.get("filename") or ""

        for token in SUSPICIOUS_FILENAME_TOKENS:
            if token in filename:
                return [
                    self.alert_factory.create(
                        event=event,
                        alert_type="credential_related_file_open",
                        severity="medium",
                        details={
                            "filename": filename,
                            "matched_token": token,
                            "comm": event.get("comm"),
                            "uid": event.get("uid"),
                        },
                    )
                ]

        return []


class ExecSensitiveFollowupRule(OpenatRule):
    def detect(self, event: dict, context) -> list[dict]:
        online_meta = event.get("_online", {})

        if not online_meta.get("is_sensitive_openat"):
            return []

        matched_rule = online_meta.get("matched_sensitive_rule")
        exec_event = context.find_matching_exec(event)

        if not exec_event:
            return []

        now_ts = online_meta.get("arrival_ts") or event.get("arrival_ts")
        time_delta = round(now_ts - exec_event["arrival_ts"], 3)

        filename = event.get("filename") or ""

        return [
            self.alert_factory.create(
                event=event,
                alert_type="exec_sensitive_followup",
                severity="high",
                details={
                    "filename": filename,
                    "comm": event.get("comm"),
                    "uid": event.get("uid"),
                    "matched_rule": matched_rule,
                    "correlation_window_seconds": context.correlation_window_seconds,
                    "time_since_exec_seconds": time_delta,
                    "triggering_exec": {
                        "pid": exec_event.get("pid"),
                        "process_key": exec_event.get("process_key"),
                        "comm": exec_event.get("comm"),
                        "filename": exec_event.get("filename"),
                        "uid": exec_event.get("uid"),
                        "container_id": exec_event.get("container_id"),
                    },
                },
            )
        ]


class SensitiveAccessAfterShellRule(OpenatRule):
    def detect(self, event: dict, context) -> list[dict]:
        online_meta = event.get("_online", {})

        if not online_meta.get("is_sensitive_openat"):
            return []

        if not context.lineage_contains_shell(event):
            return []

        filename = event.get("filename") or ""
        matched_rule = online_meta.get("matched_sensitive_rule")

        return [
            self.alert_factory.create(
                event=event,
                alert_type="sensitive_access_after_shell",
                severity="high",
                details={
                    "filename": filename,
                    "comm": event.get("comm"),
                    "uid": event.get("uid"),
                    "matched_rule": matched_rule,
                    "lineage_summary": (event.get("lineage") or {}).get("summary"),
                },
            )
        ]