from backend.detection.online.rules.base_rule import DetectionRule


class ConnectRule(DetectionRule):
    def supports(self, event: dict) -> bool:
        if event.get("event_type") != "connect":
            return False

        family = event.get("family")
        ip = event.get("ip")
        port = event.get("port")

        if family not in (2, 10):  # AF_INET / AF_INET6
            return False

        if not ip or not port:
            return False

        return True


class SensitiveAccessThenConnectRule(ConnectRule):
    def detect(self, event: dict, context) -> list[dict]:
        matched_open = context.find_matching_sensitive_open(event)

        if not matched_open:
            return []

        now_ts = event.get("arrival_ts")
        time_delta = round(now_ts - matched_open["arrival_ts"], 3)

        ip = event.get("ip")
        port = event.get("port")
        success = event.get("success")

        return [
            self.alert_factory.create(
                event=event,
                alert_type="sensitive_access_then_connect",
                severity="high" if success else "medium",
                details={
                    "destination": f"{ip}:{port}",
                    "destination_ip": ip,
                    "destination_port": port,
                    "family": event.get("family"),
                    "comm": event.get("comm"),
                    "uid": event.get("uid"),
                    "connect_success": success,
                    "connect_ret": event.get("ret"),
                    "correlation_window_seconds": context.correlation_window_seconds,
                    "time_since_sensitive_open_seconds": time_delta,
                    "triggering_open": {
                        "pid": matched_open.get("pid"),
                        "process_key": matched_open.get("process_key"),
                        "comm": matched_open.get("comm"),
                        "filename": matched_open.get("filename"),
                        "uid": matched_open.get("uid"),
                        "container_id": matched_open.get("container_id"),
                        "matched_rule": matched_open.get("matched_rule"),
                    },
                },
            )
        ]


class RootSensitiveAccessThenConnectRule(ConnectRule):
    def detect(self, event: dict, context) -> list[dict]:
        uid = event.get("uid")

        if uid != 0:
            return []

        matched_open = context.find_matching_sensitive_open(event)

        if not matched_open:
            return []

        now_ts = event.get("arrival_ts")
        time_delta = round(now_ts - matched_open["arrival_ts"], 3)

        ip = event.get("ip")
        port = event.get("port")
        success = event.get("success")

        return [
            self.alert_factory.create(
                event=event,
                alert_type="root_sensitive_access_then_connect",
                severity="critical" if success else "high",
                details={
                    "destination": f"{ip}:{port}",
                    "destination_ip": ip,
                    "destination_port": port,
                    "family": event.get("family"),
                    "comm": event.get("comm"),
                    "uid": uid,
                    "connect_success": success,
                    "connect_ret": event.get("ret"),
                    "correlation_window_seconds": context.correlation_window_seconds,
                    "time_since_sensitive_open_seconds": time_delta,
                    "triggering_open": {
                        "pid": matched_open.get("pid"),
                        "process_key": matched_open.get("process_key"),
                        "comm": matched_open.get("comm"),
                        "filename": matched_open.get("filename"),
                        "uid": matched_open.get("uid"),
                        "container_id": matched_open.get("container_id"),
                        "matched_rule": matched_open.get("matched_rule"),
                    },
                },
            )
        ]


class ShellThenConnectRule(ConnectRule):
    def detect(self, event: dict, context) -> list[dict]:
        if not context.event_is_shell_related(event):
            return []

        ip = event.get("ip")
        port = event.get("port")
        uid = event.get("uid")

        return [
            self.alert_factory.create(
                event=event,
                alert_type="shell_then_connect",
                severity="high" if uid == 0 else "medium",
                details={
                    "destination": f"{ip}:{port}",
                    "destination_ip": ip,
                    "destination_port": port,
                    "family": event.get("family"),
                    "comm": event.get("comm"),
                    "uid": uid,
                    "connect_success": event.get("success"),
                    "connect_ret": event.get("ret"),
                    "lineage_summary": (event.get("lineage") or {}).get("summary"),
                },
            )
        ]


class FullAttackChainRule(ConnectRule):
    """
    Detects:
        execve -> sensitive openat -> successful connect
    """

    def detect(self, event: dict, context) -> list[dict]:
        success = event.get("success")

        if success is not True:
            return []

        matched_exec = context.find_matching_exec(event)
        matched_open = context.find_matching_sensitive_open(event)

        if not matched_exec or not matched_open:
            return []

        return [
            self.alert_factory.create_attack_chain_alert(
                connect_event=event,
                matched_open=matched_open,
                matched_exec=matched_exec,
                correlation_window_seconds=context.correlation_window_seconds,
            )
        ]