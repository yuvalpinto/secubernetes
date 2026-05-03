import ipaddress

from backend.detection.scoring.severity import severity_from_alert_score


class AlertRiskScorer:
    """
    Calculates risk score for a single online alert.

    This scorer is used by AlertFactory.
    It is separate from the container/window risk combiner used by FeatureWorker.
    """

    ALERT_POINTS = {
        "sensitive_file_open": 12,
        "sensitive_path_open": 12,
        "credential_related_file_open": 18,
        "exec_sensitive_followup": 18,
        "sensitive_access_after_shell": 15,
        "sensitive_access_then_connect": 20,
        "root_sensitive_access_then_connect": 24,
        "sensitive_access_and_exfiltration_chain": 30,
        "shell_then_connect": 12,
        "root_exec_detected": 8,
        "burst_exec_activity": 8,
        "rare_command_window": 8,
        "shell_under_unusual_parent": 18,
        "root_open_user_home": 10,
    }

    SHELL_NAMES = {
        "sh",
        "bash",
        "dash",
        "ash",
    }

    SENSITIVE_TOKENS = (
        "id_rsa",
        "id_ed25519",
        ".kube/config",
        "token",
    )

    CONNECT_CHAIN_ALERTS = {
        "sensitive_access_then_connect",
        "root_sensitive_access_then_connect",
        "sensitive_access_and_exfiltration_chain",
        "shell_then_connect",
    }

    def calculate(
        self,
        event: dict,
        alert_type: str,
        details: dict,
    ) -> tuple[int, list[dict]]:
        score = 0
        factors: list[dict] = []

        def add(points: int, reason: str) -> None:
            nonlocal score
            score += points
            factors.append({
                "reason": reason,
                "points": points,
            })

        uid = event.get("uid")
        filename = event.get("filename") or ""
        resolver_status = event.get("resolver_status")
        success = details.get("connect_success", event.get("success"))

        triggering_open = details.get("triggering_open") or {}
        triggering_exec = details.get("triggering_exec") or {}

        open_filename = triggering_open.get("filename") or filename
        exec_comm = (triggering_exec.get("comm") or "").lower()
        event_comm = (event.get("comm") or "").lower()

        dest_ip = details.get("destination_ip") or event.get("ip")
        dest_port = details.get("destination_port") or event.get("port")

        # Network destination context
        if dest_ip and dest_port:
            network_points, network_reason = self._network_destination_score(dest_ip, dest_port)
            if network_reason:
                add(network_points, network_reason)

        # Base context
        if uid == 0:
            add(10, "running_as_root")

        if resolver_status == "resolved":
            add(3, "container_context_resolved")

        if success is True:
            add(25, "successful_network_connection")
        elif success is False:
            add(-15, "failed_network_connection")

        if event_comm in self.SHELL_NAMES or exec_comm in self.SHELL_NAMES:
            add(10, "shell_related_activity")

        # Sensitive targets
        if open_filename == "/etc/passwd":
            add(12, "access_to_etc_passwd")

        if open_filename == "/etc/shadow":
            add(22, "access_to_etc_shadow")

        if open_filename == "/etc/sudoers":
            add(18, "access_to_etc_sudoers")

        if "/var/run/secrets/kubernetes.io/serviceaccount" in open_filename:
            add(20, "access_to_kubernetes_serviceaccount_secret")

        if any(token in open_filename for token in self.SENSITIVE_TOKENS):
            add(18, "credential_related_target")

        # Alert type weighting
        if alert_type in self.ALERT_POINTS:
            add(self.ALERT_POINTS[alert_type], f"alert_type:{alert_type}")

        # Correlation strength
        has_triggering_exec = bool(triggering_exec)
        has_triggering_open = bool(triggering_open)

        if has_triggering_exec:
            add(8, "has_triggering_exec_context")

        if has_triggering_open:
            add(8, "has_triggering_open_context")

        if has_triggering_exec and has_triggering_open:
            add(8, "multi_step_correlated_sequence")

        # Time proximity
        exec_delta = details.get("time_since_exec_seconds")
        open_delta = details.get("time_since_sensitive_open_seconds")

        if isinstance(exec_delta, (int, float)) and exec_delta <= 2:
            add(4, "very_short_time_since_exec")

        if isinstance(open_delta, (int, float)) and open_delta <= 2:
            add(4, "very_short_time_since_sensitive_open")

        final_score = max(0, min(score, 100))
        return final_score, factors

    def derive_final_severity(
        self,
        event: dict,
        alert_type: str,
        details: dict,
        score: int,
    ) -> str:
        severity = severity_from_alert_score(score)
        success = details.get("connect_success", event.get("success"))

        if alert_type in self.CONNECT_CHAIN_ALERTS and success is not True and severity == "critical":
            return "high"

        return severity

    def _network_destination_score(
        self,
        ip: str | None,
        port: int | None,
    ) -> tuple[int, str | None]:
        if not ip:
            return 0, None

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return 0, None

        try:
            normalized_port = int(port) if port is not None else None
        except (TypeError, ValueError):
            normalized_port = None

        if ip_obj.is_private:
            if normalized_port == 53:
                return -15, "internal_dns_destination"

            return 0, "private_internal_destination"

        if not ip_obj.is_private:
            if normalized_port in {80, 443}:
                return 10, "external_web_destination"

            return 15, "external_public_destination"

        return 0, None