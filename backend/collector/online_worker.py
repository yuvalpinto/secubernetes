import asyncio
import queue
import threading
import time
from collections import Counter, deque
from datetime import datetime
import ipaddress

from backend.utils.alerts_repo_sync import insert_alerts_sync


class OnlineWorker(threading.Thread):
    def __init__(
        self,
        online_queue: queue.Queue,
        window_seconds: int = 30,
        burst_threshold: int = 8,
        correlation_window_seconds: int = 10,
    ):
        super().__init__(daemon=True)
        self.online_queue = online_queue
        self.window_seconds = window_seconds
        self.burst_threshold = burst_threshold
        self.correlation_window_seconds = correlation_window_seconds
        self._running = True

        self.events_window = deque()
        self.command_counter = Counter()

        self.recent_execs = deque()
        self.recent_sensitive_opens = deque()

    def stop(self):
        self._running = False

    def _cleanup_old_events(self, now_ts: float):
        while self.events_window and (now_ts - self.events_window[0]["arrival_ts"]) > self.window_seconds:
            old_event = self.events_window.popleft()
            key = old_event.get("filename") or old_event.get("comm") or "unknown"
            self.command_counter[key] -= 1
            if self.command_counter[key] <= 0:
                del self.command_counter[key]

    def _cleanup_old_execs(self, now_ts: float):
        while self.recent_execs and (now_ts - self.recent_execs[0]["arrival_ts"]) > self.correlation_window_seconds:
            self.recent_execs.popleft()

    def _cleanup_old_sensitive_opens(self, now_ts: float):
        while (
            self.recent_sensitive_opens
            and (now_ts - self.recent_sensitive_opens[0]["arrival_ts"]) > self.correlation_window_seconds
        ):
            self.recent_sensitive_opens.popleft()

    def _base_alert(self, event: dict, alert_type: str, severity: str, details: dict):
        lineage = event.get("lineage") or {}
        lineage_summary = lineage.get("summary")

        risk_score, risk_factors = self._calculate_risk_score(
            event=event,
            alert_type=alert_type,
            details=details,
        )

        derived_severity = self._derive_final_severity(
            event=event,
            alert_type=alert_type,
            details=details,
            score=risk_score,
        )

        return {
            "ts": datetime.utcnow(),
            "event_type": event.get("event_type"),
            "alert_type": alert_type,

            # בינתיים נשמור גם את הישן וגם את המחושב
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
    def _is_sensitive_openat_target(self, filename: str) -> tuple[bool, str | None]:
        sensitive_exact = {
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/root/.ssh/authorized_keys",
        }

        sensitive_prefixes = [
            "/root/",
            "/var/run/secrets/kubernetes.io/serviceaccount",
            "/etc/kubernetes/",
            "/etc/ssl/private/",
        ]

        suspicious_names = {
            "id_rsa",
            "id_ed25519",
            ".kube/config",
            "token",
        }

        if filename in sensitive_exact:
            return True, f"exact:{filename}"

        for prefix in sensitive_prefixes:
            if filename.startswith(prefix):
                return True, f"prefix:{prefix}"

        for token in suspicious_names:
            if token in filename:
                return True, f"token:{token}"

        return False, None

    def _lineage_summary(self, event: dict) -> str:
        return ((event.get("lineage") or {}).get("summary") or "").lower()


    def _lineage_ancestors(self, event: dict) -> list[dict]:
        return ((event.get("lineage") or {}).get("ancestors") or [])

    def _lineage_contains_shell(self, event: dict) -> bool:
        summary = self._lineage_summary(event)
        shell_tokens = ("sh", "bash", "dash", "ash")
        return any(token in summary for token in shell_tokens)

    def _last_ancestor_comm(self, event: dict) -> str | None:
        ancestors = self._lineage_ancestors(event)
        if not ancestors:
            return None
        return ancestors[-1].get("comm")
    def _event_is_shell_related(self, event: dict) -> bool:
        comm = (event.get("comm") or "").lower()
        shell_names = {"sh", "bash", "dash", "ash"}

        if comm in shell_names:
            return True

        return self._lineage_contains_shell(event)
        

    def _network_destination_score(self, ip: str | None, port: int | None) -> tuple[int, str | None]:
        if not ip:
            return 0, None

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return 0, None

        # Internal/private traffic
        if ip_obj.is_private:
            if port == 53:
                return -15, "internal_dns_destination"
            return 0, "private_internal_destination"

        # External/public traffic
        if not ip_obj.is_private:
            if port in {80, 443}:
                return 10, "external_web_destination"
            return 15, "external_public_destination"

        return 0, None

    def _same_execution_context(self, older_event: dict, event: dict) -> bool:
        older_process_key = older_event.get("process_key")
        current_process_key = event.get("process_key")
        current_parent_process_key = event.get("parent_process_key")

        if older_process_key and current_process_key and older_process_key == current_process_key:
            return True

        if older_process_key and current_parent_process_key and older_process_key == current_parent_process_key:
            return True

        if older_event.get("pid") == event.get("pid"):
            return True

        # fallback: same container + same uid
        if (
            older_event.get("container_id")
            and event.get("container_id")
            and older_event.get("container_id") == event.get("container_id")
            and older_event.get("uid") == event.get("uid")
        ):
            return True

        return False
    def _find_matching_exec(self, event: dict):
        for exec_event in reversed(self.recent_execs):
            if self._same_execution_context(exec_event, event):
                return exec_event
        return None
    def _severity_from_score(self, score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"
    def _derive_final_severity(self, event: dict, alert_type: str, details: dict, score: int) -> str:
        severity = self._severity_from_score(score)
        success = details.get("connect_success", event.get("success"))

        connect_chain_alerts = {
            "sensitive_access_then_connect",
            "root_sensitive_access_then_connect",
            "sensitive_access_and_exfiltration_chain",
            "shell_then_connect",
        }

        if alert_type in connect_chain_alerts and success is not True and severity == "critical":
            return "high"

        return severity

    def _calculate_risk_score(self, event: dict, alert_type: str, details: dict) -> tuple[int, list[dict]]:
        score = 0
        factors = []

        def add(points: int, reason: str):
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

        shell_names = {"sh", "bash", "dash", "ash"}

        # network destination context
        if dest_ip and dest_port:
            network_points, network_reason = self._network_destination_score(dest_ip, dest_port)
            if network_reason:
                add(network_points, network_reason)

        # base context
        if uid == 0:
            add(10, "running_as_root")

        if resolver_status == "resolved":
            add(3, "container_context_resolved")

        if success is True:
            add(25, "successful_network_connection")
        elif success is False:
            add(-15, "failed_network_connection")

        if event_comm in shell_names or exec_comm in shell_names:
            add(10, "shell_related_activity")

        # sensitive targets
        if open_filename == "/etc/passwd":
            add(12, "access_to_etc_passwd")

        if open_filename == "/etc/shadow":
            add(22, "access_to_etc_shadow")

        if open_filename == "/etc/sudoers":
            add(18, "access_to_etc_sudoers")

        if "/var/run/secrets/kubernetes.io/serviceaccount" in open_filename:
            add(20, "access_to_kubernetes_serviceaccount_secret")

        sensitive_tokens = ("id_rsa", "id_ed25519", ".kube/config", "token")
        if any(token in open_filename for token in sensitive_tokens):
            add(18, "credential_related_target")

        # alert type weighting
        alert_points = {
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

        if alert_type in alert_points:
            add(alert_points[alert_type], f"alert_type:{alert_type}")

        # correlation strength
        has_triggering_exec = bool(triggering_exec)
        has_triggering_open = bool(triggering_open)

        if has_triggering_exec:
            add(8, "has_triggering_exec_context")

        if has_triggering_open:
            add(8, "has_triggering_open_context")

        if has_triggering_exec and has_triggering_open:
            add(8, "multi_step_correlated_sequence")

        # time proximity
        exec_delta = details.get("time_since_exec_seconds")
        open_delta = details.get("time_since_sensitive_open_seconds")

        if isinstance(exec_delta, (int, float)) and exec_delta <= 2:
            add(4, "very_short_time_since_exec")

        if isinstance(open_delta, (int, float)) and open_delta <= 2:
            add(4, "very_short_time_since_sensitive_open")

        final_score = max(0, min(score, 100))
        return final_score, factors
    def _build_attack_chain_alert(
        self,
        connect_event: dict,
        matched_open: dict,
        matched_exec: dict,
    ):
        now_ts = time.time()

        exec_delta = round(now_ts - matched_exec["arrival_ts"], 3)
        open_delta = round(now_ts - matched_open["arrival_ts"], 3)

        ip = connect_event.get("ip")
        port = connect_event.get("port")
        family = connect_event.get("family")
        comm = connect_event.get("comm")
        uid = connect_event.get("uid")
        success = connect_event.get("success")
        ret = connect_event.get("ret")

        return self._base_alert(
            connect_event,
            "sensitive_access_and_exfiltration_chain",
            "critical",
            {
                "destination": f"{ip}:{port}",
                "destination_ip": ip,
                "destination_port": port,
                "family": family,
                "comm": comm,
                "uid": uid,
                "connect_success": success,
                "connect_ret": ret,
                "correlation_window_seconds": self.correlation_window_seconds,
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

    def _detect_execve(self, event: dict):
        now_ts = time.time()
        event["arrival_ts"] = now_ts

        self.events_window.append(event)

        key = event.get("filename") or event.get("comm") or "unknown"
        self.command_counter[key] += 1

        self._cleanup_old_events(now_ts)

        self.recent_execs.append({
            "pid": event.get("pid"),
            "process_key": event.get("process_key"),
            "parent_process_key": event.get("parent_process_key"),
            "comm": event.get("comm"),
            "filename": event.get("filename"),
            "uid": event.get("uid"),
            "container_id": event.get("container_id"),
            "arrival_ts": now_ts,
        })
        self._cleanup_old_execs(now_ts)

        total_execs = len(self.events_window)
        command_count = self.command_counter[key]
        uid = event.get("uid")

        alerts = []

        if total_execs >= self.burst_threshold:
            alerts.append(self._base_alert(
                event,
                "burst_exec_activity",
                "medium",
                {
                    "window_seconds": self.window_seconds,
                    "exec_count": total_execs,
                    "threshold": self.burst_threshold,
                }
            ))

        safe_root_pairs = {
            ("kube-proxy", "/usr/sbin/iptables"),
            ("kube-proxy", "/usr/sbin/ip6tables"),
            ("kubelet", "/usr/sbin/iptables"),
            ("kubelet", "/usr/sbin/ip6tables"),
        }

        pair = (event.get("comm"), event.get("filename"))
        if uid == 0 and pair not in safe_root_pairs:
            alerts.append(self._base_alert(
                event,
                "root_exec_detected",
                "low",
                {
                    "uid": uid,
                    "filename": event.get("filename"),
                    "comm": event.get("comm"),
                }
            ))

        common_whitelist = {
            "/usr/bin/whoami",
            "/usr/bin/env",
            "/bin/ls",
            "/bin/sh",
            "/bin/bash",
            "/usr/sbin/iptables",
            "/usr/sbin/ip6tables",
        }

        if command_count == 1 and key not in common_whitelist:
            alerts.append(self._base_alert(
                event,
                "rare_command_window",
                "medium",
                {
                    "command": key,
                    "count_in_window": command_count,
                    "window_seconds": self.window_seconds,
                }
            ))

        comm = (event.get("comm") or "").lower()
        shell_names = {"sh", "bash", "dash", "ash"}
        parent_comm = (self._last_ancestor_comm(event) or "").lower()

        suspicious_parents = {"python", "python3", "node", "java", "nginx"}

        if comm in shell_names and parent_comm in suspicious_parents:
            alerts.append(self._base_alert(
                event,
                "shell_under_unusual_parent",
                "high",
                {
                    "comm": event.get("comm"),
                    "parent_comm": parent_comm,
                    "lineage_summary": (event.get("lineage") or {}).get("summary"),
                }
            ))

        return alerts

    def _detect_openat(self, event: dict):
        alerts = []

        now_ts = time.time()
        self._cleanup_old_execs(now_ts)
        self._cleanup_old_sensitive_opens(now_ts)

        filename = event.get("filename") or ""
        uid = event.get("uid")
        comm = event.get("comm")

        sensitive_exact = {
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/root/.ssh/authorized_keys",
        }

        sensitive_prefixes = [
            "/root/",
            "/var/run/secrets/kubernetes.io/serviceaccount",
            "/etc/kubernetes/",
            "/etc/ssl/private/",
        ]

        if filename in sensitive_exact:
            alerts.append(self._base_alert(
                event,
                "sensitive_file_open",
                "high" if filename == "/etc/shadow" else "medium",
                {
                    "filename": filename,
                    "comm": comm,
                    "uid": uid,
                }
            ))

        for prefix in sensitive_prefixes:
            if filename.startswith(prefix):
                alerts.append(self._base_alert(
                    event,
                    "sensitive_path_open",
                    "medium",
                    {
                        "filename": filename,
                        "matched_prefix": prefix,
                        "comm": comm,
                        "uid": uid,
                    }
                ))
                break

        if uid == 0 and filename.startswith("/home/"):
            alerts.append(self._base_alert(
                event,
                "root_open_user_home",
                "medium",
                {
                    "filename": filename,
                    "comm": comm,
                    "uid": uid,
                }
            ))

        suspicious_names = {
            "id_rsa",
            "id_ed25519",
            ".kube/config",
            "token",
        }

        for token in suspicious_names:
            if token in filename:
                alerts.append(self._base_alert(
                    event,
                    "credential_related_file_open",
                    "medium",
                    {
                        "filename": filename,
                        "matched_token": token,
                        "comm": comm,
                        "uid": uid,
                    }
                ))
                break

        is_sensitive, matched_rule = self._is_sensitive_openat_target(filename)

        if is_sensitive:
            self.recent_sensitive_opens.append({
                "pid": event.get("pid"),
                "process_key": event.get("process_key"),
                "parent_process_key": event.get("parent_process_key"),
                "comm": event.get("comm"),
                "filename": filename,
                "uid": event.get("uid"),
                "container_id": event.get("container_id"),
                "arrival_ts": now_ts,
                "matched_rule": matched_rule,
            })

        if is_sensitive:
            for exec_event in reversed(self.recent_execs):
                if not self._same_execution_context(exec_event, event):
                    continue

                time_delta = round(now_ts - exec_event["arrival_ts"], 3)

                alerts.append(self._base_alert(
                    event,
                    "exec_sensitive_followup",
                    "high",
                    {
                        "filename": filename,
                        "comm": comm,
                        "uid": uid,
                        "matched_rule": matched_rule,
                        "correlation_window_seconds": self.correlation_window_seconds,
                        "time_since_exec_seconds": time_delta,
                        "triggering_exec": {
                            "pid": exec_event.get("pid"),
                            "process_key": exec_event.get("process_key"),
                            "comm": exec_event.get("comm"),
                            "filename": exec_event.get("filename"),
                            "uid": exec_event.get("uid"),
                            "container_id": exec_event.get("container_id"),
                        },
                    }
                ))
                break

        if is_sensitive and self._lineage_contains_shell(event):
            alerts.append(self._base_alert(
                event,
                "sensitive_access_after_shell",
                "high",
                {
                    "filename": filename,
                    "comm": comm,
                    "uid": uid,
                    "matched_rule": matched_rule,
                    "lineage_summary": (event.get("lineage") or {}).get("summary"),
                }
            ))

        return alerts
    def _detect_connect(self, event: dict):
        alerts = []

        now_ts = time.time()
        self._cleanup_old_execs(now_ts)
        self._cleanup_old_sensitive_opens(now_ts)

        ip = event.get("ip")
        port = event.get("port")
        family = event.get("family")
        comm = event.get("comm")
        uid = event.get("uid")
        success = event.get("success")
        ret = event.get("ret")

        if family not in (2, 10):  # AF_INET / AF_INET6
            return alerts

        if not ip or not port:
            return alerts

        matched_open = None
        for open_event in reversed(self.recent_sensitive_opens):
            if self._same_execution_context(open_event, event):
                matched_open = open_event
                break

        matched_exec = self._find_matching_exec(event)

        if matched_open:
            time_delta = round(now_ts - matched_open["arrival_ts"], 3)

            alerts.append(self._base_alert(
                event,
                "sensitive_access_then_connect",
                "high" if success else "medium",
                {
                    "destination": f"{ip}:{port}",
                    "destination_ip": ip,
                    "destination_port": port,
                    "family": family,
                    "comm": comm,
                    "uid": uid,
                    "connect_success": success,
                    "connect_ret": ret,
                    "correlation_window_seconds": self.correlation_window_seconds,
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
                }
            ))

            if uid == 0:
                alerts.append(self._base_alert(
                    event,
                    "root_sensitive_access_then_connect",
                    "critical" if success else "high",
                    {
                        "destination": f"{ip}:{port}",
                        "destination_ip": ip,
                        "destination_port": port,
                        "family": family,
                        "comm": comm,
                        "uid": uid,
                        "connect_success": success,
                        "connect_ret": ret,
                        "correlation_window_seconds": self.correlation_window_seconds,
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
                    }
                ))

        if self._event_is_shell_related(event):
            alerts.append(self._base_alert(
                event,
                "shell_then_connect",
                "high" if uid == 0 else "medium",
                {
                    "destination": f"{ip}:{port}",
                    "destination_ip": ip,
                    "destination_port": port,
                    "family": family,
                    "comm": comm,
                    "uid": uid,
                    "connect_success": success,
                    "connect_ret": ret,
                    "lineage_summary": (event.get("lineage") or {}).get("summary"),
                }
            ))

        # full attack chain: execve -> sensitive open -> connect(success)
        if matched_exec and matched_open and success is True:
            alerts.append(
                self._build_attack_chain_alert(
                    connect_event=event,
                    matched_open=matched_open,
                    matched_exec=matched_exec,
                )
            )

        return alerts
    def _detect(self, event: dict):
        event_type = event.get("event_type")

        if event_type == "execve":
            return self._detect_execve(event)

        if event_type == "openat":
            return self._detect_openat(event)

        if event_type == "connect":
            return self._detect_connect(event)

        return []

    def _filter_alerts(self, alerts: list[dict]) -> list[dict]:
        filtered = []

        for alert in alerts:
            source_event = alert.get("source_event", {})
            comm = (source_event.get("comm") or "").lower()
            alert_type = alert.get("alert_type")

            if comm in {"kubelet", "containerd", "mongod"}:
                continue

            if alert_type == "root_exec_detected" and comm in {"kubelet", "kube-proxy"}:
                continue

            filtered.append(alert)

        return filtered

    def _deduplicate_alerts(self, alerts: list[dict]) -> list[dict]:
        seen = set()
        unique = []

        for alert in alerts:
            source_event = alert.get("source_event", {})
            details = alert.get("details", {})
            triggering_open = details.get("triggering_open", {})
            triggering_exec = details.get("triggering_exec", {})

            key = (
                alert.get("alert_type"),
                source_event.get("pid"),
                source_event.get("comm"),
                details.get("destination_ip"),
                details.get("destination_port"),
                triggering_open.get("filename"),
                triggering_exec.get("filename"),
            )

            if key in seen:
                continue

            seen.add(key)
            unique.append(alert)

        return unique

    TARGET_POD_NAME = "test-pod"

    def run(self):
        while self._running:
            try:
                event = self.online_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            

            pod_name = event.get("pod_name")
            if pod_name != self.TARGET_POD_NAME:
                continue

            alerts = self._detect(event)
            alerts = self._filter_alerts(alerts)
            alerts = self._deduplicate_alerts(alerts)

            if alerts:
                for alert in alerts:
                    print("[online-detector]", alert)

                try:
                    inserted = insert_alerts_sync(alerts)
                    print(f"[online-detector] inserted {inserted} alerts")
                except Exception as exc:
                    print(f"[online-detector] failed to persist alerts: {exc}")