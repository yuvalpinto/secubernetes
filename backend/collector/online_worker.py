import asyncio
import queue
import threading
import time
from collections import Counter, deque
from datetime import datetime

from backend.utils.alerts_repo import insert_alerts


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

    def _base_alert(self, event: dict, alert_type: str, severity: str, details: dict):
        return {
            "ts": datetime.utcnow(),
            "event_type": event.get("event_type"),
            "alert_type": alert_type,
            "severity": severity,
            "details": details,
            "source_event": {
                "pid": event.get("pid"),
                "ppid": event.get("ppid"),
                "ppid_status": event.get("ppid_status"),
                "uid": event.get("uid"),
                "comm": event.get("comm"),
                "filename": event.get("filename"),
                "container_id": event.get("container_id"),
                "pod_uid": event.get("pod_uid"),
                "resolver_status": event.get("resolver_status"),
                "source": event.get("source"),
            },
        }

    def _is_sensitive_openat_target(self, filename: str) -> tuple[bool, str | None]:
        sensitive_exact = {
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

    def _detect_execve(self, event: dict):
        now_ts = time.time()
        event["arrival_ts"] = now_ts

        self.events_window.append(event)

        key = event.get("filename") or event.get("comm") or "unknown"
        self.command_counter[key] += 1

        self._cleanup_old_events(now_ts)

        self.recent_execs.append({
            "pid": event.get("pid"),
            "comm": event.get("comm"),
            "filename": event.get("filename"),
            "uid": event.get("uid"),
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

        return alerts

    def _detect_openat(self, event: dict):
        alerts = []

        now_ts = time.time()
        self._cleanup_old_execs(now_ts)

        filename = event.get("filename") or ""
        uid = event.get("uid")
        comm = event.get("comm")
        pid = event.get("pid")

        sensitive_exact = {
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
            for exec_event in reversed(self.recent_execs):
                if exec_event["pid"] != pid:
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
                            "pid": exec_event["pid"],
                            "comm": exec_event["comm"],
                            "filename": exec_event["filename"],
                            "uid": exec_event["uid"],
                        },
                    }
                ))
                break

        return alerts

    def _detect(self, event: dict):
        event_type = event.get("event_type")

        if event_type == "execve":
            return self._detect_execve(event)

        if event_type == "openat":
            return self._detect_openat(event)

        return []

    def run(self):
        asyncio.run(self._run_async())

    async def _run_async(self):
        while self._running:
            try:
                event = self.online_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            alerts = self._detect(event)

            if alerts:
                for alert in alerts:
                    print("[online-detector]", alert)

                await insert_alerts(alerts)