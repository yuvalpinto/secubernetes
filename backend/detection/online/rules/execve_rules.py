from backend.detection.online.rules.base_rule import DetectionRule


class ExecveRule(DetectionRule):
    def supports(self, event: dict) -> bool:
        return event.get("event_type") == "execve"


class BurstExecActivityRule(ExecveRule):
    def __init__(self, alert_factory, burst_threshold: int = 8):
        super().__init__(alert_factory)
        self.burst_threshold = burst_threshold

    def detect(self, event: dict, context) -> list[dict]:
        online_meta = event.get("_online", {})
        total_execs = online_meta.get("exec_window_count", 0)

        if total_execs < self.burst_threshold:
            return []

        return [
            self.alert_factory.create(
                event=event,
                alert_type="burst_exec_activity",
                severity="medium",
                details={
                    "window_seconds": context.window_seconds,
                    "exec_count": total_execs,
                    "threshold": self.burst_threshold,
                },
            )
        ]


class RootExecDetectedRule(ExecveRule):
    SAFE_ROOT_PAIRS = {
        ("kube-proxy", "/usr/sbin/iptables"),
        ("kube-proxy", "/usr/sbin/ip6tables"),
        ("kubelet", "/usr/sbin/iptables"),
        ("kubelet", "/usr/sbin/ip6tables"),
    }

    def detect(self, event: dict, context) -> list[dict]:
        uid = event.get("uid")
        pair = (event.get("comm"), event.get("filename"))

        if uid != 0:
            return []

        if pair in self.SAFE_ROOT_PAIRS:
            return []

        return [
            self.alert_factory.create(
                event=event,
                alert_type="root_exec_detected",
                severity="low",
                details={
                    "uid": uid,
                    "filename": event.get("filename"),
                    "comm": event.get("comm"),
                },
            )
        ]


class RareCommandWindowRule(ExecveRule):
    COMMON_WHITELIST = {
        "/usr/bin/whoami",
        "/usr/bin/env",
        "/bin/ls",
        "/bin/sh",
        "/bin/bash",
        "/usr/sbin/iptables",
        "/usr/sbin/ip6tables",
    }

    def detect(self, event: dict, context) -> list[dict]:
        online_meta = event.get("_online", {})

        key = online_meta.get("command_key") or event.get("filename") or event.get("comm") or "unknown"
        command_count = online_meta.get("command_count_in_window", 0)

        if command_count != 1:
            return []

        if key in self.COMMON_WHITELIST:
            return []

        return [
            self.alert_factory.create(
                event=event,
                alert_type="rare_command_window",
                severity="medium",
                details={
                    "command": key,
                    "count_in_window": command_count,
                    "window_seconds": context.window_seconds,
                },
            )
        ]


class ShellUnderUnusualParentRule(ExecveRule):
    SHELL_NAMES = {"sh", "bash", "dash", "ash"}
    SUSPICIOUS_PARENTS = {"python", "python3", "node", "java", "nginx"}

    def detect(self, event: dict, context) -> list[dict]:
        comm = (event.get("comm") or "").lower()
        parent_comm = (context.last_ancestor_comm(event) or "").lower()

        if comm not in self.SHELL_NAMES:
            return []

        if parent_comm not in self.SUSPICIOUS_PARENTS:
            return []

        return [
            self.alert_factory.create(
                event=event,
                alert_type="shell_under_unusual_parent",
                severity="high",
                details={
                    "comm": event.get("comm"),
                    "parent_comm": parent_comm,
                    "lineage_summary": (event.get("lineage") or {}).get("summary"),
                },
            )
        ]