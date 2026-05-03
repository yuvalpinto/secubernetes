class AlertFilter:
    """
    Removes noisy/system alerts that are not relevant for user-facing detection.
    """

    IGNORED_SYSTEM_COMMANDS = {
        "kubelet",
        "containerd",
        "mongod",
    }

    ROOT_EXEC_IGNORED_COMMANDS = {
        "kubelet",
        "kube-proxy",
    }

    def apply(self, alerts: list[dict]) -> list[dict]:
        filtered = []

        for alert in alerts:
            source_event = alert.get("source_event", {})
            comm = (source_event.get("comm") or "").lower()
            alert_type = alert.get("alert_type")

            if comm in self.IGNORED_SYSTEM_COMMANDS:
                continue

            if alert_type == "root_exec_detected" and comm in self.ROOT_EXEC_IGNORED_COMMANDS:
                continue

            filtered.append(alert)

        return filtered