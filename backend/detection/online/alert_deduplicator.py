class AlertDeduplicator:
    """
    Deduplicates alerts produced from the same source event and same correlation context.
    """

    def apply(self, alerts: list[dict]) -> list[dict]:
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