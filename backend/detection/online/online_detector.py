from backend.detection.online.alert_factory import AlertFactory
from backend.detection.online.detection_context import DetectionContext

from backend.detection.online.rules.base_rule import DetectionRule
from backend.detection.online.rules.execve_rules import (
    BurstExecActivityRule,
    RootExecDetectedRule,
    RareCommandWindowRule,
    ShellUnderUnusualParentRule,
)
from backend.detection.online.rules.openat_rules import (
    SensitiveFileOpenRule,
    SensitivePathOpenRule,
    RootOpenUserHomeRule,
    CredentialRelatedFileOpenRule,
    ExecSensitiveFollowupRule,
    SensitiveAccessAfterShellRule,
)
from backend.detection.online.rules.connect_rules import (
    SensitiveAccessThenConnectRule,
    RootSensitiveAccessThenConnectRule,
    ShellThenConnectRule,
    FullAttackChainRule,
)


class OnlineDetector:
    """
    Coordinates all online detection rules.

    The detector itself does not contain detection logic.
    Each detection strategy lives in a dedicated DetectionRule class.
    """

    def __init__(
        self,
        context: DetectionContext,
        rules: list[DetectionRule],
    ):
        self.context = context
        self.rules = rules

    @classmethod
    def create_default(
        cls,
        context: DetectionContext,
        burst_threshold: int = 8,
    ) -> "OnlineDetector":
        alert_factory = AlertFactory()

        rules: list[DetectionRule] = [
            # execve
            BurstExecActivityRule(alert_factory, burst_threshold=burst_threshold),
            RootExecDetectedRule(alert_factory),
            RareCommandWindowRule(alert_factory),
            ShellUnderUnusualParentRule(alert_factory),

            # openat
            SensitiveFileOpenRule(alert_factory),
            SensitivePathOpenRule(alert_factory),
            RootOpenUserHomeRule(alert_factory),
            CredentialRelatedFileOpenRule(alert_factory),
            ExecSensitiveFollowupRule(alert_factory),
            SensitiveAccessAfterShellRule(alert_factory),

            # connect
            SensitiveAccessThenConnectRule(alert_factory),
            RootSensitiveAccessThenConnectRule(alert_factory),
            ShellThenConnectRule(alert_factory),
            FullAttackChainRule(alert_factory),
        ]

        return cls(
            context=context,
            rules=rules,
        )

    def detect(self, event: dict) -> list[dict]:
        self.context.ingest_event(event)

        alerts: list[dict] = []

        for rule in self.rules:
            if not rule.supports(event):
                continue

            produced_alerts = rule.detect(event, self.context)
            if produced_alerts:
                alerts.extend(produced_alerts)

        return alerts