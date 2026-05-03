from abc import ABC, abstractmethod


class DetectionRule(ABC):
    """
    Base class for online detection rules.

    This is the Strategy Pattern:
    every concrete rule knows which event type it supports and how to detect alerts.
    """

    def __init__(self, alert_factory):
        self.alert_factory = alert_factory

    @abstractmethod
    def supports(self, event: dict) -> bool:
        pass

    @abstractmethod
    def detect(self, event: dict, context) -> list[dict]:
        pass