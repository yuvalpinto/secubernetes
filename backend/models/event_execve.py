from backend.models.event_base import EventBase

class ExecveEvent(EventBase):
    event_type: str = "execve"
    filename: str
    argv: list[str]
