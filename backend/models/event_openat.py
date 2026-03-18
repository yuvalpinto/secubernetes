from backend.models.event_base import EventBase

class OpenAtEvent(EventBase):
    event_type: str = "openat"
    path: str
    flags: int
