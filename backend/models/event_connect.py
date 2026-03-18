from backend.models.event_base import EventBase

class ConnectEvent(EventBase):
    event_type: str = "connect"
    dst_ip: str
    dst_port: int
    protocol: str  # tcp / udp
