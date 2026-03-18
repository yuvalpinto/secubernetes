from datetime import datetime
from pydantic import BaseModel, Field

class EventBase(BaseModel):
    ts: datetime = Field(default_factory=datetime.utcnow)
    event_type: str

    pid: int
    uid: int
    comm: str  # command name

    namespace: str | None = None
    pod: str | None = None
    container: str | None = None
