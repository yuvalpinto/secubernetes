import asyncio
from datetime import datetime, timezone

from backend.utils.db import get_db
from backend.models.event_execve import ExecveEvent
from backend.models.event_openat import OpenAtEvent
from backend.models.event_connect import ConnectEvent


async def main():
    db = get_db()
    col = db.events_raw

    now = datetime.now(timezone.utc)

    events = [
        ExecveEvent(
            ts=now,
            pid=1234,
            uid=0,
            comm="bash",
            namespace="default",
            pod="nginx-7c9d6f",
            container="nginx",
            filename="/bin/bash",
            argv=["bash", "-c", "cat /etc/shadow"],
        ),
        OpenAtEvent(
            ts=now,
            pid=1234,
            uid=0,
            comm="bash",
            namespace="default",
            pod="nginx-7c9d6f",
            container="nginx",
            path="/etc/shadow",
            flags=0,
        ),
        ConnectEvent(
            ts=now,
            pid=1234,
            uid=0,
            comm="curl",
            namespace="default",
            pod="nginx-7c9d6f",
            container="nginx",
            dst_ip="1.2.3.4",
            dst_port=4444,
            protocol="tcp",
        ),
    ]

    docs = [e.model_dump() for e in events]

    res = await col.insert_many(docs)
    print(f"✅ inserted {len(res.inserted_ids)} events into events_raw")
    print("First id:", res.inserted_ids[0])


if __name__ == "__main__":
    asyncio.run(main())
