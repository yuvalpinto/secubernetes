import asyncio
from backend.utils.db import get_db

ALERTS_COLLECTION = "alerts"


async def init_alert_indexes():
    db = get_db()
    collection = db[ALERTS_COLLECTION]

    await collection.create_index("ts")
    await collection.create_index("alert_type")
    await collection.create_index("severity")
    await collection.create_index("event_type")
    await collection.create_index("source_event.pid")
    await collection.create_index("source_event.uid")
    await collection.create_index("source_event.comm")
    await collection.create_index("source_event.filename")
    await collection.create_index([
        ("alert_type", 1),
        ("severity", 1),
        ("ts", -1),
    ])

    print("Alert indexes created successfully.")


if __name__ == "__main__":
    asyncio.run(init_alert_indexes())