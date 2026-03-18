import asyncio
from backend.utils.db import get_db

async def main():
    db = get_db()
    col = db.events_raw

    await col.create_index("ts")
    await col.create_index("event_type")
    await col.create_index(
        [("namespace", 1), ("pod", 1), ("container", 1)]
    )
    await col.create_index("pid")

    print("indexes created for events_raw")

if __name__ == "__main__":
    asyncio.run(main())
