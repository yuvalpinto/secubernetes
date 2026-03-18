import asyncio
from backend.utils.db import get_db

async def main():
    db = get_db()

    res = await db.events_raw.insert_one(
        {"type": "test", "msg": "db module works"}
    )
    doc = await db.events_raw.find_one({"_id": res.inserted_id})

    print("✅ inserted:", doc)

if __name__ == "__main__":
    asyncio.run(main())
