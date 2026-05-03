import asyncio
from backend.utils.db import get_db

CONTAINER_RISK_SCORES_COLLECTION = "container_risk_scores"


async def init_container_risk_scores_indexes():
    db = get_db()
    collection = db[CONTAINER_RISK_SCORES_COLLECTION]

    await collection.create_index("ts")
    await collection.create_index("namespace")
    await collection.create_index("pod_name")
    await collection.create_index("container_id")
    await collection.create_index("entity_key")
    await collection.create_index("severity")
    await collection.create_index("final_risk_level")
    await collection.create_index("final_risk_score")

    await collection.create_index([
        ("namespace", 1),
        ("pod_name", 1),
        ("ts", -1),
    ])

    await collection.create_index([
        ("entity_key", 1),
        ("ts", -1),
    ])

    await collection.create_index([
        ("severity", 1),
        ("ts", -1),
    ])

    print("Container risk score indexes created successfully.")


if __name__ == "__main__":
    asyncio.run(init_container_risk_scores_indexes())