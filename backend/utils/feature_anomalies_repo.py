from backend.utils.db import get_db

FEATURE_ANOMALIES_COLLECTION = "feature_anomalies"


async def insert_feature_anomaly(anomaly: dict):
    if not anomaly:
        return

    db = get_db()
    await db[FEATURE_ANOMALIES_COLLECTION].insert_one(anomaly)


async def insert_feature_anomalies(anomalies: list[dict]):
    if not anomalies:
        return

    db = get_db()
    await db[FEATURE_ANOMALIES_COLLECTION].insert_many(anomalies)


async def get_latest_feature_anomalies(limit: int = 100):
    db = get_db()
    cursor = (
        db[FEATURE_ANOMALIES_COLLECTION]
        .find()
        .sort("ts", -1)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)


async def get_feature_anomalies_by_pod(pod_name: str, limit: int = 100):
    db = get_db()
    cursor = (
        db[FEATURE_ANOMALIES_COLLECTION]
        .find({"pod_name": pod_name})
        .sort("ts", -1)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)


async def get_feature_anomalies_by_namespace(namespace: str, limit: int = 100):
    db = get_db()
    cursor = (
        db[FEATURE_ANOMALIES_COLLECTION]
        .find({"namespace": namespace})
        .sort("ts", -1)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)