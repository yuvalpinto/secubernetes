from backend.utils.db import get_db

ALERTS_COLLECTION = "alerts"


async def insert_alerts(alerts: list[dict]):
    if not alerts:
        return

    db = get_db()
    await db[ALERTS_COLLECTION].insert_many(alerts)


async def get_latest_alerts(limit: int = 100):
    db = get_db()
    cursor = db[ALERTS_COLLECTION].find().sort("ts", -1).limit(limit)
    return await cursor.to_list(length=limit)


async def get_alert_stats():
    db = get_db()
    collection = db[ALERTS_COLLECTION]

    total_alerts = await collection.count_documents({})

    by_severity_pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]

    by_type_pipeline = [
        {"$group": {"_id": "$alert_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]

    by_severity_raw = await collection.aggregate(by_severity_pipeline).to_list(length=100)
    by_type_raw = await collection.aggregate(by_type_pipeline).to_list(length=100)

    by_severity = [
        {"severity": item["_id"], "count": item["count"]}
        for item in by_severity_raw
    ]

    by_type = [
        {"alert_type": item["_id"], "count": item["count"]}
        for item in by_type_raw
    ]

    latest_alert = await collection.find_one(sort=[("ts", -1)])

    latest_alert_ts = None
    if latest_alert and latest_alert.get("ts") is not None:
        latest_alert_ts = latest_alert["ts"].isoformat()

    return {
        "total_alerts": total_alerts,
        "by_severity": by_severity,
        "by_type": by_type,
        "latest_alert_ts": latest_alert_ts,
    }