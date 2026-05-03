from datetime import datetime

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


async def get_alerts_by_type(alert_type: str, limit: int = 100):
    db = get_db()
    cursor = (
        db[ALERTS_COLLECTION]
        .find({"alert_type": alert_type})
        .sort("ts", -1)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)


async def get_alerts_by_types(alert_types: list[str], limit: int = 100):
    db = get_db()
    cursor = (
        db[ALERTS_COLLECTION]
        .find({"alert_type": {"$in": alert_types}})
        .sort("ts", -1)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)


async def get_alerts_by_severity(severity: str, limit: int = 100):
    db = get_db()
    cursor = (
        db[ALERTS_COLLECTION]
        .find({"severity": severity})
        .sort("ts", -1)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)
async def get_alert_summary():
    db = get_db()
    collection = db[ALERTS_COLLECTION]

    total_alerts = await collection.count_documents({})

    severity_counts_pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]

    severity_counts_raw = await collection.aggregate(severity_counts_pipeline).to_list(length=10)

    severity_counts = {
        item["_id"]: item["count"]
        for item in severity_counts_raw
    }

    top_types_pipeline = [
        {"$group": {"_id": "$alert_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5},
    ]

    top_types_raw = await collection.aggregate(top_types_pipeline).to_list(length=5)

    top_types = [
        {"alert_type": item["_id"], "count": item["count"]}
        for item in top_types_raw
    ]

    latest_chain = await collection.find_one(
        {"alert_type": "sensitive_access_and_exfiltration_chain"},
        sort=[("ts", -1)]
    )

    if latest_chain and latest_chain.get("ts"):
        latest_chain["ts"] = latest_chain["ts"].isoformat()
        latest_chain["_id"] = str(latest_chain["_id"])

    return {
        "total_alerts": total_alerts,
        "by_severity": severity_counts,
        "top_alert_types": top_types,
        "latest_chain": latest_chain,
    }


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
async def get_alerts_for_pod_in_window(
    namespace: str,
    pod_name: str,
    window_start: datetime,
    window_end: datetime,
):
    db = get_db()

    query = {
        "source_event.namespace": namespace,
        "source_event.pod_name": pod_name,
        "ts": {
            "$gte": window_start,
            "$lt": window_end,
        },
    }

    cursor = db[ALERTS_COLLECTION].find(query).sort("ts", -1)
    return await cursor.to_list(length=1000)