from typing import Optional
from backend.utils.db import get_db

COLLECTION = "container_risk_scores"

RISK_SCORE_PROJECTION = {
    "_id": 1,
    "ts": 1,
    "namespace": 1,
    "pod_name": 1,
    "container_id": 1,
    "entity_key": 1,
    "window_start": 1,
    "window_end": 1,
    "final_risk_score": 1,
    "final_risk_level": 1,
    "severity": 1,
    "sequence_score": 1,
    "stat_score": 1,
    "lof_score": 1,
    "alerts_count": 1,
    "max_alert": 1,
    "threshold_anomaly_detected": 1,
    "threshold_max_z_score": 1,
    "threshold_triggered_features": 1,
    "lof_anomaly_detected": 1,
    "lof_value": 1,
    "lof_history_size": 1,
    "exec_count_window": 1,
    "sensitive_open_count_window": 1,
    "connect_count_window": 1,
    "failed_connect_count_window": 1,
    "unique_destination_count_window": 1,
}


async def get_latest_container_risk_scores(limit: int = 50):
    db = get_db()
    cursor = (
        db[COLLECTION]
        .find({}, RISK_SCORE_PROJECTION)
        .sort("ts", -1)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)


async def get_container_risk_scores_by_pod(
    pod_name: str,
    namespace: Optional[str] = None,
    limit: int = 50,
):
    db = get_db()

    query = {"pod_name": pod_name}
    if namespace:
        query["namespace"] = namespace

    cursor = (
        db[COLLECTION]
        .find(query, RISK_SCORE_PROJECTION)
        .sort("ts", -1)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)


async def get_latest_container_risk_per_pod(limit: int = 100):
    db = get_db()

    pipeline = [
        {"$sort": {"ts": -1}},
        {
            "$group": {
                "_id": {
                    "namespace": "$namespace",
                    "pod_name": "$pod_name",
                },
                "doc": {"$first": "$$ROOT"},
            }
        },
        {"$replaceRoot": {"newRoot": "$doc"}},
        {
            "$project": RISK_SCORE_PROJECTION
        },
        {"$sort": {"final_risk_score": -1, "ts": -1}},
        {"$limit": limit},
    ]

    return await db[COLLECTION].aggregate(pipeline).to_list(length=limit)