from backend.utils.db import get_db

FEATURE_VECTORS_COLLECTION = "feature_vectors"


async def insert_feature_vectors(vectors: list[dict]):
    if not vectors:
        return

    db = get_db()
    await db[FEATURE_VECTORS_COLLECTION].insert_many(vectors)


async def insert_feature_vector(vector: dict):
    if not vector:
        return

    db = get_db()
    await db[FEATURE_VECTORS_COLLECTION].insert_one(vector)


async def get_latest_feature_vectors(limit: int = 100):
    db = get_db()
    cursor = db[FEATURE_VECTORS_COLLECTION].find().sort("window_start", -1).limit(limit)
    return await cursor.to_list(length=limit)


async def get_feature_vectors_by_pod(pod_name: str, limit: int = 100):
    db = get_db()
    cursor = (
        db[FEATURE_VECTORS_COLLECTION]
        .find({"pod_name": pod_name})
        .sort("window_start", -1)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)


async def get_feature_vectors_by_namespace(namespace: str, limit: int = 100):
    db = get_db()
    cursor = (
        db[FEATURE_VECTORS_COLLECTION]
        .find({"namespace": namespace})
        .sort("window_start", -1)
        .limit(limit)
    )
    return await cursor.to_list(length=limit)


async def get_feature_vector_stats():
    db = get_db()
    collection = db[FEATURE_VECTORS_COLLECTION]

    total_vectors = await collection.count_documents({})

    by_namespace_pipeline = [
        {"$group": {"_id": "$namespace", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]

    by_pod_pipeline = [
        {"$group": {"_id": "$pod_name", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]

    avg_features_pipeline = [
        {
            "$group": {
                "_id": None,
                "avg_exec_count_window": {"$avg": "$exec_count_window"},
                "avg_sensitive_open_count_window": {"$avg": "$sensitive_open_count_window"},
                "avg_connect_count_window": {"$avg": "$connect_count_window"},
                "avg_failed_connect_count_window": {"$avg": "$failed_connect_count_window"},
                "avg_root_event_count_window": {"$avg": "$root_event_count_window"},
                "avg_unique_destination_count_window": {"$avg": "$unique_destination_count_window"},
                "avg_total_event_count_window": {"$avg": "$total_event_count_window"},
            }
        }
    ]

    by_namespace_raw = await collection.aggregate(by_namespace_pipeline).to_list(length=100)
    by_pod_raw = await collection.aggregate(by_pod_pipeline).to_list(length=10)
    avg_features_raw = await collection.aggregate(avg_features_pipeline).to_list(length=1)

    by_namespace = [
        {"namespace": item["_id"], "count": item["count"]}
        for item in by_namespace_raw
    ]

    by_pod = [
        {"pod_name": item["_id"], "count": item["count"]}
        for item in by_pod_raw
    ]

    avg_features = avg_features_raw[0] if avg_features_raw else {}
    avg_features.pop("_id", None)

    latest_vector = await collection.find_one(sort=[("window_start", -1)])

    latest_vector_time = None
    if latest_vector and latest_vector.get("window_start") is not None:
        latest_vector_time = latest_vector["window_start"]
        if hasattr(latest_vector_time, "isoformat"):
            latest_vector_time = latest_vector_time.isoformat()

    return {
        "total_vectors": total_vectors,
        "by_namespace": by_namespace,
        "top_pods": by_pod,
        "avg_features": avg_features,
        "latest_vector_time": latest_vector_time,
    }