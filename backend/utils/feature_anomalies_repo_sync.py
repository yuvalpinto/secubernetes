from backend.utils.db_sync import get_sync_db

FEATURE_ANOMALIES_COLLECTION = "feature_anomalies"


def insert_feature_anomaly_sync(anomaly: dict):
    if not anomaly:
        return None

    db = get_sync_db()
    res = db[FEATURE_ANOMALIES_COLLECTION].insert_one(anomaly)
    return res.inserted_id


def insert_feature_anomalies_sync(anomalies: list[dict]):
    if not anomalies:
        return 0

    db = get_sync_db()
    res = db[FEATURE_ANOMALIES_COLLECTION].insert_many(anomalies, ordered=False)
    return len(res.inserted_ids)