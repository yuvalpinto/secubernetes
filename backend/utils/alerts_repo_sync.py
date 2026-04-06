from backend.utils.db_sync import get_sync_db

ALERTS_COLLECTION = "alerts"


def insert_alerts_sync(alerts: list[dict]):
    if not alerts:
        return 0

    db = get_sync_db()
    res = db[ALERTS_COLLECTION].insert_many(alerts, ordered=False)
    return len(res.inserted_ids)