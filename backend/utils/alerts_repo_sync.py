from datetime import datetime

from backend.utils.db_sync import get_sync_db

ALERTS_COLLECTION = "alerts"


def insert_alerts_sync(alerts: list[dict]):
    if not alerts:
        return 0

    db = get_sync_db()
    res = db[ALERTS_COLLECTION].insert_many(alerts, ordered=False)
    return len(res.inserted_ids)


def get_alerts_for_pod_in_window_sync(
    namespace: str,
    pod_name: str,
    window_start: datetime,
    window_end: datetime,
):
    db = get_sync_db()

    query = {
        "source_event.namespace": namespace,
        "source_event.pod_name": pod_name,
        "ts": {
            "$gte": window_start,
            "$lt": window_end,
        },
    }

    cursor = db[ALERTS_COLLECTION].find(query).sort("ts", -1)
    return list(cursor)