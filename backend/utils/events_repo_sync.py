from __future__ import annotations

from typing import Any

from backend.utils.db_sync import get_sync_db


def insert_events_raw_sync(events: list[dict[str, Any]]) -> int:
    if not events:
        return 0

    db = get_sync_db()
    col = db.events_raw

    res = col.insert_many(events, ordered=False)
    return len(res.inserted_ids)