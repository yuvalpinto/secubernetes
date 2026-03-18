from __future__ import annotations

from typing import Any

from backend.utils.db import get_db


async def insert_events_raw(events: list[dict[str, Any]]) -> int:
    """
    Insert a batch of raw events into MongoDB.

    Returns:
        int: number of inserted documents
    """
    if not events:
        return 0

    db = get_db()
    col = db.events_raw

    # ordered=False -> אם מסמך אחד נכשל, השאר ממשיכים
    res = await col.insert_many(events, ordered=False)
    return len(res.inserted_ids)


async def get_latest_events(limit: int = 50) -> list[dict[str, Any]]:
    """
    Fetch latest raw events sorted by timestamp (descending).
    """
    if limit <= 0:
        return []

    db = get_db()
    col = db.events_raw

    cursor = col.find({}).sort("ts", -1).limit(limit)
    return await cursor.to_list(length=limit)


async def get_events_by_pod(
    namespace: str,
    pod: str,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """
    Fetch raw events for a specific (namespace, pod), newest first.
    """
    if limit <= 0:
        return []

    db = get_db()
    col = db.events_raw

    query = {"namespace": namespace, "pod": pod}
    cursor = col.find(query).sort("ts", -1).limit(limit)
    return await cursor.to_list(length=limit)
