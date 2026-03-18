from fastapi import FastAPI, Query

from backend.utils.alerts_repo import get_alert_stats, get_latest_alerts
from backend.utils.events_repo import get_latest_events

app = FastAPI(title="Secubernetes API")


def serialize_doc(doc: dict) -> dict:
    doc = dict(doc)

    if "_id" in doc:
        doc["_id"] = str(doc["_id"])

    ts = doc.get("ts")
    if ts is not None and hasattr(ts, "isoformat"):
        doc["ts"] = ts.isoformat()

    source_event = doc.get("source_event")
    if isinstance(source_event, dict):
        source_event = dict(source_event)
        source_ts = source_event.get("ts")
        if source_ts is not None and hasattr(source_ts, "isoformat"):
            source_event["ts"] = source_ts.isoformat()
        doc["source_event"] = source_event

    return doc


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/alerts/latest")
async def alerts_latest(limit: int = Query(default=50, ge=1, le=500)):
    alerts = await get_latest_alerts(limit=limit)
    return {
        "count": len(alerts),
        "items": [serialize_doc(alert) for alert in alerts],
    }


@app.get("/events/latest")
async def events_latest(limit: int = Query(default=100, ge=1, le=1000)):
    events = await get_latest_events(limit=limit)
    return {
        "count": len(events),
        "items": [serialize_doc(event) for event in events],
    }


@app.get("/alerts/stats")
async def alerts_stats():
    return await get_alert_stats()