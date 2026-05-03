from datetime import datetime
from backend.utils.db_sync import get_sync_db

COLLECTION_NAME = "container_risk_scores"


def insert_container_risk_score_sync(document: dict):
    db = get_sync_db()
    result = db[COLLECTION_NAME].insert_one(document)
    return result.inserted_id