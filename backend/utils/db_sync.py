from pymongo import MongoClient
from backend.config.settings import settings

_sync_client: MongoClient | None = None


def get_sync_client() -> MongoClient:
    global _sync_client
    if _sync_client is None:
        _sync_client = MongoClient(
            settings.mongo_uri,
            serverSelectionTimeoutMS=3000,
        )
    return _sync_client


def get_sync_db():
    return get_sync_client()[settings.mongo_db]