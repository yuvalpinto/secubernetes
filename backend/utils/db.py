from motor.motor_asyncio import AsyncIOMotorClient
from backend.config.settings import settings

_client: AsyncIOMotorClient | None = None


def get_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(
            settings.mongo_uri,
            serverSelectionTimeoutMS=3000,
        )
    return _client


def get_db():
    return get_client()[settings.mongo_db]
