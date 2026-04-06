from backend.utils.db_sync import get_sync_db

FEATURE_VECTORS_COLLECTION = "feature_vectors"


def insert_feature_vectors_sync(vectors: list[dict]):
    if not vectors:
        return 0

    db = get_sync_db()
    res = db[FEATURE_VECTORS_COLLECTION].insert_many(vectors, ordered=False)
    return len(res.inserted_ids)


def insert_feature_vector_sync(vector: dict):
    if not vector:
        return None

    db = get_sync_db()
    res = db[FEATURE_VECTORS_COLLECTION].insert_one(vector)
    return res.inserted_id