import queue
from copy import deepcopy


class EventDispatcher:
    def __init__(
        self,
        db_queue: queue.Queue,
        online_queue: queue.Queue,
        feature_queue: queue.Queue,
    ):
        self.db_queue = db_queue
        self.online_queue = online_queue
        self.feature_queue = feature_queue

    def dispatch(self, event: dict):
        # deepcopy כדי ששינוי במסלול אחד לא ישפיע על האחרים
        self.db_queue.put(deepcopy(event))
        self.online_queue.put(deepcopy(event))
        self.feature_queue.put(deepcopy(event))