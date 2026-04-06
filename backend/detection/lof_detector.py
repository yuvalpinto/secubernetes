from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from math import sqrt
from typing import Any, Deque, Dict, List, Optional, Tuple


@dataclass
class LOFConfig:
    """
    Configuration for LOF detector.
    """
    k_neighbors: int = 5
    min_history: int = 10
    max_history: int = 100

    enabled_features: List[str] = field(default_factory=lambda: [
        "exec_count_window",
        "sensitive_open_count_window",
        "connect_count_window",
        "failed_connect_count_window",
        "unique_destination_count_window",
    ])

    anomaly_threshold: float = 1.5


class LOFDetector:
    """
    Local Outlier Factor detector over feature vectors.

    Design:
    - history is kept per (namespace, pod_name)
    - each vector is reduced into a numeric point using enabled_features
    - once enough history exists, LOF is computed for the new point
    - then the point is added into history

    Important:
    This skeleton intentionally leaves the core LOF math as TODOs
    so you can implement it yourself step by step.
    """

    def __init__(self, config: Optional[LOFConfig] = None):
        self.config = config or LOFConfig()

        # key: (namespace, pod_name)
        # value: deque of prior vectors / points
        self.history: Dict[Tuple[str, str], Deque[Dict[str, Any]]] = {}

    def process_vector(self, vector: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point.

        Flow:
        1. build pod key
        2. initialize history if needed
        3. convert vector -> numeric point
        4. if not enough history: warming up
        5. else compute LOF
        6. append vector to history
        7. return structured result
        """
        namespace = str(vector.get("namespace", "unknown"))
        pod_name = str(vector.get("pod_name", "unknown"))
        key = (namespace, pod_name)

        if key not in self.history:
            self.history[key] = deque(maxlen=self.config.max_history)

        pod_history = self.history[key]
        point = self._vector_to_point(vector)

        if len(pod_history) < self.config.min_history:
            result = self._build_warmup_result(
                namespace=namespace,
                pod_name=pod_name,
                vector=vector,
                history_size=len(pod_history),
                point=point,
            )
            pod_history.append(vector)
            return result

        # Build history points from previous vectors
        history_points = [self._vector_to_point(v) for v in pod_history]

        # TODO: compute LOF score for current point against history_points
        lof_value = self._compute_lof(point, history_points)

        anomaly_detected = lof_value > self.config.anomaly_threshold

        result = {
            "detector_type": "lof",
            "namespace": namespace,
            "pod_name": pod_name,
            "ts": vector.get("window_end"),
            "window_start": vector.get("window_start"),
            "window_end": vector.get("window_end"),
            "anomaly_detected": anomaly_detected,
            "lof_value": lof_value,
            "threshold": self.config.anomaly_threshold,
            "k_neighbors": self.config.k_neighbors,
            "history_size": len(pod_history),
            "enabled_features": list(self.config.enabled_features),
            "source_vector": vector,
        }

        pod_history.append(vector)
        return result

    def _vector_to_point(self, vector: Dict[str, Any]) -> List[float]:
        """
        Convert feature vector dict into ordered numeric point.

        Example output:
            [6.0, 2.0, 1.0, 0.0, 3.0]
        """
        point: List[float] = []

        for feature in self.config.enabled_features:
            value = vector.get(feature, 0.0)

            if isinstance(value, (int, float)):
                point.append(float(value))
            else:
                point.append(0.0)

        return point

    def _compute_lof(self, point: List[float], history_points: List[List[float]]) -> float:
        """
        Compute LOF score for 'point' relative to history_points.

        This is the main algorithmic part you should implement.

        Suggested steps:
        1. find k-nearest neighbors of point
        2. compute k-distance for relevant points
        3. compute reachability distance
        4. compute local reachability density (LRD)
        5. compute LOF

        For now, returns placeholder.
        """
        if len(history_points) < self.config.k_neighbors:
            return 1.0

        # TODO: replace with real LOF implementation
        return 1.0

    def _euclidean_distance(self, p1: List[float], p2: List[float]) -> float:
        """
        Standard Euclidean distance between two points.
        """
        if len(p1) != len(p2):
            raise ValueError("Points must have same dimensionality")

        squared_sum = 0.0
        for a, b in zip(p1, p2):
            squared_sum += (a - b) ** 2

        return sqrt(squared_sum)

    def _get_k_nearest_neighbors(
        self,
        point: List[float],
        history_points: List[List[float]],
    ) -> List[Tuple[List[float], float]]:
        """
        Return k nearest neighbors of point.

        Suggested return format:
            [
                ([1.0, 2.0, 0.0], 0.5),
                ([1.5, 2.1, 0.0], 0.7),
                ...
            ]

        Each item is:
            (neighbor_point, distance_to_point)

        TODO:
        - compute distances to all history points
        - sort ascending by distance
        - return first k
        """
        points: List[Tuple[List[float], float]] = [] 
        for point2 in history_points:
            distance=self._euclidean_distance(point,point2)
            points.append((point2, distance))
        return sorted(points, key=lambda item: item[1])[:self.config.k_neighbors]
            
        
        
            
            


        # TODO: implement
        return []

    def _k_distance( self,
        point: List[float],
        all_points: List[List[float]],
    ) -> float:
        neighbors = self._get_k_nearest_neighbors(point, all_points)

        if not neighbors:
            return 0.0

        return neighbors[-1][1]

    def _reachability_distance(
        self,
        point_a: List[float],
        point_b: List[float],
        all_points_for_b: List[List[float]],
    ) -> float:
        """
        reachability_distance_k(A, B) =
            max( k-distance(B), distance(A, B) )
        """
        direct_distance = self._euclidean_distance(point_a, point_b)
        k_distance_b = self._k_distance(point_b, all_points_for_b)

        return max(direct_distance, k_distance_b)

  
    def _local_reachability_density(
    self,
        point: List[float],
        neighbors: List[List[float]],
        all_points: List[List[float]],
    ) -> float:
        """
        LRD(point) = 1 / average(reachability_distance(point, neighbor))
        """
        if not neighbors:
            return 0.0

        reachability_sum = 0.0

        for neighbor in neighbors:
            rd = self._reachability_distance(point, neighbor, all_points)
            reachability_sum += rd

        avg_reachability = reachability_sum / len(neighbors)

        if avg_reachability == 0:
            return 0.0

        return 1.0 / avg_reachability

    def _build_warmup_result(
        self,
        namespace: str,
        pod_name: str,
        vector: Dict[str, Any],
        history_size: int,
        point: List[float],
    ) -> Dict[str, Any]:
        """
        Standard result during warmup phase.
        """
        return {
            "detector_type": "lof",
            "namespace": namespace,
            "pod_name": pod_name,
            "ts": vector.get("window_end"),
            "window_start": vector.get("window_start"),
            "window_end": vector.get("window_end"),
            "anomaly_detected": False,
            "lof_value": 1.0,
            "threshold": self.config.anomaly_threshold,
            "k_neighbors": self.config.k_neighbors,
            "history_size": history_size,
            "warming_up": True,
            "enabled_features": list(self.config.enabled_features),
            "point": point,
            "source_vector": vector,
        }

    def reset(self) -> None:
        """
        Clear all in-memory history.
        """
        self.history.clear()