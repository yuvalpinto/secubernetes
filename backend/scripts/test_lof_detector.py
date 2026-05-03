from backend.detection.lof_detector import LOFDetector, LOFConfig


def main():
    detector = LOFDetector(
        LOFConfig(
            k_neighbors=3,
            min_history=5,
            max_history=50,
            anomaly_threshold=1.5,
            enabled_features=[
                "exec_count_window",
                "sensitive_open_count_window",
                "connect_count_window",
                "failed_connect_count_window",
                "unique_destination_count_window",
            ],
        )
    )

    normal_vectors = [
        { "namespace": "default", "pod_name": "test-pod",  "window_start": None,  "window_end": "t-anomaly","exec_count_window": 5, "sensitive_open_count_window": 0, "connect_count_window": 1, "failed_connect_count_window": 0, "unique_destination_count_window": 1},
        { "namespace": "default",
        "pod_name": "test-pod",
        "window_start": None,
        "window_end": "t-anomaly","exec_count_window": 6, "sensitive_open_count_window": 0, "connect_count_window": 1, "failed_connect_count_window": 0, "unique_destination_count_window": 1},
        { "namespace": "default",
        "pod_name": "test-pod",
        "window_start": None,
        "window_end": "t-anomaly","exec_count_window": 5, "sensitive_open_count_window": 1, "connect_count_window": 1, "failed_connect_count_window": 0, "unique_destination_count_window": 1},
        { "namespace": "default",
        "pod_name": "test-pod",
        "window_start": None,
        "window_end": "t-anomaly","exec_count_window": 4, "sensitive_open_count_window": 0, "connect_count_window": 1, "failed_connect_count_window": 0, "unique_destination_count_window": 1},
        { "namespace": "default",
        "pod_name": "test-pod",
        "window_start": None,
        "window_end": "t-anomaly","exec_count_window": 5, "sensitive_open_count_window": 0, "connect_count_window": 2, "failed_connect_count_window": 0, "unique_destination_count_window": 1},
        { "namespace": "default",
        "pod_name": "test-pod",
        "window_start": None,
        "window_end": "t-anomaly","exec_count_window": 6, "sensitive_open_count_window": 0, "connect_count_window": 1, "failed_connect_count_window": 0, "unique_destination_count_window": 2},
    ]

    anomalous_vector = {
        "namespace": "default",
        "pod_name": "test-pod",
        "window_start": None,
        "window_end": "t-anomaly",
        "exec_count_window": 20,
        "sensitive_open_count_window": 5,
        "connect_count_window": 8,
        "failed_connect_count_window": 0,
        "unique_destination_count_window": 4,
    }

    print("=== NORMAL PHASE ===")
    for v in normal_vectors:
        result = detector.process_vector(v)
        print(result)

    print("\n=== ANOMALY PHASE ===")
    result = detector.process_vector(anomalous_vector)
    print(result)


if __name__ == "__main__":
    main()