import os
from backend.utils.container_resolver import resolve_container_info_from_pid


def main():
    pid = os.getpid()
    info = resolve_container_info_from_pid(pid)

    print("pid:", pid)
    print("container_id:", info["container_id"])
    print("pod_uid:", info["pod_uid"])
    print("cgroup_text:")
    print(info["cgroup_text"])


if __name__ == "__main__":
    main()