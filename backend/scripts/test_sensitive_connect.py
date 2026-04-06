import socket
import time


def open_sensitive_file():
    path = "/etc/passwd"
    print(f"[test] opening sensitive file: {path}")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = f.read(128)

    print(f"[test] read {len(data)} bytes from {path}")


def make_outbound_connect():
    host = "example.com"
    port = 80

    print(f"[test] connecting to {host}:{port}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)

    try:
        s.connect((host, port))
        print(f"[test] connected to {host}:{port}")

        request = (
            "GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n\r\n"
        )
        s.sendall(request.encode("utf-8"))

        response = s.recv(128)
        print(f"[test] received {len(response)} bytes")
    finally:
        s.close()


def main():
    print("[test] starting sensitive_access_then_connect scenario")

    open_sensitive_file()

    # small delay, still inside correlation window
    time.sleep(1)

    make_outbound_connect()

    print("[test] done")


if __name__ == "__main__":
    main()