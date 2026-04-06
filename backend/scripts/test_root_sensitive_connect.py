import socket
import time

def main():
    path = "/etc/shadow"
    host = "93.184.216.34"
    port = 80

    print(f"[test] opening {path}")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        _ = f.read(128)

    time.sleep(1)

    print(f"[test] connecting to {host}:{port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)

    try:
        s.connect((host, port))
        print("[test] connected")
    finally:
        s.close()

if __name__ == "__main__":
    main()