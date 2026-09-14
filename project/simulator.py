from __future__ import annotations

import os
import random
import signal
import time
from datetime import datetime
from pathlib import Path

LOG_PATH = Path("/data/security.log")
INTERVAL_SECONDS = int(os.getenv("SIMULATION_INTERVAL_SECONDS", "10"))

running = True


def stop_handler(signum: int, frame: object) -> None:
    global running
    running = False


signal.signal(signal.SIGTERM, stop_handler)
signal.signal(signal.SIGINT, stop_handler)


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def generate_bruteforce() -> list[str]:
    source_ip = random.choice(["172.18.0.21", "172.18.0.22", "172.18.0.23"])
    start_port = random.randint(43000, 49000)
    burst_count = random.randint(3, 6)

    return [
        f"{timestamp()} WARN Failed password for root from {source_ip} port {start_port + i} ssh2"
        for i in range(burst_count)
    ]


def generate_network_scan() -> list[str]:
    source_ip = random.choice(["172.18.0.31", "172.18.0.32", "172.18.0.33"])
    ports = random.choice(
        [
            "21,22,23,25",
            "22,80,443,3306",
            "53,80,443,8080",
        ]
    )

    return [
        f"{timestamp()} INFO Network scan detected from {source_ip} against ports {ports}"
    ]


def generate_normal_activity() -> list[str]:
    source_ip = random.choice(
        [
            "172.18.0.10",
            "172.18.0.11",
            "172.18.0.12",
            "172.18.0.13",
            "172.18.0.14",
        ]
    )
    user = random.choice(["student", "analyst", "administrator", "developer"])
    actions = [
        f"{timestamp()} INFO User {user} logged in successfully from {source_ip}",
        f"{timestamp()} INFO Session keep-alive received from {source_ip}",
        f"{timestamp()} INFO User {user} logged out from {source_ip}",
    ]
    return [random.choice(actions)]


def append_events(events: list[str]) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    with LOG_PATH.open("a", encoding="utf-8") as log_file:
        for event in events:
            log_file.write(event + "\n")

    print(
        f"Appended {len(events)} synthetic event(s) to {LOG_PATH}",
        flush=True,
    )


def main() -> None:
    print(
        f"Synthetic log simulator started. Interval: {INTERVAL_SECONDS} seconds.",
        flush=True,
    )

    generators = [
        generate_normal_activity,
        generate_bruteforce,
        generate_network_scan,
    ]
    # 70% Normal baseline, 15% Brute Force, 15% Network Scan
    weights = [0.70, 0.15, 0.15]

    while running:
        generator = random.choices(generators, weights=weights, k=1)[0]
        append_events(generator())

        for _ in range(INTERVAL_SECONDS):
            if not running:
                break
            time.sleep(1)

    print("Synthetic log simulator stopped.", flush=True)


if __name__ == "__main__":
    main()
