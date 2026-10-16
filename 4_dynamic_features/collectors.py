from __future__ import annotations

import re
from typing import Any

from adb import AdbDevice


FLOAT = r"([0-9]+(?:\.[0-9]+)?)"


def collect_process(device: AdbDevice, package: str) -> dict[str, Any]:
    result = device.shell(f"pidof {package}")
    pids = [p for p in result.stdout.split() if p.isdigit()]
    thread_total = 0
    for pid in pids:
        status = device.shell(f"cat /proc/{pid}/status").stdout
        match = re.search(r"^Threads:\s+(\d+)", status, re.MULTILINE)
        thread_total += int(match.group(1)) if match else 0
    return {"pids": pids, "process_count": len(pids), "thread_count": thread_total}


def collect_memory(device: AdbDevice, package: str) -> dict[str, float | None]:
    text = device.shell(f"dumpsys meminfo {package}").stdout
    total = re.search(r"TOTAL\s+(\d+)\s+(\d+)", text)
    java = re.search(r"Java Heap:\s+(\d+)", text)
    native = re.search(r"Native Heap:\s+(\d+)", text)
    return {
        "pss_kb": float(total.group(1)) if total else None,
        "rss_kb": float(total.group(2)) if total else None,
        "java_heap_kb": float(java.group(1)) if java else None,
        "native_heap_kb": float(native.group(1)) if native else None,
    }


def collect_cpu(device: AdbDevice, package: str) -> dict[str, float | None]:
    text = device.shell("dumpsys cpuinfo").stdout
    values = []
    for line in text.splitlines():
        if package in line:
            match = re.search(FLOAT + r"%", line)
            if match:
                values.append(float(match.group(1)))
    return {"cpu_percent": sum(values) if values else None}


def collect_network(device: AdbDevice, package: str) -> dict[str, Any]:
    uid_text = device.shell(f"dumpsys package {package} | grep userId=").stdout
    match = re.search(r"userId=(\d+)", uid_text)
    uid = match.group(1) if match else None
    sockets = device.shell("cat /proc/net/tcp; cat /proc/net/tcp6; cat /proc/net/udp; cat /proc/net/udp6").stdout
    socket_lines = []
    for line in sockets.splitlines():
        parts = line.split()
        if not re.search(r"\b[0-9A-F]{8}:[0-9A-F]{4}\b", line):
            continue
        # /proc/net/{tcp,udp} normally exposes the socket owner UID at column 8.
        # If Android hides/reformats the table, retain no rows instead of counting
        # unrelated sockets from the whole emulator.
        if uid and len(parts) > 7 and parts[7] == uid:
            socket_lines.append(line)
    netstats = device.shell("dumpsys netstats detail").stdout if uid else ""
    uid_lines = [line.strip() for line in netstats.splitlines() if uid and f"uid={uid}" in line]
    rx = tx = 0
    for line in uid_lines:
        for key, target in (("rxBytes", "rx"), ("txBytes", "tx")):
            found = re.search(rf"{key}=(\d+)", line)
            if found:
                if target == "rx": rx += int(found.group(1))
                else: tx += int(found.group(1))
    return {"uid": uid, "socket_table_rows": len(socket_lines), "rx_bytes_snapshot": rx, "tx_bytes_snapshot": tx, "uid_netstats_lines": uid_lines}
