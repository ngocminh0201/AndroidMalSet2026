from __future__ import annotations

import re
import statistics
from typing import Any


def _nums(samples: list[dict[str, Any]], group: str, key: str) -> list[float]:
    result = []
    for sample in samples:
        value = sample.get(group, {}).get(key)
        if isinstance(value, (int, float)):
            result.append(float(value))
    return result


def _summary(values: list[float], prefix: str) -> dict[str, float | int]:
    return {
        f"{prefix}_samples": len(values),
        f"{prefix}_mean": round(statistics.fmean(values), 3) if values else 0.0,
        f"{prefix}_max": round(max(values), 3) if values else 0.0,
    }


def build_features(meta: dict[str, Any], samples: list[dict[str, Any]], logcat: str) -> dict[str, Any]:
    result = dict(meta)
    result.update(_summary(_nums(samples, "cpu", "cpu_percent"), "cpu_percent"))
    result.update(_summary(_nums(samples, "memory", "pss_kb"), "pss_kb"))
    result.update(_summary(_nums(samples, "memory", "rss_kb"), "rss_kb"))
    result.update(_summary(_nums(samples, "memory", "java_heap_kb"), "java_heap_kb"))
    result.update(_summary(_nums(samples, "memory", "native_heap_kb"), "native_heap_kb"))
    result["process_count_max"] = int(max(_nums(samples, "process", "process_count"), default=0))
    result["thread_count_max"] = int(max(_nums(samples, "process", "thread_count"), default=0))
    rows = _nums(samples, "network", "socket_table_rows")
    rx = _nums(samples, "network", "rx_bytes_snapshot")
    tx = _nums(samples, "network", "tx_bytes_snapshot")
    result["socket_rows_max"] = int(max(rows, default=0))
    result["rx_bytes_delta"] = int(max(rx) - min(rx)) if len(rx) > 1 else 0
    result["tx_bytes_delta"] = int(max(tx) - min(tx)) if len(tx) > 1 else 0
    result["network_active"] = int(result["rx_bytes_delta"] > 0 or result["tx_bytes_delta"] > 0)
    result["log_error_count"] = len(re.findall(r"\bE/", logcat))
    result["log_warning_count"] = len(re.findall(r"\bW/", logcat))
    result["exception_count"] = len(re.findall(r"Exception|FATAL EXCEPTION", logcat, re.I))
    result["anr_count"] = len(re.findall(r"ANR in|Application Not Responding", logcat, re.I))
    result["activity_event_count"] = len(re.findall(r"ActivityTaskManager.*START", logcat))
    result["service_event_count"] = len(re.findall(r"ActivityManager.*(?:Start proc|service)", logcat, re.I))
    result["crashed"] = int(bool(re.search(r"FATAL EXCEPTION|Force finishing activity", logcat, re.I)))
    result["events_observed"] = sum(int(result[k] > 0) for k in ("process_count_max", "thread_count_max", "network_active", "activity_event_count", "service_event_count"))
    return result

