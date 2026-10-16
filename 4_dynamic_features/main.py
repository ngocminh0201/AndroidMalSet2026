from __future__ import annotations

import argparse
import csv
import json
import queue
import threading
from pathlib import Path

from adb import AdbDevice, list_devices
from config import Settings
from runner import analyze_apk, sha256_file


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lightweight multi-emulator Android dynamic feature extractor")
    parser.add_argument("--apk-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.yaml"))
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--serials", help="Comma-separated ADB serials; default: online emulators")
    parser.add_argument("--runtime", type=int)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--test-apk", type=Path)
    return parser.parse_args()


def append_jsonl(path: Path, row: dict, lock: threading.Lock) -> None:
    with lock, path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_completed(path: Path) -> set[str]:
    done = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
                if row.get("execution_success") == 1:
                    done.add(row["sha256"])
            except (json.JSONDecodeError, KeyError):
                pass
    return done


def write_csv(jsonl: Path, csv_path: Path) -> None:
    rows = [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        return
    fields = sorted({key for row in rows for key in row})
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    args = parse_args()
    settings = Settings.load(args.config)
    if args.runtime:
        settings = Settings(**{**settings.__dict__, "runtime_seconds": args.runtime})
    args.output.mkdir(parents=True, exist_ok=True)
    feature_log = args.output / "processed.jsonl"
    error_log = args.output / "failed.jsonl"
    devices = [s.strip() for s in args.serials.split(",")] if args.serials else [s for s in list_devices(args.adb) if s.startswith("emulator-")]
    devices = devices[:max(1, args.workers)]
    if not devices:
        raise SystemExit("No online Android emulator found. Check: adb devices")
    apks = [args.test_apk] if args.test_apk else sorted(args.apk_dir.rglob("*.apk"))
    completed = load_completed(feature_log) if args.resume else set()
    jobs: queue.Queue[Path] = queue.Queue()
    for apk in apks:
        if apk and apk.is_file() and (not args.resume or sha256_file(apk) not in completed):
            jobs.put(apk)
    lock = threading.Lock()

    def worker(serial: str) -> None:
        device = AdbDevice(args.adb, serial, settings.command_timeout_seconds)
        while True:
            try:
                apk = jobs.get_nowait()
            except queue.Empty:
                return
            try:
                row = analyze_apk(apk, args.output, device, settings)
                append_jsonl(feature_log, row, lock)
                if not row.get("execution_success"):
                    append_jsonl(error_log, row, lock)
                with lock:
                    print(f"[{serial}] {apk.name}: {'OK' if row.get('execution_success') else 'FAILED'}")
            finally:
                jobs.task_done()

    threads = [threading.Thread(target=worker, args=(serial,), daemon=False) for serial in devices]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    write_csv(feature_log, args.output / "dynamic_features.csv")
    print(f"Finished. CSV: {args.output / 'dynamic_features.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

