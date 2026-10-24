from __future__ import annotations

import argparse
import csv
import json
import queue
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable

from adb import AdbDevice, boot_completed, list_devices
from config import Settings
from runner import analyze_apk


DEFAULT_STAGING = Path(tempfile.gettempdir()) / "dynextract_staging"
DEVICE_WAIT_SECONDS = 600   # how long a worker waits for a lost emulator to come back
DEVICE_LOST_RETRIES = 1     # an APK is re-run this many times after losing the emulator


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
    parser.add_argument("--staging-dir", type=Path, default=DEFAULT_STAGING,
                        help="Local folder: each APK is copied here once (read the source drive only once), then deleted")
    parser.add_argument("--no-staging", action="store_true", help="Install directly from --apk-dir (old behaviour)")
    return parser.parse_args()


def append_jsonl(path: Path, row: dict, lock: threading.Lock) -> None:
    with lock, path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_completed(path: Path) -> set[str]:
    """File names of APKs already executed successfully.

    Matching by name (not SHA-256) means resume does not have to read every
    APK from a slow external drive before starting.
    """
    done = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
                if row.get("execution_success") == 1:
                    done.add(row["apk_name"])
            except (json.JSONDecodeError, KeyError):
                pass
    return done


def read_latest_rows(jsonl: Path) -> list[dict]:
    """One row per APK. An APK that was re-run appears several times in the
    append-only log; the most recent attempt is the one that counts."""
    latest: dict[str, dict] = {}
    if jsonl.exists():
        for line in jsonl.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = row.get("apk_name") or row.get("sha256")
            latest.pop(key, None)  # move to the end: order follows the latest attempt
            latest[key] = row
    return list(latest.values())


def write_csv(jsonl: Path, csv_path: Path) -> None:
    rows = read_latest_rows(jsonl)
    if not rows:
        return
    fields = sorted({key for row in rows for key in row})
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def wait_for_device(device: AdbDevice, stop_event: threading.Event, timeout: float) -> bool:
    """Wait until the emulator is back online and fully booted (e.g. restarted from the GUI)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not stop_event.is_set():
        if device.online() and boot_completed(device.adb_path, device.serial):
            return True
        stop_event.wait(5)
    return False


def run(
    args: argparse.Namespace,
    settings: Settings,
    log: Callable[[str], None] = print,
    on_result: Callable[[dict], None] | None = None,
    on_total: Callable[[int], None] | None = None,
    stop_event: threading.Event | None = None,
) -> Path:
    """Process all APKs; callbacks let a GUI follow progress and request a graceful stop."""
    stop_event = stop_event or threading.Event()
    args.output.mkdir(parents=True, exist_ok=True)
    feature_log = args.output / "processed.jsonl"
    error_log = args.output / "failed.jsonl"
    devices = [s.strip() for s in args.serials.split(",") if s.strip()] if args.serials else [s for s in list_devices(args.adb) if s.startswith("emulator-")]
    devices = devices[:max(1, args.workers)]
    if not devices:
        raise SystemExit("No online Android emulator found. Check: adb devices")
    apks = [args.test_apk] if args.test_apk else sorted(args.apk_dir.rglob("*.apk"))
    completed = load_completed(feature_log) if args.resume else set()
    jobs: queue.Queue[Path] = queue.Queue()
    for apk in apks:
        if apk and apk.name not in completed and apk.is_file():
            jobs.put(apk)
    if args.resume:
        log(f"Resume: skipped {len(completed)} APK(s) already processed successfully.")
    staging = None if getattr(args, "no_staging", False) else getattr(args, "staging_dir", None)
    if staging:
        # Leftover copies from an interrupted run (only our own <serial>/*.apk files).
        for leftover in staging.glob("*/*.apk"):
            leftover.unlink(missing_ok=True)
        log(f"Staging: each APK is copied once to {staging}, analysed, then deleted.")
    read_lock = threading.Lock()
    source_root = args.test_apk.parent if args.test_apk else args.apk_dir
    log(f"APKs to process: {jobs.qsize()} on {len(devices)} device(s): {', '.join(devices)}")
    if on_total:
        on_total(jobs.qsize())
    lock = threading.Lock()

    def worker(serial: str) -> None:
        device = AdbDevice(args.adb, serial, settings.command_timeout_seconds)
        retry: Path | None = None
        lost_count: dict[str, int] = {}
        while not stop_event.is_set():
            if retry is not None:
                apk, retry = retry, None
            else:
                try:
                    apk = jobs.get_nowait()
                except queue.Empty:
                    return
            try:
                with lock:
                    log(f"[{serial}] {apk.name}: running...")
                try:
                    row = analyze_apk(apk, args.output, device, settings, staging, read_lock)
                except OSError as exc:
                    if not source_root.exists():
                        # External drive unplugged: stop instead of marking every APK as failed.
                        jobs.put(apk)
                        with lock:
                            log(f"[{serial}] Source folder is no longer available ({exc}). Stopping.")
                        stop_event.set()
                        continue
                    raise
                if not row.get("execution_success") and not device.online():
                    # The emulator died or adb lost it: this is not the APK's result.
                    lost_count[apk.name] = lost_count.get(apk.name, 0) + 1
                    if lost_count[apk.name] <= DEVICE_LOST_RETRIES:
                        with lock:
                            log(f"[{serial}] Mất kết nối emulator khi chạy {apk.name}; mẫu này KHÔNG bị ghi lỗi và sẽ chạy lại. "
                                f"Đang đợi {serial} quay lại (tối đa {DEVICE_WAIT_SECONDS // 60} phút): "
                                "đóng cửa sổ emulator bị treo (nếu còn) rồi bấm 'Bật emulator'.")
                        if wait_for_device(device, stop_event, DEVICE_WAIT_SECONDS):
                            with lock:
                                log(f"[{serial}] Emulator đã sẵn sàng lại, chạy tiếp.")
                            retry = apk
                        else:
                            jobs.put(apk)
                            if not stop_event.is_set():
                                with lock:
                                    log(f"[{serial}] Emulator không quay lại, worker này dừng.")
                            return
                        continue
                    # Same APK took the emulator down again: keep it as a failed sample.
                    row["error"] = f"DEVICE_LOST (emulator mất kết nối {lost_count[apk.name]} lần khi chạy mẫu này); {row.get('error', '')}"[:1500]
                append_jsonl(feature_log, row, lock)
                if not row.get("execution_success"):
                    append_jsonl(error_log, row, lock)
                with lock:
                    log(f"[{serial}] {apk.name}: {'OK' if row.get('execution_success') else 'FAILED'}")
                    if on_result:
                        on_result(row)
            except Exception as exc:
                with lock:
                    log(f"[{serial}] {apk.name}: ERROR {type(exc).__name__}: {exc}")
        if retry is not None:  # stopped while an APK was waiting to be re-run
            jobs.put(retry)

    threads = [threading.Thread(target=worker, args=(serial,), daemon=False) for serial in devices]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    if stop_event.is_set():
        log(f"Stopped. {jobs.qsize()} APK(s) not processed.")
    csv_path = args.output / "dynamic_features.csv"
    if feature_log.exists():
        write_csv(feature_log, csv_path)
    log(f"Finished. CSV: {csv_path}")
    return csv_path


def main() -> int:
    args = parse_args()
    settings = Settings.load(args.config)
    if args.runtime:
        settings = Settings(**{**settings.__dict__, "runtime_seconds": args.runtime})
    run(args, settings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

