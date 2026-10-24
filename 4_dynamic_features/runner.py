from __future__ import annotations

import hashlib
import json
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from adb import AdbDevice, installed_third_party_packages, resolve_package
from collectors import collect_cpu, collect_memory, collect_network, collect_process
from config import Settings
from features import build_features


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stage_apk(apk: Path, staging_dir: Path, read_lock: threading.Lock | None = None) -> tuple[Path, str]:
    """Copy the APK to local disk in one sequential read, hashing it on the way.

    The source (e.g. an external USB drive) is then read exactly once; install,
    aapt and hashing all use the local copy. read_lock keeps parallel workers from
    reading the slow drive at the same time.
    """
    staging_dir.mkdir(parents=True, exist_ok=True)
    local = staging_dir / apk.name
    digest = hashlib.sha256()
    with read_lock or threading.Lock():
        with apk.open("rb") as src, local.open("wb") as dst:
            for block in iter(lambda: src.read(4 * 1024 * 1024), b""):
                digest.update(block)
                dst.write(block)
    return local, digest.hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def analyze_apk(
    apk: Path,
    output: Path,
    device: AdbDevice,
    settings: Settings,
    staging_dir: Path | None = None,
    read_lock: threading.Lock | None = None,
) -> dict[str, Any]:
    local_apk = apk
    if staging_dir:
        # One staging folder per emulator so parallel workers never share a file.
        local_apk, digest = stage_apk(apk, staging_dir / device.serial.replace(":", "_"), read_lock)
    else:
        digest = sha256_file(apk)
    try:
        return _analyze(apk, local_apk, digest, output, device, settings)
    finally:
        if local_apk != apk:
            local_apk.unlink(missing_ok=True)


def _analyze(apk: Path, local_apk: Path, digest: str, output: Path, device: AdbDevice, settings: Settings) -> dict[str, Any]:
    raw_dir = output / "raw" / digest
    raw_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    meta: dict[str, Any] = {
        "sha256": digest, "apk_name": apk.name, "device_serial": device.serial,
        "install_success": 0, "launch_success": 0, "execution_success": 0,
        "timeout": 0, "package_name": "", "effective_runtime": 0.0,
        "error": "",
    }
    package = None
    samples: list[dict[str, Any]] = []
    logcat = ""
    try:
        before = installed_third_party_packages(device)
        device.adb("logcat", "-c")
        installed = device.adb("install", "-r", "-g", str(local_apk), timeout=settings.install_timeout_seconds)
        meta["install_success"] = int(installed.returncode == 0 and "Success" in installed.stdout)
        meta["timeout"] = int(installed.timed_out)
        if not meta["install_success"]:
            raise RuntimeError((installed.stderr or installed.stdout).strip()[-1000:] or "Install failed")
        package = resolve_package(local_apk, device.adb_path, device, before)
        if not package:
            raise RuntimeError("Cannot determine installed package name; install Android build-tools for aapt/apkanalyzer")
        meta["package_name"] = package
        launch = device.shell(f"monkey -p {package} -c android.intent.category.LAUNCHER 1")
        meta["launch_success"] = int(launch.returncode == 0 and "Events injected: 1" in launch.stdout)
        # Run stimulation in the device shell background so telemetry collection
        # overlaps with UI events instead of starting only after Monkey finishes.
        monkey = device.shell(
            f"monkey -p {package} --ignore-crashes --ignore-timeouts "
            f"--throttle {settings.monkey_throttle_ms} {settings.monkey_events} "
            f">/data/local/tmp/dynextract_monkey.log 2>&1 &"
        )
        observe_start = time.monotonic()
        while time.monotonic() - observe_start < settings.runtime_seconds:
            sample = {
                "elapsed": round(time.monotonic() - observe_start, 3),
                "process": collect_process(device, package),
                "cpu": collect_cpu(device, package),
                "memory": collect_memory(device, package),
                "network": collect_network(device, package),
            }
            samples.append(sample)
            time.sleep(settings.sample_interval_seconds)
        meta["effective_runtime"] = round(time.monotonic() - observe_start, 3)
        meta["execution_success"] = int(bool(samples) and meta["launch_success"] == 1)
        meta["monkey_returncode"] = monkey.returncode
    except Exception as exc:
        meta["error"] = f"{type(exc).__name__}: {exc}"[:1500]
    finally:
        logcat = device.adb("logcat", "-d", "-v", "threadtime", timeout=30).stdout
        if package:
            device.shell(f"am force-stop {package}")
            device.adb("uninstall", package, timeout=60)
        meta["total_seconds"] = round(time.monotonic() - started, 3)

    features = build_features(meta, samples, logcat)
    if settings.keep_raw:
        _write_json(raw_dir / "metadata.json", meta)
        _write_json(raw_dir / "samples.json", samples)
        (raw_dir / "logcat.txt").write_text(logcat, encoding="utf-8", errors="replace")
        _write_json(raw_dir / "features.json", features)
    return features
