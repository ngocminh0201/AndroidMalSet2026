from __future__ import annotations

import hashlib
import json
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


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def analyze_apk(apk: Path, output: Path, device: AdbDevice, settings: Settings) -> dict[str, Any]:
    digest = sha256_file(apk)
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
        installed = device.adb("install", "-r", "-g", str(apk), timeout=settings.install_timeout_seconds)
        meta["install_success"] = int(installed.returncode == 0 and "Success" in installed.stdout)
        meta["timeout"] = int(installed.timed_out)
        if not meta["install_success"]:
            raise RuntimeError((installed.stderr or installed.stdout).strip()[-1000:] or "Install failed")
        package = resolve_package(apk, device.adb_path, device, before)
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
