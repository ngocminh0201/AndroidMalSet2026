from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def run_command(args: list[str], timeout: float = 30, env: dict[str, str] | None = None) -> CommandResult:
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=flags,
            env=env,
        )
        return CommandResult(result.returncode, result.stdout, result.stderr)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return CommandResult(124, out, err, True)


class AdbDevice:
    def __init__(self, adb_path: str, serial: str, timeout: int = 30):
        self.adb_path = adb_path
        self.serial = serial
        self.timeout = timeout

    def adb(self, *args: str, timeout: float | None = None) -> CommandResult:
        return run_command([self.adb_path, "-s", self.serial, *args], timeout or self.timeout)

    def shell(self, command: str, timeout: float | None = None) -> CommandResult:
        return self.adb("shell", command, timeout=timeout)

    def online(self) -> bool:
        result = self.adb("get-state", timeout=10)
        return result.returncode == 0 and result.stdout.strip() == "device"


def list_devices(adb_path: str) -> list[str]:
    result = run_command([adb_path, "devices"], timeout=15)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Cannot run adb devices")
    devices = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def resolve_package(apk: Path, adb_path: str, device: AdbDevice, packages_before: set[str]) -> str | None:
    candidates = [
        ["aapt", "dump", "badging", str(apk)],
        ["apkanalyzer", "manifest", "application-id", str(apk)],
    ]
    for command in candidates:
        result = run_command(command, timeout=30)
        if result.returncode != 0:
            continue
        text = result.stdout.strip()
        if command[0] == "aapt":
            for line in text.splitlines():
                if line.startswith("package: name='"):
                    return line.split("'", 2)[1]
        elif text:
            return text.splitlines()[0].strip()
    after = installed_third_party_packages(device)
    added = sorted(after - packages_before)
    return added[0] if len(added) == 1 else None


def installed_third_party_packages(device: AdbDevice) -> set[str]:
    result = device.shell("pm list packages -3")
    return {line.removeprefix("package:").strip() for line in result.stdout.splitlines() if line.strip()}

