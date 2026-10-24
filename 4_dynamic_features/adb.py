from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


def _version_key(name: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", name))


def find_android_sdk() -> Path | None:
    """Locate the Android SDK that Android Studio installed (it is not added to PATH)."""
    candidates = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")]
    if os.environ.get("LOCALAPPDATA"):
        candidates.append(str(Path(os.environ["LOCALAPPDATA"]) / "Android" / "Sdk"))
    home = Path.home()
    candidates += [
        str(home / "AppData" / "Local" / "Android" / "Sdk"),
        str(home / "Android" / "Sdk"),
        str(home / "Library" / "Android" / "sdk"),
    ]
    for candidate in candidates:
        if candidate and (Path(candidate) / "platform-tools").is_dir():
            return Path(candidate)
    return None


def latest_build_tools(sdk: Path) -> Path | None:
    root = sdk / "build-tools"
    if not root.is_dir():
        return None
    versions = [d for d in root.iterdir() if d.is_dir()]
    return max(versions, key=lambda d: _version_key(d.name)) if versions else None


def setup_sdk_path() -> Path | None:
    """Prepend platform-tools (adb), newest build-tools (aapt) and emulator to PATH for this process."""
    sdk = find_android_sdk()
    if not sdk:
        return None
    current = os.environ.get("PATH", "").split(os.pathsep)
    extra = [sdk / "platform-tools", latest_build_tools(sdk), sdk / "emulator"]
    add = [str(p) for p in extra if p and p.is_dir() and str(p) not in current]
    if add:
        os.environ["PATH"] = os.pathsep.join(add + current)
    os.environ.setdefault("ANDROID_HOME", str(sdk))
    return sdk


ANDROID_SDK = setup_sdk_path()


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
    except OSError as exc:
        # Program not found / not executable: report it instead of killing the caller's thread.
        return CommandResult(127, "", f"Không chạy được '{args[0]}': {exc}")


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


def emulator_exe() -> str | None:
    if ANDROID_SDK:
        for name in ("emulator.exe", "emulator"):
            path = ANDROID_SDK / "emulator" / name
            if path.is_file():
                return str(path)
    return shutil.which("emulator")


def list_avds() -> list[str]:
    """AVD names created in Android Studio's Device Manager."""
    exe = emulator_exe()
    if not exe:
        return []
    result = run_command([exe, "-list-avds"], timeout=30)
    # Newer emulator builds may also print "INFO | ..." lines; AVD names have no spaces.
    return [line.strip() for line in result.stdout.splitlines() if re.fullmatch(r"[A-Za-z0-9._-]+", line.strip())]


def start_emulator(avd: str, clean: bool = True) -> subprocess.Popen:
    """Launch an AVD in its own window. clean=True discards changes on shutdown (-no-snapshot-save)."""
    exe = emulator_exe()
    if not exe:
        raise RuntimeError("Không tìm thấy emulator trong Android SDK")
    args = [exe, "-avd", avd]
    if clean:
        args.append("-no-snapshot-save")
    flags = (subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS) if os.name == "nt" else 0
    return subprocess.Popen(
        args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=flags, close_fds=True,
    )


def avd_name(adb_path: str, serial: str) -> str:
    result = run_command([adb_path, "-s", serial, "emu", "avd", "name"], timeout=10)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip() and line.strip() != "OK"]
    return lines[0] if result.returncode == 0 and lines else ""


def boot_completed(adb_path: str, serial: str) -> bool:
    result = run_command([adb_path, "-s", serial, "shell", "getprop", "sys.boot_completed"], timeout=10)
    return result.returncode == 0 and result.stdout.strip() == "1"


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

