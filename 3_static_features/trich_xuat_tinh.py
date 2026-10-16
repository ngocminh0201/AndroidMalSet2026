#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Trich xuat dac trung tinh APK + vector hoa ra CSV cho hoc may.

Gop hai buoc trich xuat tho (apk_static_extractor) va vector hoa (jsonl_to_ml_csv)
thanh mot lenh:
  - Doc danh sach kho APK tu D:\\LinkAPK.txt  (dang:  duong_dan | TenNguon)
  - Them cot source vao SQLite va CSV
  - Nen features_json bang zlib truoc khi ghi SQLite (giam ~10 lan)
  - Nap viec theo cua so truot, khong giu toan bo future trong RAM
  - Giu thanh tien trinh tqdm, in them 1 dong log cho moi APK
  - Vector hoa doc thang tu SQLite, khong can file JSONL trung gian
  - 10/09/2026: gop ten lop ve tien to goi, bo nhom method (GHI_CHU_SUA_CODE.md)

Chay:
    python trich_xuat_tinh.py                 # trich xuat + xuat CSV
    python trich_xuat_tinh.py --thu 20        # chay thu 20 mau
    python trich_xuat_tinh.py --chi-xuat-csv  # dung lai CSV tu SQLite
    python trich_xuat_tinh.py --lam-lai-loi   # chi chay lai cac mau bao loi

Ket qua trong .\\output\\ :
    dac_trung.sqlite         co so du lieu + diem dung (checkpoint)
    apk_ml_dataset.csv       ma tran dac trung cho hoc may
    feature_vocabulary.csv   tu vung dac trung kem tan suat tai lieu
    errors.log               chi tiet loi
    tong_ket_chay.txt        nhat ky tom tat moi lan chay (ghi noi tiep)
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import sqlite3
import sys
import time
import traceback
import zipfile
import zlib
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from tqdm import tqdm

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
except ImportError as exc:
    raise SystemExit(
        "Androguard is not installed.\n"
        "Run: py -m pip install androguard==4.1.4 tqdm==4.70.0"
    ) from exc


def tat_log_androguard() -> None:
    """Chan toan bo log DEBUG cua androguard.

    Androguard 4.x dung loguru chu khong dung logging chuan, nen chi ha muc
    logging.getLogger("androguard") la khong du - phai go het sink cua loguru.
    Ham nay chay o ca tien trinh cha lan tien trinh con.
    """
    try:
        from loguru import logger as _loguru_logger
        _loguru_logger.remove()
    except Exception:
        pass
    for _ten in ("androguard", "androguard.core", "androguard.core.apk",
                 "androguard.core.dex", "androguard.core.axml",
                 "androguard.core.api_specific_resources"):
        logging.getLogger(_ten).setLevel(logging.CRITICAL)
        logging.getLogger(_ten).propagate = False


tat_log_androguard()


# =====================================================================
# CAU HINH RIENG
# =====================================================================

LINK_FILE = r"D:\LinkAPK.txt"
OUTPUT_DIR = r".\output"
DB_NAME = "dac_trung.sqlite"
CSV_NAME = "apk_ml_dataset.csv"
VOCAB_NAME = "feature_vocabulary.csv"
JSONL_NAME = "apk_features.jsonl"
LOG_NAME = "errors.log"
TOM_TAT_NAME = "tong_ket_chay.txt"
# -----------------------------
# Configuration / indicators
# -----------------------------

URL_RE = re.compile(r"""(?i)\bhttps?://[^\s"'<>\\]+""")
DOMAIN_RE = re.compile(
    r"""(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b"""
)
IP_RE = re.compile(
    r"""(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"""
)

SUSPICIOUS_KEYWORDS = (
    "/system/bin/su",
    "/system/xbin/su",
    "busybox",
    "chmod",
    "chown",
    "mount",
    "pm install",
    "pm uninstall",
    "am start",
    "dexclassloader",
    "pathclassloader",
    "class.forname",
    "runtime.exec",
    "processbuilder",
    "setjavascriptinterface",
    "addjavascriptinterface",
    "loadlibrary",
    "system.load",
    "system.loadlibrary",
    "base64",
    "aes",
    "des",
    "rsa",
    "md5",
    "sha1",
    "sha256",
    "imei",
    "imsi",
    "android_id",
    "getdeviceid",
    "getsubscriberid",
    "sendtextmessage",
    "read_sms",
    "receive_sms",
    "accessibilityservice",
    "device_admin",
    "boot_completed",
)

SUSPICIOUS_API_PATTERNS = (
    "Landroid/telephony/SmsManager;->sendTextMessage",
    "Landroid/telephony/TelephonyManager;->getDeviceId",
    "Landroid/telephony/TelephonyManager;->getSubscriberId",
    "Landroid/location/LocationManager;",
    "Landroid/hardware/Camera;",
    "Landroid/media/MediaRecorder;",
    "Ljava/lang/Runtime;->exec",
    "Ljava/lang/ProcessBuilder;",
    "Ljava/lang/reflect/",
    "Ldalvik/system/DexClassLoader;",
    "Ldalvik/system/PathClassLoader;",
    "Landroid/webkit/WebView;->addJavascriptInterface",
    "Landroid/content/pm/PackageManager;",
)


# -----------------------------
# Utility functions
# -----------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_call(fn, default=None):
    try:
        value = fn()
        return default if value is None else value
    except Exception:
        return default


def normalize_list(values: Iterable[Any] | None) -> list[str]:
    if not values:
        return []
    result = []
    for x in values:
        if x is None:
            continue
        s = str(x)
        if s:
            result.append(s)
    return sorted(set(result))


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def valid_ipv4_candidates(text: str) -> set[str]:
    out: set[str] = set()
    for candidate in IP_RE.findall(text):
        try:
            ip = ipaddress.ip_address(candidate)
            if ip.version == 4:
                out.add(str(ip))
        except ValueError:
            pass
    return out


def get_instruction_name(ins: Any) -> str:
    try:
        return str(ins.get_name())
    except Exception:
        return ins.__class__.__name__


def get_method_descriptor(method: Any) -> str:
    """
    Build a stable Dalvik method descriptor where possible.
    """
    try:
        cls = str(method.get_class_name())
    except Exception:
        cls = ""
    try:
        name = str(method.get_name())
    except Exception:
        name = ""
    try:
        desc = str(method.get_descriptor())
    except Exception:
        desc = ""
    return f"{cls}->{name}{desc}"


def get_field_descriptor(field: Any) -> str:
    try:
        cls = str(field.get_class_name())
    except Exception:
        cls = ""
    try:
        name = str(field.get_name())
    except Exception:
        name = ""
    try:
        desc = str(field.get_descriptor())
    except Exception:
        desc = ""
    return f"{cls}->{name}:{desc}"


def get_certificates(apk: APK) -> dict[str, Any]:
    """
    Extract certificate SHA-256 fingerprints from v1/v2/v3/v3.1 where available.
    """
    cert_sets: dict[str, list[str]] = {
        "v1": [],
        "v2": [],
        "v3": [],
        "v31": [],
    }

    # v1 / JAR certificates
    try:
        for sig_name in apk.get_signature_names() or []:
            try:
                der = apk.get_certificate_der(sig_name)
                if der:
                    cert_sets["v1"].append(hashlib.sha256(der).hexdigest())
            except Exception:
                continue
    except Exception:
        pass

    # APK Signature Scheme v2/v3/v3.1
    for key, method_name in (
        ("v2", "get_certificates_der_v2"),
        ("v3", "get_certificates_der_v3"),
        ("v31", "get_certificates_der_v31"),
    ):
        method = getattr(apk, method_name, None)
        if callable(method):
            try:
                for der in method() or []:
                    if der:
                        cert_sets[key].append(hashlib.sha256(der).hexdigest())
            except Exception:
                pass

    for k, values in cert_sets.items():
        cert_sets[k] = sorted(set(values))

    return {
        "certificate_sha256": cert_sets,
        "is_signed_v1": bool(cert_sets["v1"]),
        "is_signed_v2": bool(cert_sets["v2"]),
        "is_signed_v3": bool(cert_sets["v3"] or cert_sets["v31"]),
    }


def parse_manifest_intents(apk: APK) -> list[str]:
    """
    Pull <action android:name="..."> values from AndroidManifest.xml.
    Uses Androguard's XML helper first, then falls back gracefully.
    """
    values: list[str] = []
    try:
        values = list(apk.get_all_attribute_value("action", "name"))
    except Exception:
        pass
    return normalize_list(values)


def parse_manifest_categories(apk: APK) -> list[str]:
    values: list[str] = []
    try:
        values = list(apk.get_all_attribute_value("category", "name"))
    except Exception:
        pass
    return normalize_list(values)


def parse_uses_features(apk: APK) -> list[str]:
    values: list[str] = []
    try:
        values = list(apk.get_all_attribute_value("uses-feature", "name"))
    except Exception:
        pass
    return normalize_list(values)


def count_zip_structure(path: Path) -> dict[str, Any]:
    counts = collections.Counter()
    compression_methods = collections.Counter()
    total_uncompressed = 0
    total_compressed = 0
    dex_names: list[str] = []
    native_libs: list[str] = []

    with zipfile.ZipFile(path, "r") as zf:
        infos = zf.infolist()
        for info in infos:
            name = info.filename
            low = name.lower()
            total_uncompressed += int(info.file_size)
            total_compressed += int(info.compress_size)
            compression_methods[str(info.compress_type)] += 1

            if low.endswith(".dex"):
                counts["dex"] += 1
                dex_names.append(name)
            elif low.endswith(".so"):
                counts["so"] += 1
                native_libs.append(name)
            elif low.endswith(".xml"):
                counts["xml"] += 1
            elif low.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif")):
                counts["image"] += 1
            elif low.startswith("assets/"):
                counts["asset"] += 1
            elif low.startswith("res/"):
                counts["resource"] += 1
            elif low.startswith("meta-inf/"):
                counts["meta_inf"] += 1

        return {
            "zip_entry_count": len(infos),
            "zip_uncompressed_bytes": total_uncompressed,
            "zip_compressed_bytes": total_compressed,
            "zip_compression_ratio": (
                round(total_compressed / total_uncompressed, 6)
                if total_uncompressed
                else None
            ),
            "zip_counts": dict(counts),
            "zip_compression_methods": dict(compression_methods),
            "dex_names": sorted(dex_names),
            "native_library_files": sorted(native_libs),
        }


def extract_dex_features(apk: APK) -> dict[str, Any]:
    """
    DEX extraction:
      - classes / methods / fields
      - unique strings
      - opcode frequency
      - method/API descriptors
      - suspicious API hits
      - URL/domain/IP/string indicators

    This avoids full cross-reference analysis, which keeps bulk extraction
    substantially lighter than AnalyzeAPK() for very large corpora.
    """
    class_names: set[str] = set()
    method_descriptors: set[str] = set()
    field_descriptors: set[str] = set()
    all_strings: set[str] = set()

    opcode_counts = collections.Counter()
    api_prefix_counts = collections.Counter()
    suspicious_api_hits = collections.Counter()

    total_methods = 0
    total_fields = 0
    total_instructions = 0
    dex_parsed = 0
    dex_failed = 0

    urls: set[str] = set()
    domains: set[str] = set()
    ips: set[str] = set()
    suspicious_string_hits = collections.Counter()

    for dex_bytes in apk.get_all_dex():
        try:
            d = DEX(dex_bytes)
            dex_parsed += 1
        except Exception:
            dex_failed += 1
            continue

        # Strings
        try:
            dex_strings = d.get_strings() or []
        except Exception:
            dex_strings = []

        for value in dex_strings:
            try:
                s = str(value)
            except Exception:
                continue
            all_strings.add(s)

            for u in URL_RE.findall(s):
                urls.add(u[:2048])

            for domain in DOMAIN_RE.findall(s):
                domains.add(domain.lower())

            ips.update(valid_ipv4_candidates(s))

            low = s.lower()
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in low:
                    suspicious_string_hits[keyword] += 1

        # Classes / methods / fields
        try:
            classes = d.get_classes() or []
        except Exception:
            classes = []

        for cls in classes:
            try:
                class_name = str(cls.get_name())
                class_names.add(class_name)
            except Exception:
                pass

            try:
                fields = cls.get_fields() or []
            except Exception:
                fields = []

            for field in fields:
                total_fields += 1
                fd = get_field_descriptor(field)
                if fd:
                    field_descriptors.add(fd)

            try:
                methods = cls.get_methods() or []
            except Exception:
                methods = []

            for method in methods:
                total_methods += 1
                md = get_method_descriptor(method)
                if md:
                    method_descriptors.add(md)

                    # Coarse API/package prefix counts
                    if md.startswith("Landroid/"):
                        api_prefix_counts["android"] += 1
                    elif md.startswith("Ljava/"):
                        api_prefix_counts["java"] += 1
                    elif md.startswith("Ljavax/"):
                        api_prefix_counts["javax"] += 1
                    elif md.startswith("Ldalvik/"):
                        api_prefix_counts["dalvik"] += 1
                    elif md.startswith("Lkotlin/"):
                        api_prefix_counts["kotlin"] += 1

                    low_md = md.lower()
                    for pattern in SUSPICIOUS_API_PATTERNS:
                        if pattern.lower() in low_md:
                            suspicious_api_hits[pattern] += 1

                try:
                    code = method.get_code()
                except Exception:
                    code = None

                if not code:
                    continue

                try:
                    bc = code.get_bc()
                    instructions = bc.get_instructions()
                except Exception:
                    continue

                try:
                    for ins in instructions:
                        name = get_instruction_name(ins)
                        opcode_counts[name] += 1
                        total_instructions += 1
                except Exception:
                    continue

    return {
        "dex_parsed_count": dex_parsed,
        "dex_failed_count": dex_failed,
        "class_count": len(class_names),
        "method_count": total_methods,
        "unique_method_count": len(method_descriptors),
        "field_count": total_fields,
        "unique_field_count": len(field_descriptors),
        "unique_string_count": len(all_strings),
        "instruction_count": total_instructions,
        "opcode_counts": dict(opcode_counts),
        "api_prefix_counts": dict(api_prefix_counts),
        "suspicious_api_hits": dict(suspicious_api_hits),
        "urls": sorted(urls),
        "domains": sorted(domains),
        "ipv4_addresses": sorted(ips),
        "suspicious_string_hits": dict(suspicious_string_hits),

        # These large vocabularies are deliberately retained so a later
        # vectorizer can build dataset-wide features.
        "classes": sorted(class_names),
        "methods": sorted(method_descriptors),

        # Full raw strings are NOT retained by default to avoid exploding
        # database size. Indicators above are retained instead.
    }


# =====================================================================
# DOC DANH SACH KHO APK TU LinkAPK.txt
# =====================================================================

def doc_link_file(link_file: Path) -> list[tuple[str, str, list[Path]]]:
    """Tra ve list (source, duong_dan_goc, [apk...])."""
    if not link_file.exists():
        raise SystemExit(f"[ERROR] Khong tim thay file link: {link_file}")

    nguon: list[tuple[str, str, list[Path]]] = []
    with link_file.open("r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip().strip('"')
            if not line or line.startswith("#"):
                continue

            label = None
            for sep in ("|", "\t", ";"):
                if sep in line:
                    trai, phai = line.split(sep, 1)
                    line, label = trai.strip().strip('"'), phai.strip()
                    break

            path = Path(os.path.normpath(line))
            source = label or str(path)

            if path.is_dir():
                apks = [p for p in path.rglob("*") if p.is_file() and p.suffix.lower() == ".apk"]
            elif path.is_file() and path.suffix.lower() == ".apk":
                apks = [path]
            else:
                print(f"[!] Bo qua (khong ton tai hoac khong phai APK): {path}")
                continue

            apks.sort(key=lambda p: p.name.lower())
            nguon.append((source, str(path), apks))
    return nguon


# =====================================================================
# TRICH XUAT 1 APK  (ban goc, chi them tham so source)
# =====================================================================

def extract_one(apk_path_str: str, source: str = "") -> dict[str, Any]:
    path = Path(apk_path_str)
    started = time.perf_counter()

    result: dict[str, Any] = {
        "file_name": path.name,
        "source": source,
        "full_path": str(path.resolve()),
        "status": "success",
        "error": None,
        "extracted_at_utc": utc_now_iso(),
    }

    try:
        stat = path.stat()
        result["file_size_bytes"] = stat.st_size
        result["sha256"] = sha256_file(path)

        # ZIP-level structure is useful even if manifest parsing later fails.
        result.update(count_zip_structure(path))

        apk = APK(str(path))

        # Basic APK / Manifest metadata
        result["package_name"] = safe_call(apk.get_package, "")
        result["app_name"] = safe_call(apk.get_app_name, "")
        result["version_code"] = safe_call(apk.get_androidversion_code, "")
        result["version_name"] = safe_call(apk.get_androidversion_name, "")
        result["min_sdk"] = safe_call(apk.get_min_sdk_version, "")
        result["target_sdk"] = safe_call(apk.get_target_sdk_version, "")
        result["max_sdk"] = safe_call(apk.get_max_sdk_version, "")
        result["effective_target_sdk"] = safe_call(
            apk.get_effective_target_sdk_version, None
        )

        result["permissions"] = normalize_list(safe_call(apk.get_permissions, []))
        result["activities"] = normalize_list(safe_call(apk.get_activities, []))
        result["services"] = normalize_list(safe_call(apk.get_services, []))
        result["receivers"] = normalize_list(safe_call(apk.get_receivers, []))
        result["providers"] = normalize_list(safe_call(apk.get_providers, []))
        result["intent_actions"] = parse_manifest_intents(apk)
        result["intent_categories"] = parse_manifest_categories(apk)
        result["uses_features"] = parse_uses_features(apk)

        result["is_debuggable"] = bool(
            safe_call(lambda: apk.get_attribute_value("application", "debuggable"), False)
            in (True, "true", "True", "1", 1)
        )
        result["allow_backup"] = safe_call(
            lambda: apk.get_attribute_value("application", "allowBackup"), None
        )

        result.update(get_certificates(apk))
        result.update(extract_dex_features(apk))

    except Exception as exc:
        result["status"] = "error"
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["traceback"] = traceback.format_exc(limit=15)

    result["elapsed_seconds"] = round(time.perf_counter() - started, 4)
    return result


# =====================================================================
# SQLITE  (giu bo cuc ban goc, them cot source, nen features_json)
# =====================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS apk_features (
    file_name TEXT PRIMARY KEY,
    source TEXT,
    full_path TEXT,
    status TEXT NOT NULL,
    sha256 TEXT,
    package_name TEXT,
    file_size_bytes INTEGER,
    elapsed_seconds REAL,
    extracted_at_utc TEXT,
    error TEXT,
    features_json BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_apk_features_status
ON apk_features(status);

CREATE INDEX IF NOT EXISTS idx_apk_features_sha256
ON apk_features(sha256);
"""


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    # Sua 15/09/2026: thay vi MEMORY. Voi 60.000 ban ghi, moi ban ghi keo theo
    # khoi dac trung nen ~376 KB, bat vung dem sap xep nam trong RAM la MemoryError.
    conn.execute("PRAGMA temp_store=FILE;")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def successful_file_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT file_name FROM apk_features WHERE status = 'success'"
    ).fetchall()
    return {row[0] for row in rows}


def error_file_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT file_name FROM apk_features WHERE status = 'error'"
    ).fetchall()
    return {row[0] for row in rows}


def nen(payload: str) -> bytes:
    return zlib.compress(payload.encode("utf-8"), 6)


def giai_nen(blob: Any) -> dict[str, Any]:
    if isinstance(blob, bytes):
        return json.loads(zlib.decompress(blob).decode("utf-8"))
    return json.loads(blob)          # phong khi co ban ghi cu chua nen


def save_result(conn: sqlite3.Connection, result: dict[str, Any]) -> None:
    payload = json.dumps(
        result,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )

    conn.execute(
        """
        INSERT INTO apk_features (
            file_name, source, full_path, status, sha256, package_name,
            file_size_bytes, elapsed_seconds, extracted_at_utc,
            error, features_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(file_name) DO UPDATE SET
            source=excluded.source,
            full_path=excluded.full_path,
            status=excluded.status,
            sha256=excluded.sha256,
            package_name=excluded.package_name,
            file_size_bytes=excluded.file_size_bytes,
            elapsed_seconds=excluded.elapsed_seconds,
            extracted_at_utc=excluded.extracted_at_utc,
            error=excluded.error,
            features_json=excluded.features_json
        """,
        (
            result.get("file_name"),
            result.get("source"),
            result.get("full_path"),
            result.get("status"),
            result.get("sha256"),
            result.get("package_name"),
            result.get("file_size_bytes"),
            result.get("elapsed_seconds"),
            result.get("extracted_at_utc"),
            result.get("error"),
            nen(payload),
        ),
    )
    conn.commit()


def duyet_ban_ghi(conn: sqlite3.Connection):
    """Sinh tung ban ghi thanh cong, doc cuon chieu tu SQLite."""
    # Khong ORDER BY: sap xep bat SQLite gom het ket qua vao vung dem truoc khi
    # tra ve dong dau tien, ma moi dong keo theo khoi nen ~376 KB -> 60.000 dong
    # la khoang 22 GB. Doc theo thu tu tu nhien thi chay cuon chieu, RAM khong doi.
    # Thu tu dong khong anh huong gi: luot 1 chi dem, luot 2 chi ghi ra CSV.
    cur = conn.execute(
        """
        SELECT features_json
        FROM apk_features
        WHERE status = 'success'
        """
    )
    for (blob,) in cur:
        try:
            yield giai_nen(blob)
        except Exception:
            continue


def dem_ban_ghi(conn: sqlite3.Connection) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM apk_features WHERE status='success'"
    ).fetchone()[0]


def export_jsonl(conn: sqlite3.Connection, output_path: Path) -> None:
    """Ghi ra JSONL. Thu tu dong theo thu tu trich xuat, khong theo ten file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for obj in duyet_ban_ghi(conn):
            f.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))
            f.write("\n")


# =====================================================================
# VECTOR HOA -> CSV  (giu nguyen cach chon tu vung ban goc)
# =====================================================================
SCALAR_FIELDS = [
    "file_size_bytes",
    "zip_entry_count",
    "zip_uncompressed_bytes",
    "zip_compressed_bytes",
    "zip_compression_ratio",
    "effective_target_sdk",
    "is_debuggable",
    "is_signed_v1",
    "is_signed_v2",
    "is_signed_v3",
    "dex_parsed_count",
    "dex_failed_count",
    "class_count",
    "method_count",
    "unique_method_count",
    "field_count",
    "unique_field_count",
    "unique_string_count",
    "instruction_count",
]

# SDK values are sometimes strings in raw extraction, so coerce them.
SDK_FIELDS = ["min_sdk", "target_sdk", "max_sdk"]

# List-valued features converted to binary presence columns.
BINARY_LIST_GROUPS = {
    "perm": "permissions",
    "intent_action": "intent_actions",
    "intent_category": "intent_categories",
    "uses_feature": "uses_features",
    "class": "classes",
    "method": "methods",
    "domain": "domains",
    "ip": "ipv4_addresses",
}

# Dict-valued features converted to count columns.
COUNT_DICT_GROUPS = {
    "opcode": "opcode_counts",
    "api_prefix": "api_prefix_counts",
    "susp_api": "suspicious_api_hits",
    "susp_string": "suspicious_string_hits",
    "zip_count": "zip_counts",
    "zip_comp": "zip_compression_methods",
}

# Components are represented by COUNTS, not individual app-specific names.
COMPONENT_COUNT_FIELDS = {
    "activity_count": "activities",
    "service_count": "services",
    "receiver_count": "receivers",
    "provider_count": "providers",
    "url_count": "urls",
    "native_library_count": "native_library_files",
    "permission_count": "permissions",
    "intent_action_count": "intent_actions",
    "intent_category_count": "intent_categories",
    "uses_feature_count": "uses_features",
}


def safe_numeric(v: Any) -> float | int:
    if v is None or v == "":
        return 0
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)):
        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            return 0
        return v
    try:
        s = str(v).strip()
        if not s:
            return 0
        return float(s) if "." in s else int(s)
    except Exception:
        return 0


def sanitize_feature_value(value: Any) -> str:
    # Preserve meaning while making column names CSV/model friendly.
    s = str(value)
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return s


def feature_key(prefix: str, value: Any) -> str:
    return f"{prefix}::{sanitize_feature_value(value)}"


# --- Sua 10/09/2026: xem GHI_CHU_SUA_CODE.md ---------------------------------
# CAP_GOI    : gop ten lop ve tien to goi N cap (0 = giu nguyen ten lop nhu goc)
# GIU_METHOD : co dua danh sach phuong thuc vao dac trung hay khong (goc la co)
# Hai bien nay duoc gan lai trong main() theo tham so dong lenh.
CAP_GOI = 3
GIU_METHOD = False
LOC_DOMAIN = True   # chi giu ten mien that, gop ve ten mien goc

# Duoi ten mien thuc su, co y bo cac duoi de trung voi dinh danh Java:
#   .io .me .app .dev .is .it .at .be .in .to
#   .int .name .icu .id .info  (do thuc te 13/09: kotlin.int, vm.name,
#   icu.icu, display.id, log.info deu lot qua neu giu 5 duoi nay)
TLD_THAT = {
    "com", "net", "org", "biz", "pro", "mobi", "asia", "tv",
    "xyz", "top", "club", "online", "site", "shop", "store", "vip",
    "live", "fun", "space", "website", "tech", "cloud", "link", "click",
    "work", "world", "today", "life", "pw", "su", "cyou", "monster", "quest",
    "tk", "ml", "ga", "cf", "gq",
    "ru", "cn", "jp", "kr", "vn", "th", "ph", "tw", "hk", "sg", "my",
    "uk", "de", "fr", "it", "es", "nl", "pl", "se", "no", "fi", "dk", "cz",
    "ua", "by", "kz", "tr", "ir", "il", "sa", "ae", "eg", "za", "ng", "ke",
    "us", "ca", "mx", "br", "ar", "cl", "co", "pe", "au", "nz", "gov",
}
# Nhung duoi cap hai kieu .co.uk, .com.vn
DUOI_HAI_CAP = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go"}


def tien_to_goi(ten_lop: str, cap: int) -> str:
    """Lcom/qihoo/util/AppCls;  ->  Lcom/qihoo/util/"""
    s = ten_lop[:-1] if ten_lop.endswith(";") else ten_lop
    phan = s.split("/")
    if len(phan) <= 1:
        return ten_lop
    goi = phan[:-1]                 # bo ten lop o cuoi
    if cap > 0:
        goi = goi[:cap]
    return "/".join(goi) + "/"


def host_tu_url(u: str) -> str:
    """http://abc.evil.com:8080/x?y  ->  abc.evil.com"""
    s = str(u).split("://", 1)[-1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    s = s.rsplit("@", 1)[-1]
    return s.split(":", 1)[0]


def ten_mien_goc(host: str) -> str | None:
    """abc.evil.com -> evil.com ; androidx.core.app -> None (khong phai ten mien)"""
    h = str(host).strip(".").lower()
    if not h or " " in h:
        return None
    phan = h.split(".")
    if len(phan) < 2 or phan[-1] not in TLD_THAT:
        return None
    if len(phan) >= 3 and phan[-2] in DUOI_HAI_CAP:
        return ".".join(phan[-3:])
    return ".".join(phan[-2:])


def gom_ten_mien(obj: dict[str, Any]) -> set[str]:
    """Ten mien that, lay tu URL (chac chan nhat) va tu danh sach domain co duoi hop le."""
    ra: set[str] = set()
    for u in obj.get("urls") or []:
        g = ten_mien_goc(host_tu_url(u))
        if g:
            ra.add(g)
    for d in obj.get("domains") or []:
        g = ten_mien_goc(d)
        if g:
            ra.add(g)
    return ra


def sinh_dac_trung_nhi_phan(obj: dict[str, Any]):
    """Sinh cac cap (tien_to, gia_tri) cho nhom dac trung nhi phan.

    Dung chung cho ca luot dem tu vung lan luot ghi CSV, de hai buoc khong
    bao gio lech nhau.
    """
    for prefix, source in BINARY_LIST_GROUPS.items():
        if prefix == "method" and not GIU_METHOD:
            continue
        if prefix == "domain" and LOC_DOMAIN:
            for v in gom_ten_mien(obj):
                yield "domain", v
            continue
        values = obj.get(source) or []
        if prefix == "class" and CAP_GOI > 0:
            for v in {tien_to_goi(str(x), CAP_GOI) for x in values}:
                yield "class_pkg", v
        else:
            for v in values:
                yield prefix, v
def collect_present_features(obj: dict[str, Any]) -> set[str]:
    """
    Feature presence for document-frequency calculation.
    Counts each feature at most once per APK.
    """
    present: set[str] = set()

    for prefix, value in sinh_dac_trung_nhi_phan(obj):
        present.add(feature_key(prefix, value))

    for prefix, source in COUNT_DICT_GROUPS.items():
        values = obj.get(source) or {}
        if isinstance(values, dict):
            for key, count in values.items():
                if safe_numeric(count) != 0:
                    present.add(feature_key(prefix, key))

    return present
def write_vocab(
    path: Path,
    vocab: list[str],
    df: dict[str, int],
    n_samples: int,
) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["feature", "document_frequency", "document_frequency_ratio"])
        for feature in vocab:
            freq = df[feature]
            writer.writerow([feature, freq, freq / n_samples if n_samples else 0])


def build_vocab(
    conn: sqlite3.Connection,
    tong: int,
    min_df: int,
    max_df_ratio: float,
    max_features: int,
) -> tuple[list[str], dict[str, int], int, int]:

    df = collections.Counter()
    n_samples = 0

    bar = tqdm(total=tong, desc="Luot 1/2: tu vung", unit="APK",
               dynamic_ncols=True, file=sys.stdout)
    for obj in duyet_ban_ghi(conn):
        bar.update(1)
        n_samples += 1
        df.update(collect_present_features(obj))
    bar.close()

    tong_khac_nhau = len(df)
    max_df = max(1, int(n_samples * max_df_ratio))

    selected = [
        (feat, freq)
        for feat, freq in df.items()
        if freq >= min_df and freq <= max_df
    ]

    # Highest document frequency first; name is tie-breaker for reproducibility.
    selected.sort(key=lambda x: (-x[1], x[0]))

    if max_features > 0:
        selected = selected[:max_features]

    vocab = [feat for feat, _ in selected]
    selected_df = {feat: freq for feat, freq in selected}
    print(f"    So dac trung khac nhau da dem: {tong_khac_nhau:,} "
          f"-> giu lai {len(vocab):,}")
    return vocab, selected_df, n_samples, tong_khac_nhau


def make_row(obj: dict[str, Any], vocab_set: set[str]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "file_name": obj.get("file_name", ""),
        "source": obj.get("source", ""),
        "sha256": obj.get("sha256", ""),
    }

    for field in SCALAR_FIELDS:
        row[field] = safe_numeric(obj.get(field))

    for field in SDK_FIELDS:
        row[field] = safe_numeric(obj.get(field))

    for out_name, source in COMPONENT_COUNT_FIELDS.items():
        values = obj.get(source) or []
        row[out_name] = len(values) if isinstance(values, list) else 0

    # Binary feature groups
    for prefix, value in sinh_dac_trung_nhi_phan(obj):
        key = feature_key(prefix, value)
        if key in vocab_set:
            row[key] = 1

    # Count feature groups
    for prefix, source in COUNT_DICT_GROUPS.items():
        values = obj.get(source) or {}
        if isinstance(values, dict):
            for key0, count in values.items():
                key = feature_key(prefix, key0)
                if key in vocab_set:
                    row[key] = safe_numeric(count)

    return row


def xuat_csv(
    conn: sqlite3.Connection,
    csv_path: Path,
    vocab_path: Path,
    min_df: int,
    max_df_ratio: float,
    max_features: int,
    nhat_ky: Path,
) -> None:
    tong = dem_ban_ghi(conn)
    if tong == 0:
        print("[!] Chua co ban ghi thanh cong nao trong SQLite, bo qua buoc xuat CSV.")
        return

    in_va_ghi([
        "",
        "=" * 72,
        "VECTOR HOA -> CSV",
        "=" * 72,
        f"Mau            : {tong:,}",
        f"Min DF         : {min_df}",
        f"Max DF ratio   : {max_df_ratio}",
        f"Max tu vung    : {'khong gioi han' if max_features <= 0 else f'{max_features:,}'}",
        f"Nhom class     : {'giu nguyen ten lop' if CAP_GOI == 0 else f'gop ve tien to goi {CAP_GOI} cap'}",
        f"Nhom method    : {'co dua vao dac trung' if GIU_METHOD else 'bo (xem GHI_CHU_SUA_CODE.md)'}",
        f"Nhom domain    : {'giu chuoi tho' if not LOC_DOMAIN else 'chi ten mien that, gop ve ten mien goc'}",
        "=" * 72,
    ], nhat_ky)

    started = time.perf_counter()
    vocab, df, n_samples, tong_khac_nhau = build_vocab(
        conn, tong, min_df, max_df_ratio, max_features)
    write_vocab(vocab_path, vocab, df, n_samples)

    numeric_columns = SCALAR_FIELDS + SDK_FIELDS + list(COMPONENT_COUNT_FIELDS.keys())
    columns = ["file_name", "source", "sha256"] + numeric_columns + vocab
    vocab_set = set(vocab)

    csv_path.parent.mkdir(parents=True, exist_ok=True)
    processed = 0

    with csv_path.open("w", encoding="utf-8-sig", newline="") as fout:
        writer = csv.DictWriter(fout, fieldnames=columns, extrasaction="ignore", restval=0)
        writer.writeheader()

        bar = tqdm(total=tong, desc="Luot 2/2: CSV", unit="APK",
                   dynamic_ncols=True, file=sys.stdout)
        for obj in duyet_ban_ghi(conn):
            bar.update(1)
            writer.writerow(make_row(obj, vocab_set))
            processed += 1
        bar.close()

    elapsed = time.perf_counter() - started
    in_va_ghi([
        "",
        "=" * 72,
        "XONG PHAN CSV",
        "=" * 72,
        f"Mau            : {processed:,}",
        f"Dac trung da dem: {tong_khac_nhau:,}",
        f"Dac trung ML   : {len(numeric_columns) + len(vocab):,}",
        f"Tu vung        : {len(vocab):,}",
        f"Cot CSV        : {len(columns):,}",
        f"Thoi gian      : {elapsed:,.1f} s",
        f"Dataset        : {csv_path.resolve()}",
        f"Tu vung        : {vocab_path.resolve()}",
        "=" * 72,
    ], nhat_ky)


# =====================================================================
# CHAY
# =====================================================================

def configure_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=log_path,
        level=logging.ERROR,
        format="%(asctime)s | %(levelname)s | %(message)s",
        encoding="utf-8",
    )
    tat_log_androguard()


def in_va_ghi(dong: list[str], nhat_ky: Path) -> None:
    """In ra man hinh, dong thoi ghi noi vao file nhat ky de sau con doi chieu."""
    van_ban = "\n".join(dong)
    print(van_ban)
    try:
        nhat_ky.parent.mkdir(parents=True, exist_ok=True)
        with nhat_ky.open("a", encoding="utf-8") as f:
            f.write(van_ban + "\n")
    except Exception as exc:
        print(f"[!] Khong ghi duoc nhat ky: {exc}")


def fmt_time(giay: float) -> str:
    giay = int(giay)
    h, du = divmod(giay, 3600)
    m, s = divmod(du, 60)
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def trich_xuat_tat_ca(conn: sqlite3.Connection, args, log_path: Path,
                      nhat_ky: Path) -> None:
    nguon = doc_link_file(Path(args.link))

    tat_ca: list[tuple[str, Path]] = []
    dau = [
        "",
        "=" * 72,
        f"TRICH XUAT DAC TRUNG TINH   -   {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
        "=" * 72,
    ]
    for source, goc, apks in nguon:
        dau.append(f"  {source:<20} {len(apks):>7,} APK   ({goc})")
        tat_ca.extend((source, p) for p in apks)

    if not tat_ca:
        dau.append("[!] Khong tim thay APK nao.")
        in_va_ghi(dau, nhat_ky)
        return

    if args.lam_lai_loi:
        can_chay = error_file_names(conn)
        pending = [t for t in tat_ca if t[1].name in can_chay]
    else:
        da_xong = successful_file_names(conn)
        pending = [t for t in tat_ca if t[1].name not in da_xong]

    # cung mot ten file o hai kho -> coi la mot mau (dung y do ban goc)
    da_thay: set[str] = set()
    loc: list[tuple[str, Path]] = []
    for source, p in pending:
        if p.name in da_thay:
            continue
        da_thay.add(p.name)
        loc.append((source, p))
    pending = loc

    if args.thu > 0:
        pending = pending[: args.thu]

    workers = max(1, args.workers)
    dau += [
        f"  {'Tong APK':<20} {len(tat_ca):>7,}",
        f"  {'Can xu ly':<20} {len(pending):>7,}",
        f"  {'Worker':<20} {workers:>7}",
        f"  {'CSDL':<20} {conn.execute('PRAGMA database_list').fetchone()[2]}",
        "=" * 72,
    ]
    in_va_ghi(dau, nhat_ky)

    if not pending:
        in_va_ghi(["Khong con APK nao can trich xuat."], nhat_ky)
        return

    tong = len(pending)
    ok_count = 0
    err_count = 0
    tong_worker_time = 0.0
    bat_dau = time.perf_counter()
    stt = 0

    def xu_ly(result: dict[str, Any]) -> None:
        nonlocal ok_count, err_count, tong_worker_time, stt

        save_result(conn, result)
        stt += 1
        elapsed = float(result.get("elapsed_seconds") or 0.0)
        tong_worker_time += elapsed

        if result.get("status") == "success":
            ok_count += 1
            trang_thai = "OK  "
        else:
            err_count += 1
            trang_thai = "FAIL"
            logging.error(
                f"{result.get('file_name')} | {result.get('error')}\n"
                f"{result.get('traceback', '')}"
            )

        eta = (time.perf_counter() - bat_dau) / stt * (tong - stt)
        ten = result.get("file_name", "")
        ngan = ten if len(ten) <= 26 else ten[:11] + "..." + ten[-11:]
        src = result.get("source", "") or ""
        src = src if len(src) <= 12 else "..." + src[-9:]
        print(
            f"[{stt}/{tong}] {trang_thai} {src:<12} {ngan:<26} "
            f"{elapsed:6.1f}s  ETA {fmt_time(eta)}",
            flush=True,
        )

    try:
        if workers == 1:
            for source, path in pending:
                xu_ly(extract_one(str(path), source))
        else:
            # Chi tien trinh cha ghi SQLite -> khong tranh chap tren Windows.
            # Nap viec theo cua so truot de khong giu moi ket qua trong RAM.

            def chay_luot(danh_sach, so_worker, cua_so):
                """Chay mot luot. Tra ve (da_xong, pool_co_vo, dang_chay_luc_vo)."""
                da_xong: set[str] = set()
                pool_vo = False
                con_treo: list[tuple[str, Path]] = []
                hang_doi = iter(danh_sach)
                dang_chay: dict[Any, tuple[str, Path]] = {}
                try:
                    with ProcessPoolExecutor(max_workers=so_worker,
                                             initializer=tat_log_androguard) as executor:
                        for _ in range(cua_so):
                            viec = next(hang_doi, None)
                            if viec is None:
                                break
                            dang_chay[executor.submit(
                                extract_one, str(viec[1]), viec[0])] = viec

                        while dang_chay:
                            xong, _ = wait(list(dang_chay), return_when=FIRST_COMPLETED)
                            for future in xong:
                                source, path = dang_chay[future]
                                try:
                                    result = future.result()
                                except BrokenProcessPool:
                                    # giu future trong dang_chay de con quy duoc
                                    # trach nhiem cho dung mau nay
                                    raise
                                except Exception as exc:
                                    result = {
                                        "file_name": path.name,
                                        "source": source,
                                        "full_path": str(path.resolve()),
                                        "status": "error",
                                        "sha256": None,
                                        "package_name": None,
                                        "file_size_bytes": safe_call(
                                            lambda: path.stat().st_size, None),
                                        "elapsed_seconds": 0.0,
                                        "extracted_at_utc": utc_now_iso(),
                                        "error": f"WorkerError: {type(exc).__name__}: {exc}",
                                        "traceback": traceback.format_exc(limit=15),
                                    }
                                dang_chay.pop(future)
                                del future   # nha ket qua ngay, khong don trong RAM
                                xu_ly(result)
                                da_xong.add(str(path))

                                viec = next(hang_doi, None)
                                if viec is not None:
                                    dang_chay[executor.submit(
                                        extract_one, str(viec[1]), viec[0])] = viec
                except BrokenProcessPool as exc:
                    pool_vo = True
                    con_treo = [v for v in dang_chay.values()
                                if str(v[1]) not in da_xong]
                    logging.error(f"BrokenProcessPool: {exc}")
                return da_xong, pool_vo, con_treo

            def ghi_mau_doc(source, path):
                xu_ly({
                    "file_name": path.name,
                    "source": source,
                    "full_path": str(path.resolve()),
                    "status": "error",
                    "sha256": None,
                    "package_name": None,
                    "file_size_bytes": safe_call(lambda: path.stat().st_size, None),
                    "elapsed_seconds": 0.0,
                    "extracted_at_utc": utc_now_iso(),
                    "error": "WorkerKilled: tien trinh con bi giet khi xu ly rieng mau nay",
                    "traceback": "",
                })

            chua_lam = list(pending)
            so_lan_vo = 0

            while chua_lam:
                da_xong, pool_vo, con_treo = chay_luot(chua_lam, workers, workers * 4)
                chua_lam = [t for t in chua_lam if str(t[1]) not in da_xong]
                if not pool_vo:
                    break

                so_lan_vo += 1
                print(f"\n[!] Mot tien trinh con bi giet dot ngot (lan {so_lan_vo}). "
                      f"Nghi 15 giay, sau do do tung mau mot de tim mau gay loi.\n",
                      flush=True)
                if so_lan_vo >= 20:
                    print("[X] Pool vo qua 20 lan, dung han. "
                          "Kiem tra RAM, o dia hoac phan mem diet virus.", flush=True)
                    break
                time.sleep(15)

                # Do tung mau mot (1 worker, cua so 1) trong so cac mau dang chay
                # luc pool vo, de quy trach nhiem dung mau gay loi thay vi
                # do oan ca lo dang chay song song.
                nghi = [t for t in con_treo if str(t[1]) not in da_xong]
                while nghi:
                    dx, vo2, treo2 = chay_luot(nghi, 1, 1)
                    chua_lam = [t for t in chua_lam if str(t[1]) not in dx]
                    nghi = [t for t in nghi if str(t[1]) not in dx]
                    if not vo2:
                        break
                    if not treo2:
                        break
                    doc_source, doc_path = treo2[0]
                    ghi_mau_doc(doc_source, doc_path)
                    chua_lam = [t for t in chua_lam if str(t[1]) != str(doc_path)]
                    nghi = [t for t in nghi if str(t[1]) != str(doc_path)]

    except KeyboardInterrupt:
        print("\nDa dung. Nhung mau xong truoc do da luu trong SQLite.")

    wall = time.perf_counter() - bat_dau
    da_lam = ok_count + err_count

    tom_tat = [
        "",
        "=" * 72,
        f"TONG KET TRICH XUAT   -   {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
        "=" * 72,
        f"Da xu ly       : {da_lam:,}",
        f"Thanh cong     : {ok_count:,}",
        f"Loi            : {err_count:,}",
        f"Thoi gian      : {wall:,.1f} s ({fmt_time(wall)})",
    ]
    if wall > 0:
        tom_tat.append(f"Thong luong    : {da_lam / wall * 3600:,.1f} APK/gio")
    if da_lam > 0:
        tom_tat.append(f"TB moi APK     : {tong_worker_time / da_lam:,.2f} s")
    if err_count:
        tom_tat.append(f"Nhat ky loi    : {log_path.resolve()}")
    tom_tat.append("=" * 72)
    in_va_ghi(tom_tat, nhat_ky)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trich xuat dac trung tinh APK va xuat CSV cho hoc may."
    )
    p.add_argument("--link", default=LINK_FILE,
                   help=f"File danh sach kho APK. Mac dinh: {LINK_FILE}")
    p.add_argument("--output", default=OUTPUT_DIR,
                   help=f"Thu muc ket qua. Mac dinh: {OUTPUT_DIR}")
    p.add_argument("--workers", type=int, default=3,
                   help="So tien trinh chay song song. Mac dinh: 3")
    p.add_argument("--thu", type=int, default=0,
                   help="Chi chay thu N mau dau tien roi dung. Mac dinh: 0 (chay het)")
    p.add_argument("--chi-trich-xuat", action="store_true",
                   help="Chi trich xuat, khong xuat CSV.")
    p.add_argument("--chi-xuat-csv", action="store_true",
                   help="Khong trich xuat, chi dung lai CSV tu SQLite.")
    p.add_argument("--lam-lai-loi", action="store_true",
                   help="Chi chay lai nhung mau dang o trang thai loi.")
    p.add_argument("--xuat-jsonl", action="store_true",
                   help="Xuat them file JSONL (dung lai dau ra ban goc).")
    p.add_argument("--min-df", type=int, default=2,
                   help="Dac trung phai xuat hien trong it nhat N APK. Mac dinh: 2")
    p.add_argument("--max-df-ratio", type=float, default=1.0,
                   help="Bo dac trung xuat hien qua ti le nay. Mac dinh: 1.0")
    p.add_argument("--cap-goi", type=int, default=3,
                   help="Gop ten lop ve tien to goi N cap; 0 = giu nguyen ten lop. Mac dinh: 3")
    p.add_argument("--giu-domain-tho", action="store_true",
                   help="Giu nguyen chuoi domain tho nhu ban goc (lan nhieu dinh danh Java).")
    p.add_argument("--db", default=None,
                   help="Duong dan file SQLite. Mac dinh: <output>\\dac_trung.sqlite")
    p.add_argument("--giu-method", action="store_true",
                   help="Dua ca danh sach phuong thuc vao dac trung (nhu ban goc, rat ton RAM).")
    p.add_argument("--max-features", type=int, default=20000,
                   help="Kich thuoc tu vung toi da; <=0 la khong gioi han. Mac dinh: 20000")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.min_df < 1:
        raise SystemExit("--min-df phai >= 1")
    if not (0 < args.max_df_ratio <= 1):
        raise SystemExit("--max-df-ratio phai nam trong khoang (0, 1]")

    global CAP_GOI, GIU_METHOD, LOC_DOMAIN
    CAP_GOI = max(0, args.cap_goi)
    GIU_METHOD = bool(args.giu_method)
    LOC_DOMAIN = not bool(args.giu_domain_tho)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / LOG_NAME
    nhat_ky = output_dir / TOM_TAT_NAME
    configure_logging(log_path)

    db_path = Path(args.db) if args.db else output_dir / DB_NAME
    conn = init_db(db_path)

    try:
        if not args.chi_xuat_csv:
            trich_xuat_tat_ca(conn, args, log_path, nhat_ky)

        if args.xuat_jsonl:
            export_jsonl(conn, output_dir / JSONL_NAME)
            print(f"JSONL          : {(output_dir / JSONL_NAME).resolve()}")

        if not args.chi_trich_xuat:
            xuat_csv(
                conn,
                output_dir / CSV_NAME,
                output_dir / VOCAB_NAME,
                args.min_df,
                args.max_df_ratio,
                args.max_features,
                nhat_ky,
            )
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    # Bat buoc cho multiprocessing tren Windows.
    raise SystemExit(main())
