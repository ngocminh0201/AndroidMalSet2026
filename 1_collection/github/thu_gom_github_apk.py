# -*- coding: utf-8 -*-
"""
Thu gom APK tu cac kho GitHub, loc theo moc thoi gian, khu trung lap theo SHA-256.

Chay trong may ao. Mau tai ve la ma doc song.

Script KHONG gan nhan. Cot nhan trong manifest de trong, cho buoc quet VirusTotal.
Cot Duong_dan giu lai vi tri file trong kho goc de tra nguoc khi can.

Can: git, python 3, va hai goi  pip install openpyxl pyzipper
pyzipper dung de doc cac file nen WinZip AES ma module zipfile chuan khong mo duoc.

Cu phap:
    python thu_gom_github_apk.py --danh-sach nguon_github.csv --dich D:\\APK_GitHub
    python thu_gom_github_apk.py --danh-sach nguon_github.csv --dich D:\\APK_GitHub ^
        --manifest D:\\DuAnCapToc\\Thu_thap_APK\\Manifest_thu_thap_APK.xlsx --nam-toi-thieu 2020

Ket qua:
    <dich>/apk/<sha256>.apk        cac mau hop le, da khu trung lap
    <dich>/Ket_qua_thu_gom.xlsx    ghi noi them, ba sheet: Mau_thu_duoc,
                                   File_bi_loai, Tong_hop_theo_kho
"""

import argparse
import datetime
import hashlib
import os
import re
import shutil
import subprocess
import sys
import zipfile

import ghi_ket_qua
from ghi_ket_qua import COT_BQ, COT_KQ

MAT_KHAU_NEN = [b"infected", b"infected!", b"malware"]
DUOI_NEN = (".zip", ".7z", ".rar", ".gz", ".tar", ".tgz")


def sha256_file(duong_dan):
    h = hashlib.sha256()
    with open(duong_dan, "rb") as f:
        for khoi in iter(lambda: f.read(1024 * 1024), b""):
            h.update(khoi)
    return h.hexdigest()


def la_apk(duong_dan):
    """Nhan dien APK theo noi dung: ZIP hop le co chua AndroidManifest.xml.
    Khong dua vao duoi ten file, vi nhieu kho dat ten theo hash."""
    try:
        if os.path.getsize(duong_dan) < 4096:
            return False
        with open(duong_dan, "rb") as f:
            if f.read(2) != b"PK":
                return False
        with zipfile.ZipFile(duong_dan) as z:
            ten = z.namelist()
            return "AndroidManifest.xml" in ten and any(
                t.startswith("classes") and t.endswith(".dex") for t in ten
            )
    except Exception:
        return False


def moc_thoi_gian_apk(duong_dan):
    """Tra ve (nam_lon_nhat, nam_cua_classes_dex). Moc lay tu timestamp cua cac
    entry ben trong file APK. Voi phan lon mau, moc cua classes.dex phan anh
    thoi diem build. Day la bang chung yeu hon first_submission_date cua
    VirusTotal, dung de sang loc so bo."""
    nam_max, nam_dex = 0, 0
    try:
        with zipfile.ZipFile(duong_dan) as z:
            for info in z.infolist():
                nam = info.date_time[0]
                if nam > nam_max:
                    nam_max = nam
                if info.filename == "classes.dex":
                    nam_dex = nam
    except Exception:
        pass
    return nam_max, nam_dex


def target_sdk(duong_dan):
    """Doc targetSdkVersion neu co androguard. Google bat buoc target API 30 tu
    8/2021 va API 33 tu 8/2023, nen gia tri nay chan duoi duoc nam build."""
    try:
        from androguard.core.bytecodes.apk import APK
        return int(APK(duong_dan).get_target_sdk_version() or 0)
    except Exception:
        return 0


def giai_nen(duong_dan, thu_muc_ra):
    """Giai nen file, thu lan luot cac mat khau thuong gap.

    Nhieu kho nen bang WinZip AES (compress_type 99). Module zipfile cua Python
    khong doc duoc kieu nay, no bao NotImplementedError, nen phai chuyen sang
    pyzipper hoac 7-Zip. Toan bo 58 file cua sk3ptre/AndroidMalware_2021 va 14
    file cua ban 2020 thuoc dien nay."""
    os.makedirs(thu_muc_ra, exist_ok=True)
    duoi = duong_dan.lower()

    if duoi.endswith(".zip"):
        aes = False
        for mk in [None] + MAT_KHAU_NEN:
            try:
                with zipfile.ZipFile(duong_dan) as z:
                    z.extractall(thu_muc_ra, pwd=mk)
                return True
            except NotImplementedError:
                aes = True
                break
            except Exception:
                continue

        if aes:
            try:
                import pyzipper
            except ImportError:
                print("  can pyzipper de doc file nen AES. Chay: pip install pyzipper")
            else:
                for mk in MAT_KHAU_NEN:
                    try:
                        with pyzipper.AESZipFile(duong_dan) as z:
                            z.setpassword(mk)
                            z.extractall(thu_muc_ra)
                        return True
                    except Exception:
                        continue

    if shutil.which("7z"):
        for mk in ["-p", "-pinfected", "-pmalware"]:
            r = subprocess.run(["7z", "x", "-y", mk, "-o" + thu_muc_ra, duong_dan],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode == 0:
                return True
    return False


def hash_da_co(duong_dan_manifest):
    """Doc cot SHA-256 trong manifest hien co de khong thu gom trung."""
    da_co = set()
    if not duong_dan_manifest or not os.path.exists(duong_dan_manifest):
        return da_co
    try:
        import openpyxl
        wb = openpyxl.load_workbook(duong_dan_manifest, read_only=True, data_only=True)
        for ws in wb.worksheets:
            for hang in ws.iter_rows(values_only=True):
                for o in hang:
                    if isinstance(o, str) and re.fullmatch(r"[0-9a-fA-F]{64}", o.strip()):
                        da_co.add(o.strip().lower())
        wb.close()
    except Exception as e:
        print("Khong doc duoc manifest (%s). Bo qua buoc khu trung lap voi manifest." % e)
    return da_co


def clone(repo, thu_muc):
    if os.path.isdir(os.path.join(thu_muc, ".git")):
        print("  da co ban clone, bo qua")
        return True
    r = subprocess.run(["git", "clone", "--depth", "1",
                        "https://github.com/%s.git" % repo, thu_muc],
                       stdout=subprocess.DEVNULL)
    return r.returncode == 0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--danh-sach", required=True, help="file CSV liet ke cac kho")
    p.add_argument("--dich", required=True, help="thu muc luu ket qua")
    p.add_argument("--manifest", default="", help="Manifest_thu_thap_APK.xlsx de khu trung lap")
    p.add_argument("--nam-toi-thieu", type=int, default=0,
                   help="chi giu APK co moc thoi gian ben trong tu nam nay tro di; 0 = giu tat ca")
    p.add_argument("--nhom", default="", help="chi chay cac kho thuoc nhom nay, vi du A")
    tham_so = p.parse_args()

    thu_muc_clone = os.path.join(tham_so.dich, "_clone")
    thu_muc_giai_nen = os.path.join(tham_so.dich, "_giai_nen")
    thu_muc_apk = os.path.join(tham_so.dich, "apk")
    for d in (thu_muc_clone, thu_muc_giai_nen, thu_muc_apk):
        os.makedirs(d, exist_ok=True)

    da_co = hash_da_co(tham_so.manifest)
    print("Da co %d hash trong manifest." % len(da_co))

    with open(tham_so.danh_sach, encoding="utf-8-sig") as f:
        cac_kho = [d for d in csv.DictReader(f)
                   if not tham_so.nhom or d.get("nhom", "") == tham_so.nhom]

    ket_qua, bo_qua = [], []
    thay_trong_phien = {}   # sha256 -> (kho, ten file) cua ban da giu

    for d in cac_kho:
        repo = d["repo"]
        print("\n[%s]" % repo)
        dich_clone = os.path.join(thu_muc_clone, repo.replace("/", "__"))
        if not clone(repo, dich_clone):
            bo_qua.append([repo, "", "clone that bai", "", ""])
            continue

        # Buoc 1: giai nen moi file nen tim thay
        for goc, _, ten_file in os.walk(dich_clone):
            if ".git" in goc:
                continue
            for t in ten_file:
                if t.lower().endswith(DUOI_NEN):
                    nguon = os.path.join(goc, t)
                    ra = os.path.join(thu_muc_giai_nen, repo.replace("/", "__"),
                                      os.path.splitext(t)[0])
                    if not giai_nen(nguon, ra):
                        bo_qua.append([repo, t, "khong giai nen duoc", "", ""])

        # Buoc 2: quet toan bo file, nhan dien APK theo noi dung
        for thu_muc_quet in (dich_clone,
                             os.path.join(thu_muc_giai_nen, repo.replace("/", "__"))):
            if not os.path.isdir(thu_muc_quet):
                continue
            for goc, _, ten_file in os.walk(thu_muc_quet):
                if ".git" in goc:
                    continue
                for t in ten_file:
                    dp = os.path.join(goc, t)
                    if not la_apk(dp):
                        continue
                    h = sha256_file(dp)
                    if h in da_co:
                        bo_qua.append([repo, t, "trung voi mau da co trong manifest", h, "(manifest)"])
                        continue
                    if h in thay_trong_phien:
                        kho_goc, ten_goc = thay_trong_phien[h]
                        bo_qua.append([repo, t, "trung ban da lay trong dot nay: %s" % ten_goc,
                                       h, kho_goc])
                        continue
                    nam_max, nam_dex = moc_thoi_gian_apk(dp)
                    moc = nam_dex or nam_max
                    if tham_so.nam_toi_thieu and moc and moc < tham_so.nam_toi_thieu:
                        bo_qua.append([repo, t, "moc thoi gian %d, cu hon %d"
                                       % (moc, tham_so.nam_toi_thieu), h, ""])
                        continue
                    thay_trong_phien[h] = (repo, t)
                    shutil.copy2(dp, os.path.join(thu_muc_apk, h + ".apk"))
                    ket_qua.append([
                        h, t, repo, d.get("url", ""),
                        os.path.getsize(dp), nam_dex, nam_max, target_sdk(dp),
                        os.path.relpath(dp, tham_so.dich), d.get("ghi_chu", ""),
                    ])
                    print("  + %s (%s)" % (h[:12], t[:50]))

    # Khong xuat CSV nua. Ghi NOI THEM vao <dich>\\Ket_qua_thu_gom.xlsx.
    kq_dict = [dict(zip(COT_KQ[1:], hang)) for hang in ket_qua]
    bq_dict = [dict(zip(COT_BQ[1:], hang)) for hang in bo_qua]
    nhan = datetime.datetime.now().strftime("%d/%m/%Y %H:%M") + " - thu_gom_github_apk"
    them, tong = ghi_ket_qua.ghi_them(tham_so.dich, kq_dict, bq_dict, nhan)

    print("\nLan nay tim duoc %d mau, %d file bi loai." % (len(ket_qua), len(bo_qua)))
    print("Ghi them %d dong moi vao %s, tong cong %d mau hop le."
          % (them, ghi_ket_qua.duong_dan_file(tham_so.dich), tong))
    return 0


if __name__ == "__main__":
    sys.exit(main())
