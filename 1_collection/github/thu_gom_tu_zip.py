# -*- coding: utf-8 -*-
"""
Thu gom APK tu cac kho GitHub da tai san ve may (thu muc GitHubMinh).

Khac voi thu_gom_github_apk.py: script kia tu clone kho tu GitHub, script nay
doc thang tren dia, khong tai lai gi ca. Chap nhan ca hai dang:
  - thu muc da giai nen san (uu tien, doc truc tiep, khong bung lai zip ngoai)
  - file .zip cua kho, neu chua giai nen

Quy trinh cho moi kho:
    1. Chi duyet cac duong dan lot bo loc cua kho do. Bo loc co de tranh bung
       ca gigabyte ma doc Windows khong lien quan den Android.
    2. File nen long (7z, zip, rar) thi giai nen ra thu muc tam. Mat khau thu
       lan luot: khong mat khau, infected, infected!, malware, virus. Rieng
       theZoo co san file .pass canh file nen thi doc mat khau tu do.
    3. Moi file deu kiem tra theo NOI DUNG: phai la ZIP hop le, ben trong co
       AndroidManifest.xml va classes*.dex. Khong dua vao duoi ten file, vi
       nhieu kho dat ten theo hash va khong co duoi.
    4. Tinh SHA-256, khu trung voi manifest, voi kho apk da co, va trong dot nay.
    5. Loc theo moc thoi gian ben trong APK neu dat --nam-toi-thieu.
    6. Chep mau giu lai vao <dich>/apk/<sha256>.apk, ghi noi vao Ket_qua_thu_gom.xlsx.

Script KHONG gan nhan. Cot nhan trong manifest de trong, cho buoc quet VirusTotal.
Ten thu muc ho ma doc trong kho (FluBot, Cerberus, Jisut...) duoc ghi vao cot
Ghi_chu, khong dung lam nhan.

Can: python 3, va cac goi
    pip install openpyxl py7zr pyzipper
py7zr de doc .7z (kho goldoson nen bang 7z), pyzipper de doc zip nen AES.
Neu may co san 7-Zip thi script tu goi 7z.exe.

Cu phap:
    # xem truoc, khong giai nen gi het
    python thu_gom_tu_zip.py --thu-muc-nguon D:\\DuAnCapToc\\Thu_thap_APK\\GitHubMinh --liet-ke

    # chay that
    python thu_gom_tu_zip.py ^
        --thu-muc-nguon D:\\DuAnCapToc\\Thu_thap_APK\\GitHubMinh ^
        --dich D:\\APK_GitHub ^
        --manifest D:\\DuAnCapToc\\Thu_thap_APK\\Manifest_thu_thap_APK.xlsx ^
        --nam-toi-thieu 2020

Ket qua ghi NOI THEM vao <dich>\\Ket_qua_thu_gom.xlsx (ba sheet: Mau_thu_duoc,
File_bi_loai, Tong_hop_theo_kho). Khong con xuat CSV. Truoc khi ghi, ban cu duoc
cat vao <dich>\\_ban_cu\\ kem ngay gio, nen chay lai bao nhieu lan cung khong mat.
"""

import argparse
import datetime
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

import ghi_ket_qua
from ghi_ket_qua import COT_BQ, COT_KQ

MAT_KHAU = [None, b"infected", b"infected!", b"malware", b"virus"]

# Moc nam do cong cu build ghi cung vao entry cua APK chu khong phai nam that:
# zipalign va mot so ban aapt dat 1980-01-01 hoac 1981-01-01, vai chuoi build
# khac dat 2008. Gap cac moc nay nghia la APK khong con dau vet thoi gian, khong
# co nghia la mau cu, nen mac dinh GIU lai va de VirusTotal chot nam o Buoc 2.
# Toan bo 11 mau goldoson bi loai nham vi moc 1981 trong lan chay dau 30/8/2026.
MOC_KHONG_THAT = {0, 1980, 1981, 2008}
DUOI_NEN = (".zip", ".7z", ".rar", ".gz", ".tar", ".tgz", ".xz", ".bz2")
DUOI_BO = (".md", ".txt", ".pass", ".md5", ".sha", ".sha1", ".sha256", ".shasum",
           ".py", ".json", ".yml", ".yaml", ".png", ".jpg", ".gif", ".pdf",
           ".html", ".css", ".js", ".asm", ".a86", ".pas", ".c", ".h")

# Cau hinh tung kho. Khoa la chuoi nam trong ten thu muc / ten file zip.
# Thu tu kiem tra khoa quan trong: "Malware-Database" (co gach ngang, kho
# cryptwareapps) phai xet truoc "MalwareDatabase" (khong gach, kho Pyran1).
THU_TU_KHOA = ["goldoson-samples", "Malware-Database", "theZoo", "MalwareDatabase"]

CAU_HINH = {
    "goldoson-samples": {
        "repo": "IHbib/goldoson-samples",
        "url": "https://github.com/IHbib/goldoson-samples",
        "loc": None,
        "ghi_chu": "Goldoson adware, McAfee cong bo 4/2023, SDK quang cao doc nhung trong app that tren Play Store Han Quoc",
    },
    "Malware-Database": {
        "repo": "cryptwareapps/Malware-Database",
        "url": "https://github.com/cryptwareapps/Malware-Database",
        # bat ca Malware/Android/... lan Malware/Spyware/Android Pegasus/...
        "loc": r"(?i)android",
        "ghi_chu": "Ho ma doc Android doi 2011-2017 (Jisut, Svpeng, Zsone, Plankton, FakeInst...)",
    },
    "theZoo": {
        "repo": "ytisf/theZoo",
        "url": "https://github.com/ytisf/theZoo",
        "loc": r"(?i)(android|androrat)",
        "ghi_chu": "Chi 5 mau nhi phan Android trong kho, ho doi 2013-2018",
    },
    "MalwareDatabase": {
        "repo": "Pyran1/MalwareDatabase",
        "url": "https://github.com/Pyran1/MalwareDatabase",
        # kho xep theo duoi file, toan bo mau Android nam trong thu muc ".apk"
        "loc": r"(?i)(^|/)\.apk/",
        "ghi_chu": "Mau lay tu MalwareBazaar, them vao kho 2020-2022, xep theo ho: FluBot, Cerberus, Anubis, Hydra, Teabot, Sharkbot, Alienbot, BankBot...",
    },
}


def nhan_dien_kho(ten):
    for khoa in THU_TU_KHOA:
        if khoa.lower() in ten.lower():
            c = dict(CAU_HINH[khoa])
            c["khoa"] = khoa
            return c
    return {"khoa": ten, "repo": os.path.splitext(ten)[0], "url": "",
            "loc": None, "ghi_chu": ""}


def sha256_file(duong_dan):
    h = hashlib.sha256()
    with open(duong_dan, "rb") as f:
        for khoi in iter(lambda: f.read(1024 * 1024), b""):
            h.update(khoi)
    return h.hexdigest()


def la_apk(duong_dan):
    """Nhan dien APK theo noi dung: ZIP hop le co AndroidManifest.xml va classes*.dex."""
    try:
        if os.path.getsize(duong_dan) < 4096:
            return False
        with open(duong_dan, "rb") as f:
            if f.read(2) != b"PK":
                return False
        with zipfile.ZipFile(duong_dan) as z:
            ten = z.namelist()
            return "AndroidManifest.xml" in ten and any(
                t.startswith("classes") and t.endswith(".dex") for t in ten)
    except Exception:
        return False


def moc_thoi_gian_apk(duong_dan):
    """(nam lon nhat trong cac entry, nam cua classes.dex). Bang chung yeu hon
    first_submission_date cua VirusTotal, chi dung de sang loc so bo."""
    nam_max, nam_dex = 0, 0
    try:
        with zipfile.ZipFile(duong_dan) as z:
            for info in z.infolist():
                if info.date_time[0] > nam_max:
                    nam_max = info.date_time[0]
                if info.filename == "classes.dex":
                    nam_dex = info.date_time[0]
    except Exception:
        pass
    return nam_max, nam_dex


def target_sdk(duong_dan):
    try:
        from androguard.core.bytecodes.apk import APK
        return int(APK(duong_dan).get_target_sdk_version() or 0)
    except Exception:
        return 0


def tim_7z():
    for ung_vien in ("7z", "7za", r"C:\Program Files\7-Zip\7z.exe",
                     r"C:\Program Files (x86)\7-Zip\7z.exe"):
        dd = shutil.which(ung_vien) or (ung_vien if os.path.exists(ung_vien) else None)
        if dd:
            return dd
    return None


BAY_Z = tim_7z()


def giai_nen(duong_dan, thu_muc_ra, mat_khau_goi_y=None):
    """Giai nen mot file nen. Tra ve True neu ra duoc it nhat mot file."""
    os.makedirs(thu_muc_ra, exist_ok=True)
    duoi = duong_dan.lower()
    ds_mk = ([mat_khau_goi_y] if mat_khau_goi_y else []) + MAT_KHAU

    if duoi.endswith(".zip"):
        aes = False
        for mk in ds_mk:
            try:
                with zipfile.ZipFile(duong_dan) as z:
                    z.extractall(thu_muc_ra, pwd=mk)
                if os.listdir(thu_muc_ra):
                    return True
            except NotImplementedError:
                aes = True
                break
            except Exception:
                continue
        if aes:
            try:
                import pyzipper
                for mk in ds_mk:
                    if mk is None:
                        continue
                    try:
                        with pyzipper.AESZipFile(duong_dan) as z:
                            z.setpassword(mk)
                            z.extractall(thu_muc_ra)
                        if os.listdir(thu_muc_ra):
                            return True
                    except Exception:
                        continue
            except ImportError:
                print("      can pyzipper de doc zip nen AES. Chay: pip install pyzipper")

    if duoi.endswith(".7z"):
        try:
            import py7zr
            for mk in ds_mk:
                try:
                    with py7zr.SevenZipFile(
                            duong_dan, mode="r",
                            password=mk.decode() if isinstance(mk, bytes) else mk) as z:
                        z.extractall(path=thu_muc_ra)
                    if os.listdir(thu_muc_ra):
                        return True
                except Exception:
                    continue
        except ImportError:
            if not BAY_Z:
                print("      can py7zr de doc file .7z. Chay: pip install py7zr")

    if BAY_Z:
        for mk in ("-p", "-pinfected", "-pinfected!", "-pmalware"):
            r = subprocess.run([BAY_Z, "x", "-y", mk, "-o" + thu_muc_ra, duong_dan],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode == 0 and os.listdir(thu_muc_ra):
                return True
    return False


def hash_da_co(duong_dan_manifest, thu_muc_apk):
    da_co = set()
    if duong_dan_manifest and os.path.exists(duong_dan_manifest):
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
            print("Khong doc duoc manifest (%s). Bo qua khu trung lap voi manifest." % e)
    if os.path.isdir(thu_muc_apk):
        for t in os.listdir(thu_muc_apk):
            g = os.path.splitext(t)[0].lower()
            if re.fullmatch(r"[0-9a-f]{64}", g):
                da_co.add(g)
    return da_co


def cac_nguon(thu_muc_nguon):
    """Tra ve danh sach (ten, kieu, duong_dan). Thu muc da giai nen duoc uu tien;
    file zip nao da co thu muc cung ten thi bo qua de khoi lam hai lan."""
    muc = os.listdir(thu_muc_nguon)
    thu_muc = [t for t in muc if os.path.isdir(os.path.join(thu_muc_nguon, t))]
    ra = [(t, "thu_muc", os.path.join(thu_muc_nguon, t)) for t in sorted(thu_muc)]
    for t in sorted(muc):
        if t.lower().endswith(".zip") and os.path.splitext(t)[0] not in thu_muc:
            ra.append((t, "zip", os.path.join(thu_muc_nguon, t)))
    return ra


def duyet_thu_muc(goc, mau_loc):
    """Sinh (duong_dan_that, nhan) cho cac file lot bo loc."""
    for thu_muc, _, ten_file in os.walk(goc):
        if ".git" in thu_muc.split(os.sep):
            continue
        for t in ten_file:
            dd = os.path.join(thu_muc, t)
            nhan = os.path.relpath(dd, os.path.dirname(goc)).replace(os.sep, "/")
            if mau_loc and not mau_loc.search(nhan):
                continue
            if t.lower().endswith(DUOI_BO):
                continue
            yield dd, nhan


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--thu-muc-nguon", required=True,
                   help="thu muc chua cac kho da giai nen va/hoac file zip")
    p.add_argument("--dich", default="", help="thu muc luu ket qua, vi du D:\\APK_GitHub")
    p.add_argument("--manifest", default="", help="Manifest_thu_thap_APK.xlsx de khu trung lap")
    p.add_argument("--nam-toi-thieu", type=int, default=0,
                   help="chi giu APK co moc thoi gian tu nam nay tro di; 0 = giu tat ca")
    p.add_argument("--tat-ca", action="store_true",
                   help="bo het bo loc duong dan, quet toan bo cay thu muc cua moi kho")
    p.add_argument("--loai-moc-khong-ro", action="store_true",
                   help="loai luon nhung APK co moc 1980/1981/2008 thay vi giu lai. "
                        "Mac dinh la giu, vi day la moc do build tool ghi cung.")
    p.add_argument("--liet-ke", action="store_true", help="chi xem truoc, khong giai nen")
    ts = p.parse_args()

    nguon = cac_nguon(ts.thu_muc_nguon)
    if not nguon:
        print("Khong thay kho nao trong %s" % ts.thu_muc_nguon)
        return 1

    if ts.liet_ke:
        for ten, kieu, dd in nguon:
            c = nhan_dien_kho(ten)
            mau_loc = None if ts.tat_ca or not c["loc"] else re.compile(c["loc"])
            print("\n=== %s [%s]  ->  %s" % (ten, kieu, c["repo"]))
            if kieu == "thu_muc":
                het = [(x, n) for x, n in duyet_thu_muc(dd, None)]
                lot = [n for _, n in duyet_thu_muc(dd, mau_loc)]
            else:
                with zipfile.ZipFile(dd) as z:
                    het = [(None, i.filename) for i in z.infolist() if not i.is_dir()]
                lot = [n for _, n in het
                       if (not mau_loc or mau_loc.search(n))
                       and not n.lower().endswith(DUOI_BO)]
            print("  tong file        : %d" % len(het))
            print("  lot bo loc       : %d" % len(lot))
            print("  trong do .apk    : %d" % sum(1 for n in lot if n.lower().endswith(".apk")))
            print("  trong do file nen: %d" % sum(1 for n in lot if n.lower().endswith(DUOI_NEN)))
            for n in lot[:12]:
                print("     %s" % n)
            if len(lot) > 12:
                print("     ... con %d file nua" % (len(lot) - 12))
        return 0

    if not ts.dich:
        print("Thieu --dich. Vi du: --dich D:\\APK_GitHub")
        return 1

    thu_muc_apk = os.path.join(ts.dich, "apk")
    thu_muc_tam = os.path.join(ts.dich, "_tam")
    os.makedirs(thu_muc_apk, exist_ok=True)
    os.makedirs(thu_muc_tam, exist_ok=True)

    da_co = hash_da_co(ts.manifest, thu_muc_apk)
    print("Da co %d hash (manifest + kho apk). Gap lai se bo qua." % len(da_co))
    if BAY_Z:
        print("Dung 7-Zip tai: %s" % BAY_Z)

    ket_qua, bo_qua, thay_trong_phien = [], [], {}

    def xet_mot_apk(duong_dan_file, nhan, repo, c):
        """Kiem tra, khu trung, loc nam roi chep vao kho apk."""
        if not la_apk(duong_dan_file):
            return
        h = sha256_file(duong_dan_file)
        if h in da_co:
            bo_qua.append([repo, nhan, "trung voi mau da co (manifest hoac kho apk)", h, "(da co)"])
            return
        if h in thay_trong_phien:
            kho_goc, ten_cu = thay_trong_phien[h]
            bo_qua.append([repo, nhan, "trung ban da lay trong dot nay: %s" % ten_cu, h, kho_goc])
            return
        nam_max, nam_dex = moc_thoi_gian_apk(duong_dan_file)
        moc = nam_dex or nam_max
        moc_ro = moc not in MOC_KHONG_THAT and moc >= 1990
        if ts.nam_toi_thieu and moc_ro and moc < ts.nam_toi_thieu:
            bo_qua.append([repo, nhan, "moc thoi gian %d, cu hon %d" % (moc, ts.nam_toi_thieu),
                           h, ""])
            return
        if ts.nam_toi_thieu and not moc_ro and ts.loai_moc_khong_ro:
            bo_qua.append([repo, nhan,
                           "moc thoi gian %d khong xac dinh, loai theo --loai-moc-khong-ro" % moc,
                           h, ""])
            return
        thay_trong_phien[h] = (repo, nhan)
        if not moc_ro:
            c = dict(c)
            c["ghi_chu"] = ("moc thoi gian trong APK la %d, do build tool ghi cung nen khong "
                            "xac dinh duoc nam, cho VirusTotal chot; %s" % (moc, c["ghi_chu"]))
        # ten thu muc cha thuong la ten ho ma doc, ghi vao Ghi_chu de tra nguoc
        phan = nhan.split(" > ")[0].split("/")
        thu_muc_cha = phan[-2] if len(phan) > 2 else ""
        ghi_chu = c["ghi_chu"]
        if thu_muc_cha and not thu_muc_cha.lower().endswith(DUOI_NEN):
            ghi_chu = "thu muc %s; %s" % (thu_muc_cha, ghi_chu)
        shutil.copy2(duong_dan_file, os.path.join(thu_muc_apk, h + ".apk"))
        ket_qua.append([h, os.path.basename(nhan.split(" > ")[-1]), repo, c["url"],
                        os.path.getsize(duong_dan_file), nam_dex, nam_max,
                        target_sdk(duong_dan_file), nhan, ghi_chu])
        print("  + %s  %s" % (h[:12], nhan[-70:]))

    def xu_ly(duong_dan_file, nhan, repo, c, goi_y=None):
        """File thuong thi xet luon; file nen thi bung ra thu muc tam roi xet ruot."""
        xet_mot_apk(duong_dan_file, nhan, repo, c)
        if not nhan.lower().endswith(DUOI_NEN):
            return
        tam = tempfile.mkdtemp(dir=thu_muc_tam)
        try:
            if not giai_nen(duong_dan_file, tam, goi_y):
                bo_qua.append([repo, nhan, "khong giai nen duoc", "", ""])
                return
            for goc, _, ten_file in os.walk(tam):
                for t in ten_file:
                    xet_mot_apk(os.path.join(goc, t), nhan + " > " + t, repo, c)
        finally:
            shutil.rmtree(tam, ignore_errors=True)

    for ten, kieu, duong_dan_nguon in nguon:
        c = nhan_dien_kho(ten)
        repo = c["repo"]
        mau_loc = None if ts.tat_ca or not c["loc"] else re.compile(c["loc"])
        print("\n[%s]  %s  (%s)" % (ten, kieu, repo))

        if kieu == "thu_muc":
            danh_sach = list(duyet_thu_muc(duong_dan_nguon, mau_loc))
            print("  %d file lot bo loc" % len(danh_sach))
            for dd, nhan in danh_sach:
                # theZoo de mat khau trong file .pass canh file nen
                goi_y = None
                pass_file = os.path.splitext(dd)[0] + ".pass"
                if os.path.exists(pass_file):
                    try:
                        goi_y = open(pass_file, "rb").read().strip()
                    except Exception:
                        pass
                xu_ly(dd, nhan, repo, c, goi_y)
            continue

        # dang file zip chua giai nen
        try:
            zf = zipfile.ZipFile(duong_dan_nguon)
        except Exception as e:
            bo_qua.append([repo, ten, "khong mo duoc zip ngoai: %s" % e, "", ""])
            print("  khong mo duoc: %s" % e)
            continue
        goi_y_zip = {}
        for i in zf.infolist():
            if i.filename.lower().endswith(".pass"):
                try:
                    goi_y_zip[os.path.dirname(i.filename)] = zf.read(i).strip()
                except Exception:
                    pass
        cac_entry = [i for i in zf.infolist() if not i.is_dir()
                     and (not mau_loc or mau_loc.search(i.filename))
                     and not i.filename.lower().endswith(DUOI_BO)]
        print("  %d file lot bo loc / %d file trong zip" % (len(cac_entry), len(zf.infolist())))
        for entry in cac_entry:
            ten_goc = os.path.basename(entry.filename)
            if not ten_goc:
                continue
            tam = tempfile.mkdtemp(dir=thu_muc_tam)
            try:
                dich_tam = os.path.join(tam, ten_goc)
                try:
                    with zf.open(entry) as ngoc, open(dich_tam, "wb") as ra:
                        shutil.copyfileobj(ngoc, ra, 1024 * 1024)
                except Exception as e:
                    bo_qua.append([repo, entry.filename, "khong rut duoc khoi zip: %s" % e, "", ""])
                    continue
                xu_ly(dich_tam, entry.filename, repo, c,
                      goi_y_zip.get(os.path.dirname(entry.filename)))
            finally:
                shutil.rmtree(tam, ignore_errors=True)
        zf.close()

    shutil.rmtree(thu_muc_tam, ignore_errors=True)

    # Khong xuat CSV nua. Tu 30/8/2026 moi lan chay ghi NOI THEM vao mot file
    # Excel duy nhat <dich>\\Ket_qua_thu_gom.xlsx, ban cu duoc cat vao <dich>\\_ban_cu.
    kq_dict = [dict(zip(COT_KQ[1:], hang)) for hang in ket_qua]
    bq_dict = [dict(zip(COT_BQ[1:], hang)) for hang in bo_qua]
    nhan = datetime.datetime.now().strftime("%d/%m/%Y %H:%M") + " - thu_gom_tu_zip"
    them, tong = ghi_ket_qua.ghi_them(ts.dich, kq_dict, bq_dict, nhan)

    print("\nLan nay tim duoc %d mau, %d file bi loai." % (len(ket_qua), len(bo_qua)))
    theo_kho = {}
    for d in ket_qua:
        theo_kho[d[2]] = theo_kho.get(d[2], 0) + 1
    for k, v in sorted(theo_kho.items(), key=lambda x: -x[1]):
        print("   %-45s %d" % (k, v))
    print("Ghi them %d dong moi vao %s, tong cong %d mau hop le."
          % (them, ghi_ket_qua.duong_dan_file(ts.dich), tong))

    print("\nBuoc tiep: python nap_ket_qua_vao_manifest.py --dich %s --manifest %s"
          % (ts.dich, ts.manifest or "<duong dan xlsx>"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
