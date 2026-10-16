# -*- coding: utf-8 -*-
"""Tai APK tu AndroZoo theo danh muc da loc san o buoc chuan_bi_danh_muc.py.

Nhung diem khac voi cong cu az (ArtemKushnerov/az) va la ly do phai viet rieng:

  * Dat ten file theo SHA-256 dung quy uoc cua bo du lieu, khong dat theo
    pkg_name.
  * Kiem tra ma HTTP roi doi chieu SHA-256 cua file tai ve voi hash trong danh
    muc. Sai thi xoa file va danh dau de tai lai, khong de trang loi bi ghi
    thanh file .apk hong.
  * Ghi trang thai vao chinh file SQLite, nen dung giua chung (Ctrl+C, mat dien,
    mat mang) roi chay lai dung cau lenh cu la di tiep tu cho dung, khong tai
    trung.
  * Uu tien mau MOI NHAT truoc: sap giam dan theo moc ngay ma
    chuan_bi_danh_muc.py da chon (cot added neu danh sach co, khong thi
    vt_scan_date).
  * Chay duoc voi mot key. Neu file api_keys.txt co nhieu hon mot dong thi
    dong dau la key chinh, cac dong sau la du phong: key chinh bi tu choi
    (401/403) hoac cham tran (429) thi tu chuyen sang key ke tiep.

Cu phap thuong dung:

    python tai_androzoo.py --so-luong 500 --nhom ma_doc
    python tai_androzoo.py --so-luong 500 --nhom lanh
    python tai_androzoo.py --tiep-tuc            (tai lai nhung mau bi loi)

API key doc tu file api_keys.txt dat canh script, moi dong mot key. Dung mot
key la du: han muc AndroZoo la 500.000 luot trong 6 thang.
"""

import argparse
import datetime
import hashlib
import os
import queue
import random
import shutil
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests

THU_MUC = os.path.dirname(os.path.abspath(__file__))
API = "https://androzoo.uni.lu/api/download"
TEN_EXCEL = "Ket_qua_AndroZoo.xlsx"
TEN_KHOA = "_dang_chay.lock"
S_MAU, S_TH = "Mau_AndroZoo", "Tong_hop"

# Kho APK khac cung dat ten file theo SHA-256. Mau tai tu AndroZoo co the trung
# voi mau da thu tu GitHub; tai lai vua ton bang thong vua lam bo du lieu bi dem
# hai lan luc gop manifest. Mac dinh doi chieu kho nay, tat bang
# --khong-doi-chieu-kho-khac.
KHO_KHAC_MAC_DINH = r"D:\APK_GitHub\apk"

# Danh sach kho APK cua ca du an. Moi dong mot thu muc, dang "duong_dan | Nhan".
# APK gio nam rai o nhieu o (o D, o roi F, o roi G) nen khong con mot thu muc
# nao la toan bo kho nua; file nay la cho duy nhat ghi lai chung o dau, va
# static.py cung doc chinh file nay.
LINKAPK_MAC_DINH = r"D:\LinkAPK.txt"

# Moc_ngay: cot 'added' neu danh sach co, khong thi lay vt_scan_date. Xem
# phan in ra cua chuan_bi_danh_muc.py de biet lan nap nay dung cot nao.
COT_MAU = ["Lan_chay", "SHA-256", "pkg_name", "Kich_thuoc_byte", "Moc_ngay",
           "vt_detection", "vt_scan_date", "dex_date", "markets", "Nhom",
           "Duong_dan", "Ghi_chu"]


# ------------------------------------------------------------- chong chay trung

class DangChay(object):
    """Khoa chi cho mot ban script chay tai mot thoi diem.

    Hai tien trinh cung chay se dam nhau o hai cho: file SQLite chi cho mot
    nguoi ghi (nguoi thu hai bao "database is locked"), va file Excel bi doc
    - sua - ghi de nen lan ghi sau xoa mat cac dong cua lan ghi truoc. Chay
    song song cung khong nhanh hon vi nut that la bang thong; muon nhanh hon
    thi tang --luong trong MOT tien trinh.
    """

    def __init__(self, thu_muc, bo_qua=False):
        self.duong_dan = os.path.join(thu_muc, TEN_KHOA)
        self.bo_qua = bo_qua
        self.giu = False

    def __enter__(self):
        if os.path.exists(self.duong_dan) and not self.bo_qua:
            try:
                with open(self.duong_dan, "r", encoding="utf-8") as f:
                    noi_dung = f.read().strip()
            except OSError:
                noi_dung = "(khong doc duoc)"
            tuoi = time.time() - os.path.getmtime(self.duong_dan)
            print("DUNG LAI: dang co mot ban tai_androzoo.py khac chay.")
            print("  %s" % noi_dung)
            print("  khoa tao cach day %.0f phut" % (tuoi / 60))
            print()
            print("Dung mo hai cua so cmd cung luc: hai tien trinh se dam nhau")
            print("khi ghi androzoo_index.db va se ghi de len nhau o file Excel.")
            print("Muon chay hai dot noi tiep thi dung mot cua so va noi bang &&.")
            print("Muon tai nhanh hon thi tang --luong trong mot tien trinh.")
            print()
            print("Neu chac chan khong con tien trinh nao chay (may tat dot ngot,")
            print("Ctrl+C khong kip don), xoa file %s roi chay lai." % TEN_KHOA)
            sys.exit(1)
        try:
            with open(self.duong_dan, "w", encoding="utf-8") as f:
                f.write("PID %d, bat dau %s"
                        % (os.getpid(),
                           datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            self.giu = True
        except OSError:
            pass  # khong tao duoc khoa thi van cho chay, khoa chi la lop bao ve
        return self

    def __exit__(self, *a):
        if self.giu:
            try:
                os.remove(self.duong_dan)
            except OSError:
                pass
        return False


# ---------------------------------------------------------------- quan ly key

class KhoKey(object):
    """Giu danh sach key, tra ve key dang dung, tu chuyen khi key hong."""

    def __init__(self, keys):
        self.keys = list(keys)
        self.vi_tri = 0
        self.hong = set()
        self.khoa = threading.Lock()

    def lay(self):
        with self.khoa:
            return self.keys[self.vi_tri]

    def chuyen(self, key_cu, ly_do):
        """Chuyen sang key ke tiep neu key hien tai van la key_cu."""
        with self.khoa:
            if self.keys[self.vi_tri] != key_cu:
                return self.keys[self.vi_tri]  # luong khac da chuyen roi
            if ly_do == "hong":
                self.hong.add(key_cu)
            n = len(self.keys)
            for buoc in range(1, n + 1):
                j = (self.vi_tri + buoc) % n
                if self.keys[j] not in self.hong:
                    self.vi_tri = j
                    if n == 1:
                        print("  [key] chi co mot key, cho roi thu lai (%s)" % ly_do)
                    else:
                        print("  [key] chuyen sang key #%d (ly do: %s)"
                              % (j + 1, ly_do))
                    return self.keys[j]
            return None


# Cac dong mau trong file api_keys.txt phat kem. Neu nguoi dung chi dan mot key
# vao dong dau thi dong mau con lai van nam do; phai loai no ra chu khong dem
# thanh key that.
DONG_MAU = {"key_thu_nhat_dan_vao_day", "key_thu_hai_dan_vao_day",
            "key_cua_anh", "dan_key_vao_day"}
DAI_TOI_THIEU = 20  # key AndroZoo dai hon nhieu; ngan hon the la go nham


def che(key):
    """Hien key du de nhan ra ma khong in ca chuoi ra man hinh."""
    if len(key) <= 12:
        return key[:2] + "..." + key[-2:]
    return key[:6] + "..." + key[-4:]


def doc_keys(args):
    if args.key:
        return [k.strip() for k in args.key.split(",") if k.strip()]
    for ten in ("api_keys.txt", "api_key.txt"):
        dd = os.path.join(THU_MUC, ten)
        if not os.path.exists(dd):
            continue
        keys, bo_mau, bo_ngan = [], 0, 0
        with open(dd, "r", encoding="utf-8") as f:
            for dong in f:
                dong = dong.strip()
                if not dong or dong.startswith("#"):
                    continue
                k = dong.split()[0]
                if k.lower() in DONG_MAU:
                    bo_mau += 1
                    continue
                if len(k) < DAI_TOI_THIEU:
                    bo_ngan += 1
                    continue
                if k not in keys:
                    keys.append(k)
        if bo_mau:
            print("Bo qua %d dong mau chua thay the trong %s." % (bo_mau, ten))
        if bo_ngan:
            print("Bo qua %d dong qua ngan de la key trong %s." % (bo_ngan, ten))
        if keys:
            print("Dung %d API key tu %s: %s"
                  % (len(keys), ten, ", ".join(che(k) for k in keys)))
            return keys
    sys.exit("Khong tim thay API key hop le. Dat key vao api_keys.txt canh "
             "script (moi dong mot key), hoac dung --key <key>.")


# ------------------------------------------------------------------- tai file

class Loi(Exception):
    def __init__(self, ly_do, doi_key=None):
        super().__init__(ly_do)
        self.ly_do = ly_do
        self.doi_key = doi_key  # None | "cham_tran" | "hong"


def tai_mot(mau, kho_key, thu_muc, nhip, thoi_gian_cho):
    """Tai mot mau, kiem tra bam. Tra ve (sha256, ok, ly_do)."""
    sha = mau["sha256"]
    dich = os.path.join(thu_muc, sha + ".apk")
    if os.path.exists(dich):
        return sha, True, "da co san trong thu muc"

    tam = os.path.join(thu_muc, sha + ".tam")
    key = kho_key.lay()
    if key is None:
        raise Loi("het key dung duoc")
    try:
        r = requests.get(API, params={"apikey": key, "sha256": sha},
                         stream=True, timeout=thoi_gian_cho)
        if r.status_code in (401, 403):
            r.close()
            raise Loi("key bi tu choi (HTTP %d)" % r.status_code, "hong")
        if r.status_code == 429:
            r.close()
            raise Loi("cham tran toc do (HTTP 429)", "cham_tran")
        if r.status_code != 200:
            r.close()
            return sha, False, "HTTP %d" % r.status_code

        bam = hashlib.sha256()
        so_byte = 0
        with open(tam, "wb") as f:
            for khoi in r.iter_content(chunk_size=1024 * 256):
                if khoi:
                    bam.update(khoi)
                    f.write(khoi)
                    so_byte += len(khoi)
        r.close()

        if so_byte == 0:
            os.remove(tam)
            return sha, False, "file rong"
        thuc_te = bam.hexdigest()
        if thuc_te != sha:
            os.remove(tam)
            return sha, False, "sai bam (nhan duoc %s..., %d byte)" % (
                thuc_te[:12], so_byte)
        os.replace(tam, dich)
        if nhip:
            time.sleep(nhip)
        return sha, True, ""
    except Loi:
        raise
    except requests.exceptions.RequestException as e:
        if os.path.exists(tam):
            try:
                os.remove(tam)
            except OSError:
                pass
        return sha, False, "loi mang: %s" % type(e).__name__
    except Exception as e:  # noqa: BLE001 - ghi lai de con truy nguoc
        if os.path.exists(tam):
            try:
                os.remove(tam)
            except OSError:
                pass
        return sha, False, "loi khac: %s" % e


# -------------------------------------------------------------------- chon mau

def chon_mau(con, args, da_co, kho_khac=frozenset()):
    dieu_kien = ["trang_thai IN ('chua','loi')" if args.tiep_tuc else "trang_thai='chua'"]
    tham_so = []
    if args.nhom:
        dieu_kien.append("nhom IN (%s)" % ",".join("?" * len(args.nhom)))
        tham_so.extend(sorted(args.nhom))
    if args.tu_nam:
        dieu_kien.append("CAST(nam AS INTEGER) >= ?")
        tham_so.append(args.tu_nam)
    if args.den_nam:
        dieu_kien.append("CAST(nam AS INTEGER) <= ?")
        tham_so.append(args.den_nam)
    if args.kich_thuoc:
        dieu_kien.append("apk_size <= ?")
        tham_so.append(args.kich_thuoc * 1024 * 1024)
    if args.vt_toi_thieu:
        dieu_kien.append("vt_detection >= ?")
        tham_so.append(args.vt_toi_thieu)
    if args.vt_toi_da:
        dieu_kien.append("vt_detection <= ?")
        tham_so.append(args.vt_toi_da)
    if args.tiep_tuc:
        dieu_kien.append("so_lan_thu < ?")
        tham_so.append(args.so_lan_thu_toi_da)

    sql = ("SELECT sha256,pkg_name,apk_size,moc_ngay,dex_date,vt_detection,"
           "vt_scan_date,markets,nhom FROM ungvien WHERE %s ORDER BY %s LIMIT ?"
           % (" AND ".join(dieu_kien),
              "RANDOM()" if args.ngau_nhien else "moc_ngay DESC"))

    # Doc theo cua so roi tu noi rong khi chua gom du. Truoc day cua so co dinh
    # bang --so-luong x 3: dong nao da co file tren dia van chiem cho trong cua
    # so, nen chi can vai tram dong nhu vay la lan chay tra ve it hon so mau
    # yeu cau ma khong bao gi. Buoc dong bo o dau moi lan chay da don gan het
    # loai dong do, day la lop chan con lai.
    ten_cot = ["sha256", "pkg_name", "apk_size", "moc_ngay", "dex_date",
               "vt_detection", "vt_scan_date", "markets", "nhom"]
    he_so = 3
    while True:
        gioi_han = args.so_luong * he_so
        ra, trung_kho_khac, so_dong = [], 0, 0
        for hang in con.execute(sql, tham_so + [gioi_han]):
            so_dong += 1
            if hang[0] in da_co:
                if hang[0] in kho_khac:
                    trung_kho_khac += 1
                continue
            ra.append(dict(zip(ten_cot, hang)))
            if len(ra) >= args.so_luong:
                break
        if len(ra) >= args.so_luong:
            break
        if so_dong < gioi_han:
            print("  danh muc chi con %d dong dat dieu kien, gom duoc %d ung vien"
                  % (so_dong, len(ra)))
            break
        if he_so >= 3000:
            print("  da doc %d dong ma van chua du %d ung vien, dung o day"
                  % (so_dong, args.so_luong))
            break
        he_so *= 5
        print("  cua so %d dong moi gom duoc %d ung vien, noi rong len %d dong ..."
              % (gioi_han, len(ra), args.so_luong * he_so))
    if trung_kho_khac:
        print("  bo %d ung vien vi da co ben kho doi chieu" % trung_kho_khac)
    return ra


def dong_bo_trang_thai(con, tat_ca, cho_ha, chi_xem=False):
    """Chinh trang_thai trong danh muc cho khop voi file APK thuc co tren dia.

    tat_ca la SHA-256 cua moi file dang co o MOI kho, khong rieng thu muc dich.
    Ke tu luc APK nam rai tren nhieu o, mot danh muc phuc vu nhieu thu muc, nen
    doi chieu voi rieng thu muc dich la sai: mau tai xuong o F se bi coi nhu mat
    file va bi tai lai lan nua khi dot sau ghi vao o G.

    Hai chieu lech deu tung xay ra va deu am tham:

      * Dung lai androzoo_index.db (xoa di roi chay lai chuan_bi_danh_muc.py) thi
        moi dong quay ve 'chua', ke ca mau da tai tu truoc. Nhung dong do nam li
        o dau hang doi vi thu tu sap xep la moc_ngay DESC, chiem cho cua so ung
        vien nen moi lan chay chi ra duoc mot phan so mau yeu cau.
      * Nguoc lai, dong ghi 'da_tai' ma file da bi xoa hoac tai hong thi mau do
        bi coi nhu da co, khong bao gio duoc tai lai, va con so trong danh muc
        cao hon so file that.

    cho_ha=False thi chi nang dong len 'da_tai' chu khong ha dong nao xuong
    'chua'. Dung khi co kho trong danh sach khong cam vao may: luc do khong
    nhin thay file khong co nghia la file da mat.
    """
    print("Doi chieu danh muc voi file thuc co tren dia ...")
    ds = sorted(tat_ca)
    trang = {}
    for i in range(0, len(ds), 500):
        lo = ds[i:i + 500]
        sql = ("SELECT sha256,trang_thai FROM ungvien WHERE sha256 IN (%s)"
               % ",".join("?" * len(lo)))
        for hang in con.execute(sql, lo):
            trang[str(hang[0]).lower()] = hang[1]

    thieu = sorted(h for h, t in trang.items() if t != "da_tai")
    thua = sorted(h for (h,) in con.execute(
        "SELECT sha256 FROM ungvien WHERE trang_thai='da_tai'")
        if str(h).lower() not in tat_ca)
    ngoai = len(tat_ca) - len(trang)

    if not chi_xem:
        for i in range(0, len(thieu), 500):
            lo = thieu[i:i + 500]
            con.execute(
                "UPDATE ungvien SET trang_thai='da_tai', so_lan_thu=0, "
                "ghi_chu='dong bo tu file tren dia' WHERE sha256 IN (%s)"
                % ",".join("?" * len(lo)), lo)
        if cho_ha:
            for i in range(0, len(thua), 500):
                lo = thua[i:i + 500]
                con.execute(
                    "UPDATE ungvien SET trang_thai='chua', thoi_diem_tai=NULL, "
                    "ghi_chu='khong con thay file o kho nao' WHERE sha256 IN (%s)"
                    % ",".join("?" * len(lo)), lo)
        con.commit()

    dau = "se sua" if chi_xem else "da sua"
    if thieu:
        print("  %s %d dong thanh da_tai (co file tren dia ma danh muc ghi chua tai)"
              % (dau, len(thieu)))
    if thua and cho_ha:
        print("  %s %d dong ve chua tai (danh muc ghi da_tai ma khong con file)"
              % (dau, len(thua)))
    elif thua:
        print("  GIU NGUYEN %d dong da_tai khong thay file: dang thieu kho nen "
              "chua the ket luan la mat file" % len(thua))
    if not thieu and not thua:
        print("  danh muc da khop voi file tren dia, khong phai sua gi")
    if ngoai:
        print("  %d file tren dia khong co dong nao trong danh muc (nam ngoai "
              "tieu chi loc cua chuan_bi_danh_muc.py hoac thu tu nguon khac)"
              % ngoai)

    sau = con.execute(
        "SELECT COUNT(*) FROM ungvien WHERE trang_thai='da_tai'").fetchone()[0]
    print("  danh muc: %d dong da_tai | tren dia: %d file APK"
          % (sau, len(tat_ca)))
    if not chi_xem and cho_ha and sau + ngoai != len(tat_ca):
        print("  LUU Y: hai con so van lech %d. Kiem tra xem co ban tai_androzoo.py "
              "nao khac dang chay khong." % (len(tat_ca) - ngoai - sau))
    return len(thieu), len(thua)


def la_hex64(x):
    return len(x) == 64 and all(c in "0123456789abcdef" for c in x)


def doc_danh_sach(dd):
    """Doc file danh sach SHA-256, moi dong mot ma bam. Bo dong trong va # ghi chu."""
    if not os.path.exists(dd):
        sys.exit("Khong thay file danh sach: %s" % dd)
    ra, hong, da_thay = [], 0, set()
    with open(dd, "r", encoding="utf-8-sig") as f:
        for dong in f:
            x = dong.strip().split(",")[0].strip().lower()
            if not x or x.startswith("#"):
                continue
            if not la_hex64(x):
                hong += 1
                continue
            if x in da_thay:
                continue
            da_thay.add(x)
            ra.append(x)
    if hong:
        print("  bo %d dong khong phai SHA-256" % hong)
    if not ra:
        sys.exit("File danh sach %s khong co ma bam nao dung dinh dang." % dd)
    return ra


def chon_theo_danh_sach(con, args, da_co):
    """Chon dung cac mau co trong file danh sach, KHONG loc theo trang_thai.

    Dung khi can tai lai mau da tung tai roi bi mat file: chon_mau chi lay
    trang_thai='chua' nen khong bao gio chon lai chung.
    """
    ds = doc_danh_sach(args.danh_sach)
    print("Doc %d ma bam tu %s" % (len(ds), args.danh_sach))
    con_lai = [h for h in ds if h not in da_co]
    if len(con_lai) != len(ds):
        print("  bo %d ma bam vi APK da co san tren dia" % (len(ds) - len(con_lai)))

    ra, thieu = [], []
    ten_cot = ["sha256", "pkg_name", "apk_size", "moc_ngay", "dex_date",
               "vt_detection", "vt_scan_date", "markets", "nhom"]
    for i in range(0, len(con_lai), 500):
        lo = con_lai[i:i + 500]
        sql = ("SELECT %s FROM ungvien WHERE sha256 IN (%s)"
               % (",".join(ten_cot), ",".join("?" * len(lo))))
        thay = set()
        for hang in con.execute(sql, lo):
            thay.add(str(hang[0]).lower())
            ra.append(dict(zip(ten_cot, hang)))
        thieu.extend(h for h in lo if h not in thay)
    if thieu:
        print("  %d ma bam khong co trong danh muc nen bo qua" % len(thieu))

    thu_tu = {h: i for i, h in enumerate(con_lai)}
    ra.sort(key=lambda m: thu_tu.get(str(m["sha256"]).lower(), 0))
    if any(a == "--so-luong" or a.startswith("--so-luong=") for a in sys.argv[1:]):
        if len(ra) > args.so_luong:
            print("  cat con %d mau dau theo --so-luong" % args.so_luong)
            ra = ra[:args.so_luong]
    return ra


def don_file_tam(thu_muc):
    """Xoa cac file .tam mo coi cua lan chay truoc.

    File .tam la ban tai dang do, chua kiem bam. No chi con sot lai khi tien
    trinh bi giet cung (tat may, taskkill, may ngu dong) truoc khi khoi don dep
    kip chay. De lai thi vua chiem dia vua de bi nham la mau that.
    """
    if not os.path.isdir(thu_muc):
        return
    tam = [t for t in os.listdir(thu_muc) if t.lower().endswith(".tam")]
    if not tam:
        return
    byte = 0
    xoa = 0
    for t in tam:
        dd = os.path.join(thu_muc, t)
        try:
            byte += os.path.getsize(dd)
            os.remove(dd)
            xoa += 1
        except OSError:
            pass
    print("Da xoa %d file .tam mo coi cua lan chay truoc (%.1f MB). Day la ban "
          "tai dang do, khong phai mau hop le." % (xoa, byte / 1024 / 1024))


def doc_linkapk(dd):
    """Doc danh sach kho APK tu LinkAPK.txt. Tra ve list (duong_dan, nhan).

    Dinh dang moi dong: "duong_dan | Nhan". Dong trong va dong bat dau bang #
    bi bo qua. Khong co file thi tra ve rong chu khong bao loi: may chua dung
    file nay van chay duoc nhu cu.
    """
    ra = []
    if not dd or not os.path.exists(dd):
        return ra
    with open(dd, "r", encoding="utf-8-sig") as f:
        for dong in f:
            dong = dong.strip().strip('"')
            if not dong or dong.startswith("#"):
                continue
            nhan = ""
            for dau in ("|", "\t", ";"):
                if dau in dong:
                    trai, phai = dong.split(dau, 1)
                    dong, nhan = trai.strip().strip('"'), phai.strip()
                    break
            ra.append((os.path.normpath(dong), nhan))
    return ra


def gom_kho(args):
    """Tap hop cac thu muc kho APK can doi chieu, va cac thu muc dang thieu.

    Lay tu hai cho: LinkAPK.txt (nguon chinh) va --kho-khac (them tay). Thu muc
    dich khong tinh vao day vi da duoc quet rieng. Tra ve (cac_kho, thieu):
    thieu la nhung duong dan co trong danh sach ma khong tim thay tren may,
    thuong la o roi chua cam vao.
    """
    dich = os.path.normcase(os.path.abspath(args.dich))
    cac_kho, thieu, da_thay = [], [], {dich}
    nguon = [dd for dd, _ in doc_linkapk(args.linkapk)]
    if not nguon:
        # Chua dung LinkAPK.txt thi quay ve nep cu: doi chieu voi kho GitHub.
        nguon = [KHO_KHAC_MAC_DINH]
    nguon += [x.strip().strip('"') for x in args.kho_khac.split(";")]
    for dd in nguon:
        if not dd:
            continue
        khoa = os.path.normcase(os.path.abspath(dd))
        if khoa in da_thay:
            continue
        da_thay.add(khoa)
        (cac_kho if os.path.isdir(dd) else thieu).append(dd)
    return cac_kho, thieu


def quet_kho_khac(danh_sach):
    """Tap SHA-256 dang co o cac kho APK khac (vi du kho thu tu GitHub).

    Chi doc ten file, khong mo file, nen quet vai nghin mau chi mat mot phan
    nghin giay. Thu muc khong ton tai thi bo qua chu khong bao loi: may khac
    hoac o dia khac thi duong dan mac dinh se khong co that.
    """
    ra = set()
    for thu_muc in danh_sach:
        thu_muc = thu_muc.strip()
        if not thu_muc:
            continue
        if not os.path.isdir(thu_muc):
            print("  bo qua kho doi chieu %s (khong tim thay thu muc)" % thu_muc)
            continue
        rieng = quet_thu_muc(thu_muc)
        ra |= rieng
        print("  kho doi chieu %s: %d mau" % (thu_muc, len(rieng)))
    return ra


def quet_thu_muc(thu_muc):
    """Tap SHA-256 da co san trong thu muc dich, de khong tai lai."""
    ra = set()
    if not os.path.isdir(thu_muc):
        return ra
    for ten in os.listdir(thu_muc):
        goc, duoi = os.path.splitext(ten)
        if duoi.lower() == ".apk" and len(goc) == 64:
            ra.add(goc.lower())
    return ra


# --------------------------------------------------------------------- ghi so

def ghi_excel(dich, dong_moi, lan_chay):
    """Ghi NOI THEM vao Ket_qua_AndroZoo.xlsx, khong ghi de. Sao luu ban cu."""
    try:
        from openpyxl import Workbook, load_workbook
        from openpyxl.styles import Alignment, Font, PatternFill
        from openpyxl.utils import get_column_letter
    except ImportError:
        print("Chua co openpyxl nen bo qua buoc ghi Excel. Cai bang: "
              "pip install openpyxl")
        return None

    dd = os.path.join(dich, TEN_EXCEL)
    if os.path.exists(dd):
        thu_muc_cu = os.path.join(dich, "_ban_cu")
        os.makedirs(thu_muc_cu, exist_ok=True)
        shutil.copy2(dd, os.path.join(
            thu_muc_cu, "%s_%s" % (datetime.datetime.now().strftime("%Y%m%d_%H%M%S"),
                                   TEN_EXCEL)))
        wb = load_workbook(dd)
    else:
        wb = Workbook()
        wb.remove(wb.active)

    if S_MAU not in wb.sheetnames:
        ws = wb.create_sheet(S_MAU)
        ws.append(COT_MAU)
    ws = wb[S_MAU]

    da_co = set()
    for hang in ws.iter_rows(min_row=2, min_col=2, max_col=2, values_only=True):
        if hang[0]:
            da_co.add(str(hang[0]).strip().lower())

    them = 0
    for m in dong_moi:
        if m["SHA-256"] in da_co:
            continue
        ws.append([m.get(c, "") for c in COT_MAU])
        da_co.add(m["SHA-256"])
        them += 1

    # dinh dang
    xanh = PatternFill("solid", fgColor="1F4E78")
    for o in ws[1]:
        o.font = Font(name="Times New Roman", bold=True, color="FFFFFF")
        o.fill = xanh
        o.alignment = Alignment(horizontal="center", vertical="center")
    rong = {"Lan_chay": 19, "SHA-256": 66, "pkg_name": 34, "Kich_thuoc_byte": 15,
            "Moc_ngay": 20, "dex_date": 20, "vt_detection": 12, "vt_scan_date": 20,
            "markets": 24, "Nhom": 10, "Duong_dan": 46, "Ghi_chu": 30}
    for i, c in enumerate(COT_MAU, 1):
        ws.column_dimensions[get_column_letter(i)].width = rong.get(c, 16)
    ws.freeze_panes = "A2"

    # sheet tong hop, dung lai moi lan ghi
    if S_TH in wb.sheetnames:
        wb.remove(wb[S_TH])
    wt = wb.create_sheet(S_TH)
    dem_nhom = {}
    dem_nam = {}
    tong_byte = 0
    for hang in ws.iter_rows(min_row=2, values_only=True):
        d = dict(zip(COT_MAU, hang))
        dem_nhom[d.get("Nhom") or "?"] = dem_nhom.get(d.get("Nhom") or "?", 0) + 1
        nam = str(d.get("Moc_ngay") or "")[:4] or "?"
        dem_nam[nam] = dem_nam.get(nam, 0) + 1
        try:
            tong_byte += int(d.get("Kich_thuoc_byte") or 0)
        except (TypeError, ValueError):
            pass
    wt.append(["Bang tong hop mau tai tu AndroZoo"])
    wt.append(["Cap nhat", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    wt.append([])
    wt.append(["Theo nhom (so engine bao doc ghi trong danh sach AndroZoo)"])
    wt.append(["Nhom", "So mau"])
    for k in sorted(dem_nhom):
        wt.append([k, dem_nhom[k]])
    wt.append([])
    wt.append(["Theo nam theo moc ngay moi nhat cua mau"])
    wt.append(["Nam", "So mau"])
    for k in sorted(dem_nam, reverse=True):
        wt.append([k, dem_nam[k]])
    wt.append([])
    wt.append(["Tong so mau", ws.max_row - 1])
    wt.append(["Tong dung luong (GB)", round(tong_byte / 1024 / 1024 / 1024, 2)])
    for hang in wt.iter_rows():
        for o in hang:
            o.font = Font(name="Times New Roman")
    wt["A1"].font = Font(name="Times New Roman", bold=True, size=13)
    wt.column_dimensions["A"].width = 40
    wt.column_dimensions["B"].width = 22

    wb.save(dd)
    return dd, them


# ----------------------------------------------------------------------- chay

def chay(args):
    if not os.path.exists(args.db):
        sys.exit("Chua co danh muc %s. Chay chuan_bi_danh_muc.py truoc." % args.db)
    os.makedirs(args.dich, exist_ok=True)

    keys = doc_keys(args)
    kho_key = KhoKey(keys)
    # timeout 60 giay thay vi 5 giay mac dinh: neu co tien trinh khac dang ghi
    # thi cho thay vi bao loi "database is locked" ngay lap tuc.
    con = sqlite3.connect(args.db, timeout=60.0)
    con.execute("PRAGMA busy_timeout=60000")

    don_file_tam(args.dich)
    print("Quet thu muc dich ...")
    tren_dia = quet_thu_muc(args.dich)
    print("  %d file APK trong %s" % (len(tren_dia), args.dich))

    kho_khac, thieu_kho = set(), []
    if args.khong_doi_chieu_kho_khac:
        print("Bo qua cac kho khac theo --khong-doi-chieu-kho-khac.")
    else:
        cac_kho, thieu_kho = gom_kho(args)
        print("Quet %d kho APK khac (%s) ..."
              % (len(cac_kho), args.linkapk if os.path.exists(args.linkapk)
                 else "khong thay LinkAPK.txt, chi dung --kho-khac"))
        kho_khac = quet_kho_khac(cac_kho)
        for dd in thieu_kho:
            print("  THIEU kho %s (o chua cam vao may?)" % dd)

    da_co = set(tren_dia) | kho_khac

    # Chi cho phep ha dong 'da_tai' xuong 'chua' khi da nhin thay du moi kho.
    # Thieu mot o roi ma van ha thi vai nghin mau nam tren o do se bi tai lai.
    cho_ha = not thieu_kho and not args.khong_doi_chieu_kho_khac
    if not cho_ha:
        print("Che do doi chieu an toan: chi nang trang thai len, khong ha xuong.")
    dong_bo_trang_thai(con, da_co, cho_ha, chi_xem=args.thu_thoi)

    if args.danh_sach:
        mau = chon_theo_danh_sach(con, args, da_co)
        if not mau:
            print("Danh sach khong con ma bam nao can tai: hoac da co du file "
                  "tren dia, hoac khong ma nao nam trong danh muc.")
            return
    else:
        mau = chon_mau(con, args, da_co, kho_khac)
        if not mau:
            print("Khong con ung vien nao dat dieu kien. Xem lai --nhom / --tu-nam, "
                  "hoac chay chuan_bi_danh_muc.py voi danh sach moi hon.")
            return
    uoc = sum(m["apk_size"] for m in mau) / 1024 / 1024 / 1024
    print("Se tai %d mau, uoc tinh %.2f GB, %d luong, %d key."
          % (len(mau), uoc, args.luong, len(keys)))
    try:
        con_trong = shutil.disk_usage(args.dich).free / 1024 / 1024 / 1024
        print("O dia dich con trong %.1f GB, muc du tru %.1f GB."
              % (con_trong, args.du_tru))
        if con_trong <= args.du_tru:
            print()
            print("DUNG LAI: cho trong da o duoi muc du tru, khong tai gi ca.")
            print("Don bot dia roi chay lai, hoac ha --du-tru neu chac chan.")
            return
        if uoc > (con_trong - args.du_tru) * 0.8:
            print()
            print("DUNG LAI: dot tai nay chiem hon 80% phan dia dung duoc")
            print("(cho trong tru di muc du tru).")
            print("Cach xu ly: giam --so-luong, them --kich-thuoc 25 de bo mau")
            print("lon, hoac them --tu-nam 2022 --den-nam 2022 (mau 2022 trung")
            print("binh 13 MB, nhe hon mau 2026 gan ba lan).")
            print("Van muon chay thi them --bo-qua-canh-bao.")
            if not args.bo_qua_canh_bao:
                return
    except OSError:
        pass
    if args.thu_thoi:
        for m in mau[:20]:
            print("  %s  %-32s %8.1f MB  moc=%s  vt=%s"
                  % (m["sha256"][:16], (m["pkg_name"] or "")[:32],
                     m["apk_size"] / 1024 / 1024, m["moc_ngay"], m["vt_detection"]))
        print("  ... (che do --thu-thoi, khong tai gi ca)")
        return

    lan_chay = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    xong = loi = 0
    dong_moi = []
    t0 = time.time()
    dung = threading.Event()
    tra_cuu = {m["sha256"]: m for m in mau}

    canh_bao_dia = threading.Event()

    def con_du_dia():
        """Con du cho de tai tiep khong.

        Kiem tra truoc TUNG file chu khong chi mot lan luc bat dau: mot dot
        vai nghin mau chay ca dem, den giua chung o dia day thi cac file sau
        deu tai hong hoac ghi cut, va con lam ket ca Windows. Het cho thi
        dung han dot nay mot cach sach se - phan da tai van con nguyen trong
        SQLite nen chay lai la di tiep.
        """
        if args.du_tru <= 0:
            return True
        try:
            con_trong = shutil.disk_usage(args.dich).free / 1024 / 1024 / 1024
        except OSError:
            return True
        if con_trong > args.du_tru:
            return True
        if not canh_bao_dia.is_set():
            canh_bao_dia.set()
            print()
            print("  [dia] Chi con %.1f GB, duoi muc du tru %.1f GB. Dung dot "
                  "tai o day." % (con_trong, args.du_tru))
        dung.set()
        return False

    def cong_viec(m):
        if dung.is_set():
            return None
        if not con_du_dia():
            return None
        for lan in range(3):
            key = kho_key.lay()
            try:
                return tai_mot(m, kho_key, args.dich, args.nhip, args.cho)
            except Loi as e:
                if e.doi_key == "cham_tran":
                    time.sleep(min(60, 5 * (2 ** lan)) + random.random())
                    kho_key.chuyen(key, "cham tran")
                    continue
                if e.doi_key == "hong":
                    if kho_key.chuyen(key, "hong") is None:
                        dung.set()
                        return m["sha256"], False, "het key dung duoc"
                    continue
                dung.set()
                return m["sha256"], False, e.ly_do
        return m["sha256"], False, "thu 3 lan van khong duoc"

    try:
        with ThreadPoolExecutor(max_workers=args.luong) as pool:
            for kq in pool.map(cong_viec, mau):
                if kq is None:
                    continue
                sha, ok, ly_do = kq
                m = tra_cuu[sha]
                if ok:
                    xong += 1
                    con.execute(
                        "UPDATE ungvien SET trang_thai='da_tai', thoi_diem_tai=?, "
                        "ghi_chu=? WHERE sha256=?", (lan_chay, ly_do, sha))
                    dong_moi.append({
                        "Lan_chay": lan_chay, "SHA-256": sha,
                        "pkg_name": m["pkg_name"],
                        "Kich_thuoc_byte": m["apk_size"],
                        "Moc_ngay": m["moc_ngay"],
                        "dex_date": m["dex_date"],
                        "vt_detection": m["vt_detection"],
                        "vt_scan_date": m["vt_scan_date"],
                        "markets": m["markets"], "Nhom": m["nhom"],
                        "Duong_dan": os.path.join(args.dich, sha + ".apk"),
                        "Ghi_chu": ly_do,
                    })
                else:
                    loi += 1
                    con.execute(
                        "UPDATE ungvien SET trang_thai='loi', "
                        "so_lan_thu=so_lan_thu+1, ghi_chu=? WHERE sha256=?",
                        (ly_do, sha))
                if (xong + loi) % 10 == 0:
                    con.commit()
                    toc = (xong + loi) / max(1e-9, time.time() - t0)
                    print("  %d/%d xong, %d loi, %.1f mau/phut"
                          % (xong, len(mau), loi, toc * 60))
    except KeyboardInterrupt:
        print("\nDa bam Ctrl+C. Dang luu phan da lam ...")
    finally:
        con.commit()

    print()
    print("=" * 66)
    print("Tai duoc %d mau, %d mau loi, het %.1f phut."
          % (xong, loi, (time.time() - t0) / 60))
    if dong_moi:
        kq = ghi_excel(THU_MUC, dong_moi, lan_chay)
        if kq:
            dd, them = kq
            print("Ghi them %d dong vao %s" % (them, dd))
    con_lai = con.execute(
        "SELECT COUNT(*) FROM ungvien WHERE trang_thai='chua'").fetchone()[0]
    bi_loi = con.execute(
        "SELECT COUNT(*) FROM ungvien WHERE trang_thai='loi'").fetchone()[0]
    print("Con %d ung vien chua tai, %d mau dang o trang thai loi." % (con_lai, bi_loi))
    if bi_loi:
        print("Tai lai phan loi bang: python tai_androzoo.py --tiep-tuc "
              "--so-luong %d" % min(bi_loi, 500))
    con.close()


def main():
    p = argparse.ArgumentParser(description="Tai APK tu AndroZoo theo danh muc.")
    p.add_argument("--db", default=os.path.join(THU_MUC, "androzoo_index.db"))
    p.add_argument("--dich", default=os.path.join(THU_MUC, "apk"),
                   help="Thu muc luu APK cua dot nay, mac dinh la thu muc apk "
                        "canh script. Tro sang o roi de tai vao do, vi du "
                        r"--dich F:\ApkAndroZoo")
    p.add_argument("--so-luong", type=int, default=200,
                   help="So mau tai trong lan chay nay")
    p.add_argument("--danh-sach", default="",
                   help="File text chua danh sach SHA-256 can tai, moi dong mot "
                        "ma bam. Khi co tham so nay thi bo qua --nhom / --tu-nam "
                        "/ --vt-toi-thieu va khong loc theo trang_thai trong "
                        "danh muc, nen tai lai duoc ca mau da tung tai. Mac dinh "
                        "tai het danh sach; them --so-luong de cat bot")
    p.add_argument("--nhom", default="",
                   help="lanh, nghi, ma_doc, chua_quet - cach nhau bang dau phay")
    p.add_argument("--tu-nam", type=int, default=0,
                   help="Chi tai mau tu nam nay tro di (0 = theo danh muc)")
    p.add_argument("--den-nam", type=int, default=0,
                   help="Chi tai mau den het nam nay (0 = khong gioi han). "
                        "Dung de lay rieng mot dai nam, vi du --tu-nam 2022 "
                        "--den-nam 2022")
    p.add_argument("--du-tru", type=float, default=20.0,
                   help="Giu lai bay nhieu GB trong o dia dich. Dot tai tu "
                        "dung khi cho trong tut xuong duoi muc nay, mac dinh "
                        "20 GB. Dat 0 de tat")
    p.add_argument("--kho-khac", default="",
                   help="Them thu muc APK de doi chieu, ngoai cac thu muc da co "
                        "trong LinkAPK.txt. Nhieu thu muc thi cach nhau bang dau "
                        "cham phay. Mac dinh de trong vi LinkAPK.txt da liet ke "
                        "du; khong co LinkAPK.txt thi script tu doi chieu voi "
                        + KHO_KHAC_MAC_DINH)
    p.add_argument("--linkapk", default=LINKAPK_MAC_DINH,
                   help="File liet ke moi kho APK cua du an, moi dong mot thu "
                        "muc dang 'duong_dan | Nhan'. Script doc file nay de "
                        "biet mau nao da co o o khac. Mac dinh: "
                        + LINKAPK_MAC_DINH)
    p.add_argument("--khong-doi-chieu-kho-khac", action="store_true",
                   help="Khong doi chieu voi kho APK khac, chi tranh trung "
                        "trong thu muc dich. Luc do script cung khong ha dong "
                        "da_tai nao xuong chua, vi khong con nhin thay du kho")
    p.add_argument("--kich-thuoc", type=int, default=0,
                   help="Bo qua mau lon hon so MB nay (0 = theo danh muc). "
                        "Dung khi o dia con it")
    p.add_argument("--vt-toi-thieu", type=int, default=0,
                   help="Chi tai mau co it nhat bay nhieu engine bao doc. "
                        "Nguong 4 chi la muc toi thieu de goi la ma doc; dat "
                        "10 tro len de lay mau chac chan la ma doc")
    p.add_argument("--vt-toi-da", type=int, default=0,
                   help="Chi tai mau co nhieu nhat bay nhieu engine bao doc")
    p.add_argument("--luong", type=int, default=4,
                   help="So luong tai dong thoi, mac dinh 4")
    p.add_argument("--nhip", type=float, default=0.0,
                   help="Nghi bao nhieu giay sau moi file, mac dinh 0")
    p.add_argument("--cho", type=int, default=120,
                   help="So giay cho toi da moi yeu cau, mac dinh 120")
    p.add_argument("--key", default="", help="API key, cach nhau bang dau phay")
    p.add_argument("--tiep-tuc", action="store_true",
                   help="Tai lai ca nhung mau dang o trang thai loi")
    p.add_argument("--so-lan-thu-toi-da", type=int, default=3,
                   help="Bo han mau da thu qua so lan nay, mac dinh 3")
    p.add_argument("--ngau-nhien", action="store_true",
                   help="Chon ngau nhien thay vi uu tien mau moi nhat")
    p.add_argument("--thu-thoi", action="store_true",
                   help="Chi in danh sach se tai, khong tai that")
    p.add_argument("--bo-qua-canh-bao", action="store_true",
                   help="Van tai du dot nay chiem hon 80%% cho trong o dia")
    p.add_argument("--bo-qua-khoa", action="store_true",
                   help="Chay du dang co ban khac chay. Chi dung khi chac chan "
                        "khoa la tan du cua lan chay truoc bi ngat dot ngot")
    args = p.parse_args()
    args.nhom = {x.strip() for x in args.nhom.split(",") if x.strip()}
    if args.thu_thoi:
        chay(args)  # che do xem thu khong ghi gi, khong can khoa
        return
    with DangChay(THU_MUC, args.bo_qua_khoa):
        chay(args)


if __name__ == "__main__":
    main()
