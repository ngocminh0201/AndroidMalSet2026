# -*- coding: utf-8 -*-
"""Buoc 0 cua tuyen AndroZoo: bien danh sach khong lo cua AndroZoo thanh mot
danh muc ung vien nho gon de tra cuu trong vai giay.

Danh sach latest_with-added-date.csv cua AndroZoo nang hon 7 GB, vai chuc
trieu dong. Khong
the moi lan muon tai vai nghin mau lai quet lai tu dau. Script nay doc file
theo tung dong (nhan ca ban .csv lan ban .csv.gz, khong can giai nen), giu lai
nhung dong dat tieu chi cua bo du lieu, roi nap vao mot file SQLite nho gon.

Doc cot theo TEN trong dong tieu de chu khong theo VI TRI, nen chay dung voi
ca ban latest_with-added-date.csv (12 cot, co cot 'added' ghi ngay mau duoc
dua vao kho) lan ban latest.csv (11 cot, khong co cot do nen phai lay
vt_scan_date lam moc). Script in ro no dang dung cot nao.

Chay lai script voi danh sach moi hon thi nhung dong da co giu nguyen trang
thai (da tai / bi loi), chi them phan moi. Do la co che cap nhat dinh ky.

Cu phap:

    python chuan_bi_danh_muc.py --danh-sach "latest_with-added-date.csv"

Cac tham so khac xem phan cuoi file hoac chay voi --help.
"""

import argparse
import csv
import datetime
import gzip
import io
import os
import sqlite3
import sys
import time

THU_MUC = os.path.dirname(os.path.abspath(__file__))

# Ten cot theo tai lieu AndroZoo. Doc theo TEN chu khong theo VI TRI: neu mai
# nay ho them cot hoac doi thu tu thi script van chay dung, khong lech du lieu.
COT_BAT_BUOC = ["sha256", "apk_size", "pkg_name"]
COT_LAY = ["sha256", "sha1", "md5", "dex_date", "apk_size", "pkg_name",
           "vercode", "vt_detection", "vt_scan_date", "dex_size", "markets",
           "added"]

NGUONG_MA_DOC = 4  # giong nguong trong quet_virustotal.py

LUOC_DO = """
CREATE TABLE IF NOT EXISTS ungvien (
    sha256        TEXT PRIMARY KEY,
    sha1          TEXT,
    md5           TEXT,
    pkg_name      TEXT,
    apk_size      INTEGER,
    dex_date      TEXT,
    vercode       TEXT,
    vt_detection  INTEGER,
    vt_scan_date  TEXT,
    dex_size      INTEGER,
    markets       TEXT,
    added         TEXT,
    moc_ngay      TEXT,
    nam           TEXT,
    nhom          TEXT,
    trang_thai    TEXT DEFAULT 'chua',
    so_lan_thu    INTEGER DEFAULT 0,
    thoi_diem_tai TEXT,
    ghi_chu       TEXT
);
CREATE INDEX IF NOT EXISTS ix_chon  ON ungvien (nhom, trang_thai, moc_ngay DESC);
CREATE INDEX IF NOT EXISTS ix_trang ON ungvien (trang_thai);
CREATE TABLE IF NOT EXISTS lan_nap (
    thoi_diem   TEXT,
    danh_sach   TEXT,
    dong_doc    INTEGER,
    dong_nhan   INTEGER,
    dong_moi    INTEGER,
    dong_hong   INTEGER,
    tieu_chi    TEXT,
    cot_moc     TEXT
);
"""


def xep_nhom(vt):
    """Chia ung vien theo so engine bao doc ghi san trong danh sach AndroZoo."""
    if vt is None:
        return "chua_quet"
    if vt == 0:
        return "lanh"
    if vt < NGUONG_MA_DOC:
        return "nghi"
    return "ma_doc"


def mo_danh_sach(duong_dan):
    """Mo file .csv hoac .csv.gz, tra ve doi tuong doc text."""
    if duong_dan.lower().endswith(".gz"):
        f = gzip.open(duong_dan, "rt", encoding="utf-8", errors="replace",
                      newline="")
    else:
        f = open(duong_dan, "rt", encoding="utf-8", errors="replace",
                 newline="")
    return f


def doc_tieu_de(reader, duong_dan):
    try:
        tieu_de = next(reader)
    except StopIteration:
        sys.exit("File danh sach rong: %s" % duong_dan)
    tieu_de = [c.strip().lstrip("\ufeff") for c in tieu_de]
    vi_tri = {ten: i for i, ten in enumerate(tieu_de)}
    thieu = [c for c in COT_BAT_BUOC if c not in vi_tri]
    if thieu:
        sys.exit("File danh sach thieu cot bat buoc: %s\nDong tieu de doc duoc: %s"
                 % (", ".join(thieu), ", ".join(tieu_de)))
    return vi_tri, tieu_de


def so_nguyen(chuoi):
    chuoi = (chuoi or "").strip()
    if not chuoi:
        return None
    try:
        return int(float(chuoi))
    except ValueError:
        return None


def lay_nam(*chuoi_ngay):
    """Lay nam tu chuoi ngay dau tien co dang 4 chu so hop ly."""
    for c in chuoi_ngay:
        c = (c or "").strip()
        if len(c) >= 4 and c[:4].isdigit():
            nam = int(c[:4])
            if 1990 <= nam <= 2100:
                return str(nam)
    return ""


def nap(args):
    t0 = time.time()
    con = sqlite3.connect(args.db)
    con.executescript(LUOC_DO)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=OFF")

    truoc = con.execute("SELECT COUNT(*) FROM ungvien").fetchone()[0]
    kich_thuoc_toi_da = args.kich_thuoc * 1024 * 1024

    f = mo_danh_sach(args.danh_sach)
    reader = csv.reader(f)
    vi_tri, tieu_de = doc_tieu_de(reader, args.danh_sach)
    co_added = "added" in vi_tri
    print("Tieu de doc duoc (%d cot): %s" % (len(tieu_de), ", ".join(tieu_de)))
    if co_added:
        cot_moc = "added"
        print("Moc 'moi nhat' lay theo cot 'added' (ngay mau duoc dua vao AndroZoo).")
    elif "vt_scan_date" in vi_tri:
        cot_moc = "vt_scan_date"
        print("File nay KHONG co cot 'added' (day la ban latest.csv 11 cot).")
        print("Moc 'moi nhat' lay theo cot 'vt_scan_date' - ngay VirusTotal quet")
        print("lan cuoi. AndroZoo quet ngay khi nhan mau nen hai moc nay xap xi")
        print("nhau, nhung khong dong nhat. Muon dung moc chinh xac thi tai ban")
        print("latest_with-added-date.csv o https://androzoo.uni.lu/lists")
    else:
        cot_moc = "dex_date"
        print("CANH BAO: file khong co ca 'added' lan 'vt_scan_date'. Phai dua vao")
        print("          dex_date, ma AndroZoo canh bao truong nay khong dang tin.")
    so_cot = len(tieu_de)

    dong_doc = dong_nhan = dong_hong = 0
    lo = []

    def do_lo():
        # Ghi de cac cot doi theo thoi gian (VirusTotal quet lai thi vt_detection
        # thay doi, ban danh sach co cot added thi bo sung moc chinh xac hon),
        # nhung GIU NGUYEN trang_thai / so_lan_thu / thoi_diem_tai de khong xoa
        # mat tien do tai cua nhung lan chay truoc.
        nonlocal lo
        if not lo:
            return
        con.executemany(
            "INSERT INTO ungvien "
            "(sha256,sha1,md5,pkg_name,apk_size,dex_date,vercode,vt_detection,"
            " vt_scan_date,dex_size,markets,added,moc_ngay,nam,nhom) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(sha256) DO UPDATE SET "
            "  vt_detection = excluded.vt_detection,"
            "  vt_scan_date = excluded.vt_scan_date,"
            "  markets      = excluded.markets,"
            "  nhom         = excluded.nhom,"
            "  added        = CASE WHEN excluded.added <> '' "
            "                      THEN excluded.added ELSE ungvien.added END,"
            "  moc_ngay     = CASE WHEN excluded.added <> '' "
            "                      THEN excluded.added ELSE ungvien.moc_ngay END,"
            "  nam          = excluded.nam", lo)
        con.commit()
        lo = []

    co_kich_thuoc = os.path.getsize(args.danh_sach)
    uoc_tong = 0
    do_dai_mau = 0
    MAU = 200000  # so dong dau dung de uoc do dai trung binh mot dong
    # Khong dung f.tell(): Python cam goi tell() tren file text dang duoc duyet
    # bang next() ("telling position disabled by next() call"), ma csv.reader
    # thi duyet file bang next(). Uoc do dai dong tu chinh noi dung doc duoc.
    print("Dang doc %s (%.1f GB) ..." % (args.danh_sach, co_kich_thuoc / 1024**3))
    for dong in reader:
        dong_doc += 1
        if dong_doc <= MAU and not args.danh_sach.lower().endswith(".gz"):
            # do dai dong = tong do dai cac truong + dau phay ngan cach + xuong dong
            do_dai_mau += sum(len(x) for x in dong) + len(dong) + 1
            if dong_doc == MAU:
                uoc_tong = int(co_kich_thuoc / max(1.0, do_dai_mau / float(MAU)))
                print("  (uoc chung %.1f trieu dong tat ca)"
                      % (uoc_tong / 1000000.0))
        if dong_doc % 2000000 == 0:
            da = time.time() - t0
            if uoc_tong:
                con_lai = da / dong_doc * max(0, uoc_tong - dong_doc)
                print("  ... %s trieu dong (%.0f%%), giu %s, da %.0f phut, "
                      "con khoang %.0f phut"
                      % (dong_doc // 1000000, 100.0 * dong_doc / uoc_tong,
                         dong_nhan, da / 60, con_lai / 60))
            else:
                print("  ... da doc %s trieu dong, giu %s, %.0f phut"
                      % (dong_doc // 1000000, dong_nhan, da / 60))
        # Dong hong: AndroZoo co it nhat mot ban ghi co dau phay trong pkg_name
        # (goi snaggamea) lam lech so truong. Bo qua thay vi de vo ca lan chay.
        if len(dong) != so_cot:
            dong_hong += 1
            continue
        try:
            kich_thuoc = so_nguyen(dong[vi_tri["apk_size"]])
            if kich_thuoc is None or kich_thuoc <= 0:
                dong_hong += 1
                continue
            if kich_thuoc > kich_thuoc_toi_da:
                continue

            added = dong[vi_tri["added"]] if co_added else ""
            vt_scan = dong[vi_tri["vt_scan_date"]] if "vt_scan_date" in vi_tri else ""
            dex_date = dong[vi_tri["dex_date"]] if "dex_date" in vi_tri else ""
            moc = (added or vt_scan or dex_date or "").strip()
            nam = lay_nam(added, vt_scan, dex_date)
            if not nam or int(nam) < args.tu_nam:
                continue

            vt = so_nguyen(dong[vi_tri["vt_detection"]]) if "vt_detection" in vi_tri else None
            nhom = xep_nhom(vt)
            if args.nhom and nhom not in args.nhom:
                continue

            thi_truong = dong[vi_tri["markets"]] if "markets" in vi_tri else ""
            if args.markets:
                co = set((thi_truong or "").split("|"))
                if not co.intersection(args.markets):
                    continue

            sha256 = dong[vi_tri["sha256"]].strip().lower()
            if len(sha256) != 64:
                dong_hong += 1
                continue

            lo.append((
                sha256,
                dong[vi_tri["sha1"]].strip().lower() if "sha1" in vi_tri else "",
                dong[vi_tri["md5"]].strip().lower() if "md5" in vi_tri else "",
                dong[vi_tri["pkg_name"]] if "pkg_name" in vi_tri else "",
                kich_thuoc,
                dex_date,
                dong[vi_tri["vercode"]] if "vercode" in vi_tri else "",
                vt,
                vt_scan,
                so_nguyen(dong[vi_tri["dex_size"]]) if "dex_size" in vi_tri else None,
                thi_truong,
                added,
                moc,
                nam,
                nhom,
            ))
            dong_nhan += 1
            if len(lo) >= 50000:
                do_lo()
        except IndexError:
            dong_hong += 1
            continue

    do_lo()
    f.close()

    sau = con.execute("SELECT COUNT(*) FROM ungvien").fetchone()[0]
    tieu_chi = ("tu nam %s, kich thuoc <= %s MB, nhom = %s, markets = %s"
                % (args.tu_nam, args.kich_thuoc,
                   ",".join(sorted(args.nhom)) if args.nhom else "tat ca",
                   ",".join(sorted(args.markets)) if args.markets else "tat ca"))
    con.execute("INSERT INTO lan_nap VALUES (?,?,?,?,?,?,?,?)",
                (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 os.path.basename(args.danh_sach), dong_doc, dong_nhan,
                 sau - truoc, dong_hong, tieu_chi, cot_moc))
    con.commit()

    print()
    print("=" * 66)
    print("Doc %s dong, giu lai %s dong dat tieu chi, bo %s dong hong."
          % (dong_doc, dong_nhan, dong_hong))
    print("Danh muc truoc: %s ung vien -> sau: %s (them moi %s, lam moi %s)."
          % (truoc, sau, sau - truoc, dong_nhan - (sau - truoc)))
    print("Tieu chi: %s" % tieu_chi)
    print("Cot dung lam moc 'moi nhat': %s" % cot_moc)
    print("Het %.0f phut." % ((time.time() - t0) / 60))
    thong_ke(con)
    con.close()


def thong_ke(con):
    print()
    print("Ung vien theo nam va theo nhom (so engine bao doc ghi trong AndroZoo):")
    nhoms = ["lanh", "nghi", "ma_doc", "chua_quet"]
    print("  %-6s %10s %10s %10s %10s %10s"
          % ("Nam", "lanh(0)", "nghi(1-3)", "ma_doc(>=4)", "chua_quet", "Cong"))
    tong = {n: 0 for n in nhoms}
    for nam, in con.execute("SELECT DISTINCT nam FROM ungvien ORDER BY nam DESC"):
        hang = {n: 0 for n in nhoms}
        for n, c in con.execute(
                "SELECT nhom, COUNT(*) FROM ungvien WHERE nam=? GROUP BY nhom",
                (nam,)):
            hang[n] = c
            tong[n] = tong.get(n, 0) + c
        print("  %-6s %10s %10s %10s %10s %10s"
              % (nam, hang["lanh"], hang["nghi"], hang["ma_doc"],
                 hang["chua_quet"], sum(hang.values())))
    print("  %-6s %10s %10s %10s %10s %10s"
          % ("CONG", tong["lanh"], tong["nghi"], tong["ma_doc"],
             tong["chua_quet"], sum(tong.values())))

    print()
    print("Trang thai tai:")
    for tt, c in con.execute(
            "SELECT trang_thai, COUNT(*) FROM ungvien GROUP BY trang_thai"):
        print("  %-12s %s" % (tt, c))

    dung_luong = con.execute(
        "SELECT SUM(apk_size) FROM ungvien WHERE trang_thai='chua'").fetchone()[0]
    if dung_luong:
        print()
        print("Neu tai het phan chua tai: %.1f GB (uoc tinh theo cot apk_size)."
              % (dung_luong / 1024 / 1024 / 1024))


def main():
    p = argparse.ArgumentParser(
        description="Loc danh sach AndroZoo thanh danh muc ung vien SQLite.")
    p.add_argument("--danh-sach", default="",
                   help="Duong dan file danh sach. Bo trong thi tu tim file "
                        "latest*.csv hoac latest*.csv.gz canh script")
    p.add_argument("--db", default=os.path.join(THU_MUC, "androzoo_index.db"),
                   help="File SQLite dich, mac dinh androzoo_index.db canh script")
    p.add_argument("--tu-nam", type=int, default=2021,
                   help="Chi giu mau tu nam nay tro di, mac dinh 2021")
    p.add_argument("--kich-thuoc", type=int, default=100,
                   help="Kich thuoc APK toi da tinh bang MB, mac dinh 100")
    p.add_argument("--nhom", default="",
                   help="Chi giu cac nhom nay, cach nhau bang dau phay: "
                        "lanh,nghi,ma_doc,chua_quet. Bo trong = giu tat ca")
    p.add_argument("--markets", default="",
                   help="Chi giu mau xuat hien o cac cho nay, cach nhau bang "
                        "dau phay. Bo trong = khong loc theo cho")
    p.add_argument("--chi-thong-ke", action="store_true",
                   help="Khong nap gi, chi in thong ke danh muc dang co")
    args = p.parse_args()

    args.nhom = {x.strip() for x in args.nhom.split(",") if x.strip()}
    args.markets = {x.strip() for x in args.markets.split(",") if x.strip()}

    if args.chi_thong_ke:
        if not os.path.exists(args.db):
            sys.exit("Chua co file danh muc %s" % args.db)
        con = sqlite3.connect(args.db)
        thong_ke(con)
        con.close()
        return

    if not args.danh_sach:
        import glob
        ung = sorted(glob.glob(os.path.join(THU_MUC, "latest*.csv"))
                     + glob.glob(os.path.join(THU_MUC, "latest*.csv.gz")))
        # uu tien ban co cot added, roi den ban .csv (doc nhanh hon .gz)
        ung.sort(key=lambda x: (0 if "added" in os.path.basename(x) else 1,
                                0 if not x.endswith(".gz") else 1))
        if not ung:
            sys.exit("Thieu --danh-sach va khong thay file latest*.csv canh "
                     "script. Tai file tai https://androzoo.uni.lu/lists")
        args.danh_sach = ung[0]
        print("Tu chon file danh sach: %s" % args.danh_sach)
    if not os.path.exists(args.danh_sach):
        sys.exit("Khong thay file %s" % args.danh_sach)
    nap(args)


if __name__ == "__main__":
    main()
