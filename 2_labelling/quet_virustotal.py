# -*- coding: utf-8 -*-
"""quet_virustotal.py - tra ket qua VirusTotal cho tung file APK trong mot thu muc.

Buoc 2 (gan nhan) cua quy trinh 5 buoc xay dung AndroidMalSet2026: moi mau duoc
gui len VirusTotal, lay ve so cong cu diet virus danh dau la doc, roi tu do ket
luan mau co phai ma doc hay khong. Quy uoc mac dinh cua bo du lieu: CHI CAN
1 engine bao doc la ket luan ma doc, khong engine nao bao thi la lanh tinh.
Khong con nhom trung gian "nghi ngo". Buoc chuan hoa ve 5 nhan cuoi (Benign,
Adware, Banking, Riskware, SMS) lam o gan_nhan_gemini.py bang mo hinh ngon ngu,
script nay chi ghi san goi y de doi chieu.

Diem quan trong: script KHONG tai file len VirusTotal. No chi tra theo ma bam
SHA-256 (endpoint GET /api/v3/files/{sha256}). Mau nao VirusTotal chua co thi
ghi trang thai "Chua co tren VT" roi bo qua - vua tiet kiem quota, vua khong
phat tan mau ra ngoai.

Gioi han cua API key mien phi: 4 luot/phut, 500 luot/ngay, 15.500 luot/thang.
Script tu giu nhip 16 giay mot luot cho MOI KEY va tu dem so luot da dung trong
ngay (file _quota_virustotal.json). Chay den khi het quota ngay thi dung lai va
bao so mau con lai; hom sau chay lai dung cau lenh cu, no bo qua nhung mau da co
ket qua trong Excel va di tiep.

Ve loi 429: VirusTotal dung chung mot ma 429 cho ca "goi qua 4 luot/phut", "het
han muc gio" lan "het 500 luot/ngay", va loi do chi noi ve RIENG cai key vua
goi. Mot key bi 429 khong he co nghia la cac key con lai cung het. Vi vay script
khong doan nua: truoc khi chay va moi lan gap 429, no hoi thang VirusTotal so
luot that su da dung cua tung key (endpoint /users/{key}/overall_quotas, nhan
luon chuoi API key lam id, khong ton luot tra file nao). Het han ngay thi bo key
do toi sang mai; het han gio thi hoan toi dau gio sau; con du luot ma van 429
thi dung la goi qua nhanh, hoan 65 giay roi chay tiep bang key khac. Xem bang
han muc that bang --kiem-tra-key. Neu ca sau key cung 429 mot luc trong khi bang
han muc van bao con du luot thi nhieu kha nang bi chan theo dia chi IP: ha nhip
ca may bang --nhip-chung 4.

Ket qua ghi noi them vao Ket_qua_VirusTotal.xlsx (khong bao gio ghi de), ban
JSON goc cua tung mau luu trong thu muc phan_hoi_json de lam minh chung.

Che do --tinh-lai: doc lai toan bo file JSON trong phan_hoi_json roi dung lai
Excel theo nguong hien hanh, KHONG goi API va khong ton mot luot quota nao. Dung
khi doi quy uoc nguong, hoac khi muon dung lai Excel sau su co. Cot Nhan_Gemini
va cot Lan_chay cua tung dong deu duoc giu nguyen.

Vi du chay:
    python quet_virustotal.py --thu-muc "D:\\APK_GitHub\\apk"
    python quet_virustotal.py --thu-muc "D:\\APK_GitHub\\apk" --gioi-han 20
    python quet_virustotal.py --kiem-tra-key
    python quet_virustotal.py --thu-muc "D:\\APK_GitHub\\apk" --noi-tiep
    python quet_virustotal.py --tinh-lai
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

API = "https://www.virustotal.com/api/v3/files/"
# Endpoint bao so luot that su da dung cua mot key. Nhan luon chuoi API key lam
# id, khong can biet ten tai khoan.
API_HAN_MUC = "https://www.virustotal.com/api/v3/users/%s/overall_quotas"
# Endpoint du phong: tra ve ho so tai khoan, trong do co muc quotas.
API_NGUOI_DUNG = "https://www.virustotal.com/api/v3/users/%s"
TEN_FILE_KEY = "api_key.txt"
TEN_FILE_EXCEL = "Ket_qua_VirusTotal.xlsx"
TEN_FILE_QUOTA = "_quota_virustotal.json"
S_KQ, S_TH = "Ket_qua_VT", "Tong_hop"

# Nhan_Gemini do gan_nhan_gemini.py ghi nguoc vao day. Script nay khong tu sinh ra
# gia tri cho cot do, chi giu lai gia tri da co khi ghi lai file.
COT = ["Lan_chay", "SHA-256", "Ten_file", "Dung_luong_byte", "Trang_thai",
       "So_engine_phat_hien", "Tong_so_engine", "Ty_le_phat_hien", "Ket_luan",
       "Nhan_goi_y", "Nhan_Gemini", "Ho_ma_doc", "Nhom_de_doa", "Lan_gui_dau_tien",
       "Lan_quet_gan_nhat", "Goi_Android", "Duong_dan", "Ghi_chu"]
COT_GIU_LAI = ("Nhan_Gemini",)
COT_SO = {"Dung_luong_byte", "So_engine_phat_hien", "Tong_so_engine"}

FONT = "Times New Roman"
XANH = PatternFill("solid", fgColor="1F4E78")
DO_NHAT = PatternFill("solid", fgColor="FCE4D6")
XAM = PatternFill("solid", fgColor="D9E1F2")

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")

# Bi 429 thi hoan key do bay nhieu giay roi moi dung lai (tran phut la 4 luot/60
# giay, cho 65 giay la chac chan qua tran).
CHO_KHI_429 = 65.0
# Chi dung khi KHONG hoi duoc han muc that tu VirusTotal: bao nhieu lan 429 lien
# tiep - moi lan deu da cho du CHO_KHI_429 giay - thi moi doan la het han ngay.
SO_LAN_429_LA_HET_NGAY = 3
# Gioi han cua tung API Free: toi da 4 request trong 60 giay.
# Script giu nhip ~15 giay GIUA HAI LAN DUNG CUNG MOT KEY.
# Cua so truot ben duoi van duoc giu lai lam lop bao ve thu hai.
LUOT_PHUT = 4
NHIP_MOI_KEY_MAC_DINH = 15.0
LE_AN_TOAN = 2.0

# --- Phanh chung cho ca may, chong bi chan theo dia chi IP ---
# Ngay 3/9/2026 ca sau key cung bi 429 ngay tu luot goi dau tien cua tung key, ke
# ca endpoint hoi han muc von khong ton luot tra file nao. Tran 4 luot/phut cua
# tung key khong giai thich duoc chuyen do: moi key moi goi dung mot lan. Nen
# ngoai nhip rieng cua tung key, script giu them mot phanh cho ca may.
# KHONG dat gioi han giua HAI KEY KHAC NHAU.
# 0 = khong phanh chung. Moi key tu tuan thu gioi han 4 luot/phut rieng.
NHIP_CHUNG_MAC_DINH = 0.0
NHIP_CHUNG_TOI_DA = 30.0
HE_SO_CHAM = 1.6            # gap 429 la la thi gian nhip ra bay nhieu lan
HE_SO_NHANH = 0.9           # chay tron tru mot luc thi thu nhanh lai
SO_LUOT_TRON_TRU = 25       # bao nhieu luot lien tiep khong loi thi thu nhanh lai
# Bay nhieu KEY KHAC NHAU cung bi 429 trong CUA_SO_CHAN_IP giay thi coi la dau
# hieu bi chan theo IP, khong phai het han muc cua tung key.
SO_KEY_429_LA_CHAN_IP = 3
CUA_SO_CHAN_IP = 180.0
NGHI_KHI_CHAN_IP = 600.0    # nghi 10 phut cho ben kia nguoi roi chay tiep
SO_LAN_NGHI_TOI_DA = 6
# Ma bam cua file thu EICAR, VirusTotal chac chan co san. Dung cho --kiem-tra-key.
SHA_THU = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# Gia tri ghi vao Excel de tieng Viet co dau cho de doc khi bao cao.
KL_DOC, KL_NGHI, KL_LANH, KL_CHUA = "Mã độc", "Nghi ngờ", "Lành tính", "Chưa rõ"
TT_CO, TT_KHONG, TT_LOI = "Đã có kết quả", "Chưa có trên VirusTotal", "Lỗi tra cứu"
DA_XU_LY = (TT_CO, TT_KHONG)

# Tu khoa trong ten ho ma doc do cac engine dat, dung de goi y nhan so bo.
# Day chi la doi chieu tu khoa may moc, khong thay the buoc chuan hoa nhan.
TU_KHOA_NHAN = [
    ("Banking malware", ["bank", "cerberus", "anubis", "hydra", "teabot", "sharkbot",
                         "flubot", "medusa", "octo", "ermac", "gustuff", "svpeng",
                         "marcher", "zitmo", "asacub", "wroba", "coper", "vultur",
                         "alien", "brata", "sova", "xenomorph"]),
    ("SMS malware", ["sms", "opfake", "fakeinst", "smforw", "podec", "boxer",
                     "wapsx", "joker", "jocker", "harly"]),
    ("Adware", ["adware", "airpush", "dowgin", "kuguo", "revmob", "youmi", "adwo",
                "hiddenad", "hiddad", "ewind", "leadbolt", "inmobi", "startapp",
                "appad", "adpush", "mobidash", "shedun", "batmobi"]),
    ("Riskware", ["riskware", "riskool", "skymobi", "wapron", "secapk", "jiagu",
                  "packer", "tool", "monitor", "track", "revenue", "smsreg",
                  "smspay", "agentsmith"]),
]


# ---------------------------------------------------------------- doc tham so

def doc_tham_so():
    p = argparse.ArgumentParser(
        description="Tra VirusTotal theo SHA-256 cho toan bo APK trong mot thu muc.")
    p.add_argument("--thu-muc", default=r"D:\APK_GitHub\apk",
                   help="thu muc chua file APK can kiem tra")
    p.add_argument("--ket-qua", default="",
                   help="thu muc ghi Excel va JSON; mac dinh la thu muc chua script nay")
    p.add_argument("--key", default="",
                   help="API key VirusTotal, nhieu key ngan cach bang dau phay; de trong "
                        "thi doc file api_key.txt (moi key mot dong) hoac bien moi truong "
                        "VT_API_KEY")
    p.add_argument("--nguong", type=int, default=1,
                   help="so engine bao doc toi thieu de ket luan la ma doc (mac dinh 1, "
                        "quy uoc mac dinh cua bo du lieu). De 1 thi khong con nhom nghi ngo: "
                        "co engine bao doc la ma doc, khong co la lanh tinh")
    p.add_argument("--nhip", type=float, default=NHIP_MOI_KEY_MAC_DINH,
                   help="so giay toi thieu giua hai lan dung CUNG MOT key "
                        "(mac dinh %.0f giay, phu hop 4 luot/phut/key)" % NHIP_MOI_KEY_MAC_DINH)
    p.add_argument("--gioi-han-ngay", type=int, default=500,
                   help="tran so luot API cho MOI KEY trong mot ngay (mac dinh 500, dung "
                        "bang han muc cua tai khoan free)")
    p.add_argument("--gioi-han", type=int, default=0,
                   help="chi xu ly toi da bay nhieu mau trong lan chay nay; 0 = khong gioi han")
    p.add_argument("--quet-lai", action="store_true",
                   help="tra lai ca nhung mau da co ket qua trong Excel")
    p.add_argument("--quet-lai-thieu", action="store_true",
                   help="chi tra lai nhung dong da ghi trong Excel ma chua co "
                        "ket qua that, tuc trang thai khac \"%s\" (Chua co tren "
                        "VirusTotal, Loi tra cuu). Khac --quet-lai o cho khong "
                        "dung lai quota cho ca nghin mau da xong" % TT_CO)
    p.add_argument("--tat-ca-file", action="store_true",
                   help="xet moi file trong thu muc, khong chi file duoi .apk "
                        "(dung cho mau CIC dat ten theo hash, khong co duoi)")
    p.add_argument("--bat-buoc-bam", action="store_true",
                   help="luon tinh lai SHA-256 tu noi dung file, ke ca khi ten file da la hash")
    p.add_argument("--tinh-lai", action="store_true",
                   help="dung lai Excel tu cac file trong phan_hoi_json theo nguong hien "
                        "hanh, khong goi API, khong ton quota")
    p.add_argument("--nhip-chung", type=float, default=NHIP_CHUNG_MAC_DINH,
                   help="gioi han giua hai luot goi BAT KY, gop chung moi key; "
                        "mac dinh 0 = KHONG gioi han chung. Gioi han 4 luot/phut van "
                        "duoc ap dung rieng cho tung key")
    p.add_argument("--khong-cho", action="store_true",
                   help="gap dau hieu bi chan theo IP thi dung han thay vi nghi %d phut roi "
                        "thu lai. Dung khi chay tay de xem ket qua ngay"
                        % int(NGHI_KHI_CHAN_IP // 60))
    p.add_argument("--khong-hoi-han-muc", action="store_true",
                   help="khong hoi VirusTotal so luot that su da dung cua tung key, chi tin "
                        "bo dem trong %s. Chi dung khi endpoint han muc bi loi" % TEN_FILE_QUOTA)
    p.add_argument("--noi-tiep", action="store_true",
                   help="dung het key thu nhat roi moi sang key thu hai, thay vi quay vong "
                        "deu giua cac key. Cham hon N lan nhung khi co su co thi biet ngay "
                        "key nao hong")
    p.add_argument("--kiem-tra-key", action="store_true",
                   help="hoi VirusTotal han muc gio/ngay/thang that su cua tung key roi in "
                        "ra, khong ton luot tra file nao. Key nao khong hoi duoc han muc "
                        "thi goi thu mot luot de biet no con song hay khong")
    p.add_argument("--dat-lai-quota", action="store_true",
                   help="xoa bo dem quota cua hom nay trong %s roi chay lai tu dau. Dung khi "
                        "bo dem bi sai lam cho script tuong la het key" % TEN_FILE_QUOTA)
    p.add_argument("--json-day-du", action="store_true",
                   help="luu nguyen ban tra loi cua VirusTotal thay vi ban rut gon")
    return p.parse_args()


DAU_FILE_KEY = """\
# API key VirusTotal - MOI KEY MOT DONG.
#
# Dan them key vao cac dong trong o duoi. Script tu chia luot cho tat ca cac key
# va tu chuyen sang key ke tiep khi mot key het 500 luot trong ngay, nen cang
# nhieu key thi cang quet duoc nhieu mau moi ngay va cang nhanh.
#
# Lay key: dang nhap virustotal.com -> avatar goc phai -> API key.
# Moi tai khoan free cho 4 luot/phut, 500 luot/ngay, 15.500 luot/thang.
#
# Dong bat dau bang dau # la chu thich, script bo qua.
# KHONG chia se file nay, khong day len GitHub.
"""


def ma_khoa(k):
    """Ma rut gon cua mot key, dung lam khoa trong file dem quota.

    Khong luu nguyen key vao file dem de file do co lo mo ra cung khong lo gi.
    """
    return hashlib.sha256(k.encode("utf-8")).hexdigest()[:12]


def doc_khoa(tham_so, thu_muc_script):
    """Tra ve danh sach key, giu nguyen thu tu, da khu trung."""
    tho = []
    if tham_so.key.strip():
        tho += [x for x in re.split(r"[,;\s]+", tham_so.key) if x]
    if os.environ.get("VT_API_KEY", "").strip():
        tho += [x for x in re.split(r"[,;\s]+", os.environ["VT_API_KEY"]) if x]
    dd = os.path.join(thu_muc_script, TEN_FILE_KEY)
    if os.path.exists(dd):
        with open(dd, "r", encoding="utf-8") as f:
            for dong in f:
                dong = dong.strip()
                if dong and not dong.startswith("#"):
                    tho.append(dong)

    ra, da_co = [], set()
    for k in tho:
        if k not in da_co:
            da_co.add(k)
            ra.append(k)
    return ra


def chuan_hoa_file_key(thu_muc_script, khoa):
    """Ghi lai api_key.txt theo dung khuon mau: phan huong dan roi moi key mot dong.

    Chay mot lan la file tu co dang de dien tiep. Key khong bao gio roi khoi may
    nay - script chi doc file cu roi ghi lai chinh no.
    """
    dd = os.path.join(thu_muc_script, TEN_FILE_KEY)
    than = DAU_FILE_KEY + "\n"
    for i, k in enumerate(khoa, start=1):
        than += "# key %d\n%s\n\n" % (i, k)
    than += ("# key %d - dan key tiep theo vao dong duoi day\n\n" % (len(khoa) + 1))

    cu = ""
    if os.path.exists(dd):
        try:
            with open(dd, "r", encoding="utf-8") as f:
                cu = f.read()
        except Exception:
            cu = ""
    if cu.strip() == than.strip():
        return False
    if cu:
        ban_sao = os.path.join(thu_muc_script, "_ban_cu")
        os.makedirs(ban_sao, exist_ok=True)
        shutil.copy2(dd, os.path.join(
            ban_sao, "api_key_%s.txt" % datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")))
    with open(dd, "w", encoding="utf-8") as f:
        f.write(than)
    return True


# ------------------------------------------------------------------ file APK

def la_apk(dd):
    """Nhan dien APK theo noi dung: ZIP hop le, ben trong co AndroidManifest.xml."""
    import zipfile
    try:
        with zipfile.ZipFile(dd) as z:
            ten = z.namelist()
            return "AndroidManifest.xml" in ten and any(t.startswith("classes") and
                                                        t.endswith(".dex") for t in ten)
    except Exception:
        return False


def bam_sha256(dd):
    h = hashlib.sha256()
    with open(dd, "rb") as f:
        for khoi in iter(lambda: f.read(1024 * 1024), b""):
            h.update(khoi)
    return h.hexdigest()


def liet_ke_mau(thu_muc, tat_ca_file, bat_buoc_bam):
    """Tra ve danh sach dict {sha256, ten, duong_dan, kich_thuoc}, da khu trung hash."""
    if not os.path.isdir(thu_muc):
        raise SystemExit("Khong thay thu muc: %s" % thu_muc)

    ung_vien = []
    for ten in sorted(os.listdir(thu_muc)):
        dd = os.path.join(thu_muc, ten)
        if not os.path.isfile(dd):
            continue
        if ten.lower().endswith(".apk") or tat_ca_file:
            ung_vien.append((ten, dd))

    ra, da_co = [], set()
    for ten, dd in ung_vien:
        goc = os.path.splitext(ten)[0]
        if HEX64.match(goc) and not bat_buoc_bam:
            sha = goc.lower()
        else:
            if not la_apk(dd):
                continue
            sha = bam_sha256(dd)
        if sha in da_co:
            continue
        da_co.add(sha)
        ra.append({"sha256": sha, "ten": ten, "duong_dan": dd,
                   "kich_thuoc": os.path.getsize(dd)})
    return ra


# ---------------------------------------------------------------- quota ngay

def ngay_quota():
    """VirusTotal dat lai han muc ngay theo gio UTC, tuc 7 gio sang gio Viet Nam.

    Truoc day ham nay dung ngay theo gio may, nen bo dem cua script ve 0 luc nua
    dem gio Viet Nam trong khi ben VirusTotal chua reset - chay tiep se an 429.
    """
    return datetime.datetime.now(datetime.timezone.utc).date().isoformat()


def doc_quota(thu_muc):
    """Tra ve (dict ma_khoa -> so luot da dung, set ma_khoa VirusTotal bao het ngay).

    Hai thu nay tach roi nhau co chu y: "so luot da dung" la so lan script nay
    goi API thanh cong, con "het ngay" la ket luan rut ra tu chinh cau tra loi
    cua VirusTotal. Ban cu gop chung lam mot nen chi can mot lan 429 la so dem bi
    day thang len 500 va key coi nhu chet oan ca ngay.
    """
    dd = os.path.join(thu_muc, TEN_FILE_QUOTA)
    if not os.path.exists(dd):
        return {}, set()
    try:
        with open(dd, "r", encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        return {}, set()
    if d.get("ngay") != ngay_quota():
        return {}, set()
    dung = {k: int(v) for k, v in (d.get("theo_key") or {}).items()}
    return dung, set(d.get("het_ngay") or [])


def ghi_quota(thu_muc, theo_key, het_ngay=()):
    with open(os.path.join(thu_muc, TEN_FILE_QUOTA), "w", encoding="utf-8") as f:
        json.dump({"ngay": ngay_quota(), "theo_key": theo_key,
                   "het_ngay": sorted(het_ngay),
                   "so_luot": sum(theo_key.values())},
                  f, ensure_ascii=False, indent=2)


# ------------------------------------------------------------- quay vong key

class BoKhoa:
    """Giu trang thai cua tung key: da dung bao nhieu luot, khi nao duoc goi tiep.

    Han muc la cua RIENG tung key, nen mot key bi tu choi khong noi len dieu gi
    ve cac key con lai. Va bo dem trong %s chi dem nhung lan chinh script nay
    goi - no khong biet gi ve nhung lan goi tu may khac, tu lan chay truoc, hay
    tu trinh duyet. Vi vay lop nay hoi thang VirusTotal (dong_bo) de lay con so
    that, chu khong tu suy dien tu ma loi 429.
    """ % TEN_FILE_QUOTA

    def __init__(self, khoa, tran_ngay, da_dung, da_het=(), noi_tiep=False,
                 nhip=NHIP_MOI_KEY_MAC_DINH, luot_phut=LUOT_PHUT):
        self.tran = tran_ngay
        self.noi_tiep = noi_tiep
        self.nhip = nhip
        self.luot_phut = luot_phut
        self.ds = []
        for i, k in enumerate(khoa, start=1):
            ma = ma_khoa(k)
            self.ds.append({"key": k, "ma": ma, "nhan": "key %d" % i,
                            "dung": int(da_dung.get(ma, 0)),
                            "tran_rieng": tran_ngay,
                            "het_ngay": ma in set(da_het),
                            "vt": None, "mocs": [], "loi_han_muc": "",
                            "san_sang": 0.0, "hong": "", "lien_tiep": 0})

    # ------------------------------------------------------------ han muc that

    def dong_bo(self, x):
        """Hoi VirusTotal so luot that su da dung cua mot key. True neu hoi duoc."""
        hm, ly_do = doc_han_muc(x["key"])
        x["loi_han_muc"] = ly_do
        if not hm:
            return False
        x["vt"] = hm
        if "ngay" in hm:
            dung, tran = hm["ngay"]
            x["dung"] = dung
            x["tran_rieng"] = tran
            x["het_ngay"] = dung >= tran
        if "thang" in hm and hm["thang"][0] >= hm["thang"][1]:
            x["hong"] = "het han muc thang (%d/%d)" % hm["thang"]
        if "gio" in hm and hm["gio"][0] >= hm["gio"][1]:
            # Het han muc gio thi chi phai cho den dau gio sau, khong chet ca ngay.
            x["san_sang"] = max(x["san_sang"], time.time() + giay_den_dau_gio())
        return True

    def het_gio(self, x):
        hm = x.get("vt") or {}
        return "gio" in hm and hm["gio"][0] >= hm["gio"][1]

    # ------------------------------------------------------------- chon va nhip

    def dung_duoc(self, x):
        return (not x["hong"]) and (not x["het_ngay"]) and x["dung"] < x["tran_rieng"]

    def con_lai(self):
        return sum(max(0, x["tran_rieng"] - x["dung"]) for x in self.ds if self.dung_duoc(x))

    def cho_bao_lau(self, x):
        """So giay con phai cho truoc khi duoc phep goi bang key nay."""
        t = time.time()
        cho = max(0.0, x["san_sang"] - t)
        if self.luot_phut > 0:
            x["mocs"] = [m for m in x["mocs"] if t - m < 60.0]
            if len(x["mocs"]) >= self.luot_phut:
                cho = max(cho, 60.0 + LE_AN_TOAN - (t - x["mocs"][0]))
        return cho

    def chon(self):
        """Key duoc phep goi som nhat; None neu khong con key nao dung duoc.

        Trong so nhung key da san sang thi lay key it dung nhat, de han muc ngay
        rai deu chu khong don het vao mot key. Khi nhip chung bi ha xuong vi nghi
        bi chan IP, neu cu lay key ranh som nhat thi chi mot hai key gong het.
        """
        ung = [x for x in self.ds if self.dung_duoc(x)]
        if not ung:
            return None
        if self.noi_tiep:
            return ung[0]
        san = [x for x in ung if self.cho_bao_lau(x) <= 0]
        if san:
            return min(san, key=lambda x: x["dung"])
        return min(ung, key=self.cho_bao_lau)

    def danh_dau(self, x):
        """Ghi nhan vua goi mot luot bang key nay."""
        t = time.time()
        x["mocs"].append(t)
        x["san_sang"] = t + self.nhip

    def hoan(self, x, giay):
        """Tam khoa mot key trong bay nhieu giay, khong dung den no nua."""
        x["san_sang"] = time.time() + giay

    # ------------------------------------------------------------------- luu tru

    def het_ngay_ma(self):
        return [x["ma"] for x in self.ds if x["het_ngay"]]

    def theo_key(self):
        return {x["ma"]: x["dung"] for x in self.ds}

    def luu(self, thu_muc):
        ghi_quota(thu_muc, self.theo_key(), self.het_ngay_ma())

    def in_trang_thai(self, dau_dong="  "):
        for x in self.ds:
            if x["hong"]:
                trang = x["hong"]
            elif x["het_ngay"]:
                trang = "het han muc ngay"
            elif self.het_gio(x):
                trang = "het han muc gio, cho sang gio sau"
            elif x["dung"] >= x["tran_rieng"]:
                trang = "da dung du %d luot" % x["tran_rieng"]
            else:
                trang = "con %d luot" % (x["tran_rieng"] - x["dung"])
            hm = x.get("vt") or {}
            them = ""
            if "gio" in hm:
                them += "  gio %d/%d" % hm["gio"]
            if "thang" in hm:
                them += "  thang %d/%d" % hm["thang"]
            print("%s%-7s %s...%s  ngay %3d/%d  (%s)%s"
                  % (dau_dong, x["nhan"], x["key"][:6], x["key"][-4:],
                     x["dung"], x["tran_rieng"], trang, them))
        if not any(x.get("vt") for x in self.ds):
            print("%s(so lieu tren lay tu bo dem cua may nay, chua hoi duoc VirusTotal)"
                  % dau_dong)


def _in_han_muc(bo, x, dau):
    hm = x["vt"]
    phan = []
    for nhan, ten in (("gio", "gio"), ("ngay", "ngay"), ("thang", "thang")):
        if nhan in hm:
            phan.append("%s %d/%d" % ((ten,) + hm[nhan]))
    con = max(0, x["tran_rieng"] - x["dung"])
    ket = x["hong"] or ("HET HAN NGAY" if x["het_ngay"] else
                        ("het han gio, cho sang gio sau" if bo.het_gio(x)
                         else "CON %d LUOT" % con))
    print(dau + "%s  ->  %s" % ("  ".join(phan), ket))


class NhipMay:
    """Phanh chung cho ca may, tu gian ra khi nghi bi chan theo dia chi IP.

    Han muc 4 luot/phut la cua RIENG tung key, nen ve ly thuyet sau key chay xen
    ke duoc 24 luot/phut. Thuc te VirusTotal con siet theo dia chi IP: dau hieu
    la nhieu key khac nhau cung bi 429 trong mot khoang ngan du key nao cung con
    du han muc. Lop nay giu mot khoang cach toi thieu giua hai luot goi bat ky,
    noi rong no khi vap, va thu nhanh lai khi da chay tron tru mot luc.
    """

    def __init__(self, nhip_san, toi_da=NHIP_CHUNG_TOI_DA):
        self.san = max(0.0, nhip_san)   # nhip nhanh nhat cho phep
        self.nhip = self.san
        self.toi_da = max(toi_da, self.san)
        self.moc = 0.0
        self.tron_tru = 0
        self.vap_gan_day = []           # (thoi diem, ma key) cua cac lan 429 la la
        self.so_lan_nghi = 0

    def cho(self):
        """Cho den luc ca may duoc phep goi luot tiep theo."""
        if self.nhip > 0:
            c = self.moc + self.nhip - time.time()
            if c > 0:
                time.sleep(c)
        self.moc = time.time()

    def tron(self):
        """Ghi nhan mot luot tron tru. Tra ve nhip moi neu vua thu nhanh lai."""
        self.tron_tru += 1
        if self.tron_tru >= SO_LUOT_TRON_TRU and self.nhip > self.san:
            self.tron_tru = 0
            self.nhip = max(self.san, self.nhip * HE_SO_NHANH)
            return self.nhip
        return None

    def vap(self, ma_key):
        """Ghi nhan mot lan 429 ma han muc cua key do khong giai thich duoc.

        Tra ve (nhip_moi, co_dau_hieu_chan_ip). nhip_moi la None neu khong doi.
        """
        t = time.time()
        self.tron_tru = 0
        self.vap_gan_day = [(x, m) for x, m in self.vap_gan_day if t - x < CUA_SO_CHAN_IP]
        self.vap_gan_day.append((t, ma_key))
        cu = self.nhip
        self.nhip = min(self.toi_da, max(1.0, self.nhip) * HE_SO_CHAM)
        chan_ip = len({m for _, m in self.vap_gan_day}) >= SO_KEY_429_LA_CHAN_IP
        return (self.nhip if self.nhip != cu else None), chan_ip

    def nghi(self):
        """Nghi mot lat cho ben kia nguoi. False neu da nghi qua nhieu lan."""
        if self.so_lan_nghi >= SO_LAN_NGHI_TOI_DA:
            return False
        self.so_lan_nghi += 1
        time.sleep(NGHI_KHI_CHAN_IP)
        self.vap_gan_day = []
        self.moc = time.time()
        return True


def kiem_tra_key(khoa, tran, thu_muc_kq, nhip_thu=20.0):
    """Tim xem tung key con dung duoc hay khong, va neu khong thi vi sao.

    Chay hai luot. Luot mot hoi han muc that (khong ton luot tra file nao). Key
    nao khong hoi duoc thi sang luot hai: nghi cho may im lang mot phut roi goi
    thu tung key MOT CACH THUNG THA, moi key cach nhau %d giay. Gian cach nay la
    co chu dich - neu goi don le, cach xa nhau ma van bi 429 thi khong con do
    duoc cho tran 4 luot/phut nua.
    """ % int(nhip_thu)
    da_dung, da_het = doc_quota(thu_muc_kq)
    bo = BoKhoa(khoa, tran, da_dung, da_het)

    print("Luot 1 - hoi han muc that tai VirusTotal (khong ton luot tra file):")
    con_lai = []
    for x in bo.ds:
        dau = "  %-7s %s...%s  " % (x["nhan"], x["key"][:6], x["key"][-4:])
        if bo.dong_bo(x):
            _in_han_muc(bo, x, dau)
        else:
            print(dau + "khong hoi duoc: %s" % x["loi_han_muc"])
            con_lai.append(x)
        time.sleep(1.0)

    if not con_lai:
        bo.luu(thu_muc_kq)
        print("\nTong con %d luot dung duoc hom nay tren %d key."
              % (bo.con_lai(), len(bo.ds)))
        return 0

    print("\nLuot 2 - goi thu tung key, moi key cach nhau %d giay." % int(nhip_thu))
    print("Nghi %d giay cho may im lang truoc da..." % int(CHO_KHI_429))
    time.sleep(CHO_KHI_429)
    song, chet_429, chet_401 = [], [], []
    for j, x in enumerate(con_lai):
        if j:
            time.sleep(nhip_thu)
        dau = "  %-7s %s...%s  " % (x["nhan"], x["key"][:6], x["key"][-4:])
        data, loi = goi_api(SHA_THU, x["key"], so_lan=1)
        if not loi or loi == "404":
            x["dung"] += 1
            song.append(x)
            print(dau + "CON DUNG DUOC")
        elif loi.startswith("401"):
            x["hong"] = "bi tu choi (401)"
            chet_401.append(x)
            print(dau + "KEY SAI HOAC BI KHOA (401) %s" % loi[4:].strip())
        elif loi.startswith("429"):
            chet_429.append(x)
            print(dau + "bi tu choi 429: %s" % (loi[4:].strip() or "khong kem thong bao"))
        else:
            print(dau + "loi khac: %s" % loi)
    bo.luu(thu_muc_kq)

    print("\n--- Ket luan ---")
    if song:
        print("  %d key van goi duoc khi goi thung tha." % len(song))
    if chet_401:
        print("  %d key sai hoac bi thu hoi, sua lai trong %s." % (len(chet_401), TEN_FILE_KEY))
    if chet_429:
        print("  %d key bi 429 ngay ca khi goi don le, cach nhau %d giay."
              % (len(chet_429), int(nhip_thu)))
        if len(chet_429) == len(con_lai) and len(con_lai) > 1:
            print("  Ca %d key cung bi mot luc, va endpoint han muc cung khong hoi duoc."
                  % len(chet_429))
            print("  Truong hop nay tran 4 luot/phut khong giai thich duoc, vi moi key chi")
            print("  goi dung mot lan. Hai kha nang con lai:")
            print("    1. VirusTotal chan theo dia chi IP cua may nay chu khong theo key.")
            print("       Thu lai sau vai gio, hoac doi mang (4G dien thoai) de kiem chung.")
            print("       Khi chay lai thi ha nhip ca may: --nhip-chung 4")
            print("    2. Ca %d tai khoan deu that su het 500 luot trong ngay." % len(chet_429))
            print("       Dang nhap virustotal.com bang tung tai khoan, vao muc API key,")
            print("       xem so luot da dung de biet chac.")
    return 0


# ------------------------------------------------------------------- goi API

def giay_den_dau_gio():
    """So giay tu bay gio den dau gio ke tiep, cong them mot chut cho chac."""
    t = datetime.datetime.now()
    return 60 * (59 - t.minute) + (60 - t.second) + 5


def _boc_han_muc(d, kieu):
    """Boc cap (da_dung, tran) tu hai dang tra loi khac nhau cua VirusTotal."""
    if kieu == "overall":
        goc = d
        lay = lambda q: (q or {}).get("user") or {}
    else:
        goc = ((d.get("attributes") or {}).get("quotas") or {})
        lay = lambda q: q or {}
    ra = {}
    for ten, nhan in (("api_requests_hourly", "gio"),
                      ("api_requests_daily", "ngay"),
                      ("api_requests_monthly", "thang")):
        q = lay(goc.get(ten))
        try:
            ra[nhan] = (int(q["used"]), int(q["allowed"]))
        except Exception:
            pass
    return ra


def doc_han_muc(key):
    """Hoi thang VirusTotal xem key nay da dung bao nhieu luot.

    Day la cach duy nhat biet chac mot key con bao nhieu luot. Bo dem trong
    %s chi dem nhung lan chinh script nay goi: no khong biet gi ve nhung lan goi
    tu lan chay truoc da bi ket luan nham, tu may khac, hay tu trinh duyet.

    Thu lan luot hai endpoint vi tuy tai khoan ma cai nay hay cai kia bi tu choi.
    Tra ve (dict, "") khi hoi duoc, hoac (None, ly_do) khi that bai - ly do la
    nguyen van ma loi HTTP kem thong bao cua VirusTotal, de con biet duong ma
    sua chu khong chi biet la "khong hoi duoc".

    dict co dang {'gio': (dung, tran), 'ngay': (...), 'thang': (...)}, thieu muc
    nao thi khong co khoa do.
    """ % TEN_FILE_QUOTA
    ly_do = "khong ro"
    for mau, kieu in ((API_HAN_MUC, "overall"), (API_NGUOI_DUNG, "ho_so")):
        yc = urllib.request.Request(mau % key, headers={
            "x-apikey": key, "Accept": "application/json",
            "User-Agent": "quet_virustotal/1.0"})
        try:
            with urllib.request.urlopen(yc, timeout=30) as p:
                d = json.loads(p.read().decode("utf-8")).get("data", {}) or {}
        except urllib.error.HTTPError as e:
            ly_do = "HTTP %d %s" % (e.code, doc_loi_http(e))
            continue
        except Exception as e:
            ly_do = "%s" % e
            continue
        ra = _boc_han_muc(d, kieu)
        if ra:
            return ra, ""
        ly_do = "tra loi khong co muc han muc"
    return None, ly_do


def doc_loi_http(e):
    """Lay cau thong bao ma VirusTotal gui kem theo ma loi HTTP.

    Chinh cau nay la thu phan biet duoc "goi qua 4 luot/phut" voi "het 500 luot
    trong ngay", vi ca hai deu tra ve ma 429 nhu nhau.
    """
    try:
        than = e.read().decode("utf-8", "replace")
    except Exception:
        return ""
    try:
        d = json.loads(than).get("error", {}) or {}
        return ("%s %s" % (d.get("code", ""), d.get("message", ""))).strip()
    except Exception:
        return " ".join(than.split())[:200]


TU_KHOA_QUA_NHANH = ("minute", "hourly", "hour", "rate limit", "too many requests",
                     "slow down")
TU_KHOA_HET_NGAY = ("daily", "day", "monthly", "month", "quota exceeded for the day")


def het_han_ngay(tb):
    """Doan xem thong bao 429 la het han muc ngay/thang hay chi la goi qua nhanh.

    Tra ve True neu chac la het ngay, False neu chac la qua nhanh, None neu
    khong doan duoc. Khong doan duoc thi ben goi coi nhu chi la qua nhanh - tha
    thu lai ton them mot lan cho, con hon la ket luan oan mot key con song la da
    chet ca ngay.
    """
    t = (tb or "").lower()
    if any(x in t for x in TU_KHOA_QUA_NHANH):
        return False
    if any(x in t for x in TU_KHOA_HET_NGAY):
        return True
    return None


def goi_api(sha, key, so_lan=3):
    """Tra ve (data, loi). data la dict attributes; loi la chuoi mo ta neu that bai.

    Ma tra ve dac biet: loi == "404" nghia la VirusTotal chua co mau nay;
    loi bat dau bang "429:" nghia la bi tu choi vi vuot han muc, phan sau dau hai
    cham la nguyen van thong bao cua VirusTotal; "401:" la key sai hoac bi khoa.
    """
    yc = urllib.request.Request(API + sha, headers={
        "x-apikey": key, "Accept": "application/json",
        "User-Agent": "quet_virustotal/1.0"})
    for lan in range(so_lan):
        try:
            with urllib.request.urlopen(yc, timeout=60) as p:
                return json.loads(p.read().decode("utf-8")).get("data", {}), ""
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None, "404"
            if e.code == 429:
                return None, "429:" + doc_loi_http(e)
            if e.code == 401:
                return None, "401:" + doc_loi_http(e)
            if e.code in (500, 502, 503, 504) and lan < so_lan - 1:
                time.sleep(10 * (lan + 1))
                continue
            return None, "HTTP %d" % e.code
        except Exception as e:
            if lan < so_lan - 1:
                time.sleep(10 * (lan + 1))
                continue
            return None, "Loi ket noi: %s" % e
    return None, "Khong goi duoc API"


def rut_gon(data):
    a = data.get("attributes", {}) or {}
    giu = ["sha256", "md5", "size", "type_description", "meaningful_name",
           "first_submission_date", "last_analysis_date", "times_submitted",
           "last_analysis_stats", "last_analysis_results",
           "popular_threat_classification", "tags", "reputation"]
    b = {k: a[k] for k in giu if k in a}
    ag = a.get("androguard") or {}
    if isinstance(ag, dict):
        b["androguard"] = {k: ag.get(k) for k in
                           ("Package", "VersionName", "VersionCode", "MinSdkVersion",
                            "TargetSdkVersion", "main_activity", "AndroidVersionName")
                           if k in ag}
    return {"id": data.get("id", ""), "attributes": b}


# ------------------------------------------------------------- doc ket qua VT

def ngay_tu_epoch(v):
    try:
        return datetime.datetime.fromtimestamp(int(v)).strftime("%d/%m/%Y")
    except Exception:
        return ""


def goi_y_nhan(ho, nhom, doc_hai):
    """Doi chieu tu khoa de goi y nhan so bo. Chi la goi y, khong phai nhan cuoi."""
    chuoi = (" ".join([str(ho), str(nhom)])).lower()
    for nhan, tu_khoa in TU_KHOA_NHAN:
        for t in tu_khoa:
            if t in chuoi:
                return nhan
    if doc_hai == 0:
        return "Benign"
    return "Chưa xác định"


def phan_tich(mau, data, nguong):
    a = data.get("attributes", {}) or {}
    tk = a.get("last_analysis_stats", {}) or {}
    doc_hai = int(tk.get("malicious", 0))
    nghi = int(tk.get("suspicious", 0))
    tong = sum(int(tk.get(k, 0)) for k in
               ("malicious", "suspicious", "undetected", "harmless", "timeout"))

    pt = a.get("popular_threat_classification", {}) or {}
    ho = pt.get("suggested_threat_label", "") or ""
    nhom = ", ".join("%s (%d)" % (x.get("value", ""), x.get("count", 0))
                     for x in (pt.get("popular_threat_category") or [])[:3])
    ten_ho = ", ".join("%s (%d)" % (x.get("value", ""), x.get("count", 0))
                       for x in (pt.get("popular_threat_name") or [])[:3])
    if ten_ho:
        ho = (ho + " | " if ho else "") + ten_ho

    if doc_hai >= nguong:
        ket_luan = KL_DOC
    elif nguong > 1 and doc_hai + nghi > 0:
        # Chi ton tai khi chay voi nguong > 1. Voi nguong 1 (quy uoc bai bao) thi
        # khong co vung trung gian: co engine bao doc la ma doc, khong co la lanh tinh.
        ket_luan = KL_NGHI
    else:
        ket_luan = KL_LANH

    ag = a.get("androguard") or {}
    goi = ""
    if isinstance(ag, dict):
        goi = str(ag.get("Package") or "")
        if ag.get("VersionName"):
            goi = "%s (%s)" % (goi, ag.get("VersionName"))

    ghi_chu = []
    if nghi:
        ghi_chu.append("%d engine đánh dấu nghi ngờ" % nghi)
    if a.get("times_submitted"):
        ghi_chu.append("đã được gửi lên VirusTotal %s lần" % a.get("times_submitted"))
    if a.get("meaningful_name"):
        ghi_chu.append("tên gốc trên VirusTotal: %s" % a.get("meaningful_name"))

    return {
        "SHA-256": mau["sha256"], "Ten_file": mau["ten"],
        "Dung_luong_byte": mau["kich_thuoc"], "Trang_thai": TT_CO,
        "So_engine_phat_hien": doc_hai, "Tong_so_engine": tong,
        "Ty_le_phat_hien": (doc_hai / tong) if tong else "",
        "Ket_luan": ket_luan,
        "Nhan_goi_y": goi_y_nhan(ho, nhom, doc_hai),
        "Ho_ma_doc": ho, "Nhom_de_doa": nhom,
        "Lan_gui_dau_tien": ngay_tu_epoch(a.get("first_submission_date")),
        "Lan_quet_gan_nhat": ngay_tu_epoch(a.get("last_analysis_date")),
        "Goi_Android": goi, "Duong_dan": mau["duong_dan"],
        "Ghi_chu": "; ".join(ghi_chu),
    }


def dong_that_bai(mau, trang_thai, ghi_chu):
    return {"SHA-256": mau["sha256"], "Ten_file": mau["ten"],
            "Dung_luong_byte": mau["kich_thuoc"], "Trang_thai": trang_thai,
            "So_engine_phat_hien": "", "Tong_so_engine": "", "Ty_le_phat_hien": "",
            "Ket_luan": KL_CHUA, "Nhan_goi_y": "", "Ho_ma_doc": "",
            "Nhom_de_doa": "", "Lan_gui_dau_tien": "", "Lan_quet_gan_nhat": "",
            "Goi_Android": "", "Duong_dan": mau["duong_dan"], "Ghi_chu": ghi_chu}


# ----------------------------------------------------------------- ghi Excel

def duong_dan_excel(thu_muc):
    return os.path.join(thu_muc, TEN_FILE_EXCEL)


def doc_excel(thu_muc):
    dd = duong_dan_excel(thu_muc)
    if not os.path.exists(dd):
        return []
    wb = load_workbook(dd, read_only=True, data_only=True)
    if S_KQ not in wb.sheetnames:
        wb.close()
        return []
    ws = wb[S_KQ]
    tieu_de = [c.value for c in ws[1]]
    ra = []
    for hang in ws.iter_rows(min_row=2, values_only=True):
        if all(v is None for v in hang):
            continue
        d = {t: ("" if v is None else v) for t, v in zip(tieu_de, hang)}
        ra.append({k: d.get(k, "") for k in COT})
    wb.close()
    return ra


def _ke_bang(ws, du_lieu):
    ws.append(COT)
    for o in ws[1]:
        o.font = Font(name=FONT, size=11, bold=True, color="FFFFFF")
        o.fill = XANH
        o.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    ws.row_dimensions[1].height = 30

    for d in du_lieu:
        hang = []
        for k in COT:
            v = d.get(k, "")
            if k in COT_SO and str(v).lstrip("-").isdigit():
                v = int(v)
            hang.append(v)
        ws.append(hang)

    cot_ty_le = COT.index("Ty_le_phat_hien") + 1
    cot_ket_luan = COT.index("Ket_luan") + 1
    for hang in ws.iter_rows(min_row=2):
        for o in hang:
            o.font = Font(name=FONT, size=10)
            o.alignment = Alignment(vertical="top")
        hang[cot_ty_le - 1].number_format = "0.0%"
        hang[cot_ty_le - 1].alignment = Alignment(horizontal="center", vertical="top")
        if hang[cot_ket_luan - 1].value == KL_DOC:
            for o in hang:
                o.fill = DO_NHAT

    for i, ten in enumerate(COT, start=1):
        rong = max([len(str(ten))] + [len(str(d.get(ten, ""))) for d in du_lieu[:500]]) + 2
        ws.column_dimensions[get_column_letter(i)].width = min(max(rong, 9), 48)
    if du_lieu:
        ws.auto_filter.ref = "A1:%s%d" % (get_column_letter(len(COT)), len(du_lieu) + 1)
    ws.freeze_panes = "C2"


def _ke_tong_hop(ws, du_lieu, nguong, thu_muc_apk, so_file):
    ws["A1"] = "TỔNG HỢP KẾT QUẢ QUÉT VIRUSTOTAL"
    ws["A1"].font = Font(name=FONT, size=14, bold=True)
    ws.merge_cells("A1:D1")

    chu_thich = [
        "Số liệu lập ngày %s. Thư mục quét: %s (%d file được nhận là mẫu APK duy nhất theo SHA-256)."
        % (datetime.date.today().strftime("%d/%m/%Y"), thu_muc_apk, so_file),
        "Cách tra: gọi VirusTotal API v3 theo mã băm SHA-256 của từng file, không tải file lên. "
        "Mẫu nào VirusTotal chưa có sẵn trong cơ sở dữ liệu thì ghi trạng thái "
        "\u201c%s\u201d và cần xử lý riêng, chưa tính vào phần đã kết luận." % TT_KHONG,
        ("Ngưỡng kết luận đang dùng: chỉ cần 1 engine báo độc là xếp mã độc, không engine nào "
         "báo thì xếp lành tính. Đây là quy ước mặc định của bộ dữ liệu, nên không có nhóm trung gian nào cần xem lại bằng tay."
         if nguong <= 1 else
         "Ngưỡng kết luận đang dùng: từ %d engine trở lên báo độc thì xếp là mã độc; có 1 đến %d "
         "engine báo độc hoặc nghi ngờ thì xếp là nghi ngờ, cần xem lại bằng tay; không engine nào "
         "báo thì xếp là lành tính." % (nguong, nguong - 1)),
        "Cột Nhan_goi_y chỉ là đối chiếu từ khóa trong tên họ mã độc do các engine đặt. Đây không "
        "phải nhãn cuối cùng — bước chuẩn hóa về 5 nhãn "
        "được thực hiện bằng gan_nhan_gemini.py.",
        "Cột Nhan_Gemini nằm ngay bên phải là nhãn cuối sau bước chuẩn hóa bằng mô hình Gemini, do "
        "script gan_nhan_gemini.py ghi vào. Ô còn trống nghĩa là mẫu đó chưa qua bước gán nhãn. "
        "Đặt hai cột cạnh nhau để so trực tiếp cách dò từ khóa với cách dùng mô hình ngôn ngữ.",
        "Bản trả lời gốc của VirusTotal cho từng mẫu nằm trong thư mục phan_hoi_json, đặt tên theo "
        "SHA-256, dùng làm minh chứng khi báo cáo.",
    ]
    hang = 3
    for t in chu_thich:
        o = ws.cell(row=hang, column=1, value=t)
        o.font = Font(name=FONT, size=9, italic=True, color="404040")
        o.alignment = Alignment(wrap_text=True, vertical="top")
        ws.merge_cells(start_row=hang, start_column=1, end_row=hang, end_column=4)
        ws.row_dimensions[hang].height = 26 if len(t) < 150 else 42
        hang += 1

    for rong, i in ((10, 1), (52, 2), (16, 3), (14, 4)):
        ws.column_dimensions[get_column_letter(i)].width = rong

    def bang(tieu_de, cap, tong):
        nonlocal hang
        hang += 1
        o = ws.cell(row=hang, column=2, value=tieu_de)
        o.font = Font(name=FONT, size=12, bold=True)
        hang += 1
        for i, ten in enumerate(("STT", "Hạng mục", "Số mẫu", "Tỷ lệ"), start=1):
            c = ws.cell(row=hang, column=i, value=ten)
            c.font = Font(name=FONT, size=11, bold=True, color="FFFFFF")
            c.fill = XANH
            c.alignment = Alignment(horizontal="center", vertical="center")
        for stt, (ten, so) in enumerate(cap, start=1):
            hang += 1
            ws.cell(row=hang, column=1, value=stt)
            ws.cell(row=hang, column=2, value=ten)
            ws.cell(row=hang, column=3, value=so)
            c = ws.cell(row=hang, column=4, value=(so / tong) if tong else 0)
            c.number_format = "0.0%"
            for i in range(1, 5):
                x = ws.cell(row=hang, column=i)
                x.font = Font(name=FONT, size=10)
                x.alignment = Alignment(horizontal="left" if i == 2 else "center")
        hang += 1
        ws.cell(row=hang, column=2, value="TỔNG CỘNG")
        ws.cell(row=hang, column=3, value=tong)
        for i in range(1, 5):
            x = ws.cell(row=hang, column=i)
            x.font = Font(name=FONT, size=11, bold=True)
            x.fill = XAM
            x.alignment = Alignment(horizontal="left" if i == 2 else "center")
        hang += 1

    tong = len(du_lieu)
    ten_ket_luan = [KL_DOC, KL_LANH, KL_CHUA] if nguong <= 1 else [KL_DOC, KL_NGHI, KL_LANH, KL_CHUA]
    dem = {t: sum(1 for d in du_lieu if d.get("Ket_luan") == t) for t in ten_ket_luan}
    bang("Theo kết luận", [(t, dem[t]) for t in ten_ket_luan], tong)

    trang = {}
    for d in du_lieu:
        t = str(d.get("Trang_thai", "")) or "(trống)"
        trang[t] = trang.get(t, 0) + 1
    bang("Theo trạng thái tra cứu", sorted(trang.items(), key=lambda kv: -kv[1]), tong)

    nhan = {}
    for d in du_lieu:
        t = str(d.get("Nhan_goi_y", "")) or "(chưa có)"
        nhan[t] = nhan.get(t, 0) + 1
    bang("Theo nhãn gợi ý (chỉ để tham khảo)",
         sorted(nhan.items(), key=lambda kv: -kv[1]), tong)


def ghi_them(thu_muc, dong_moi, nhan_lan_chay, thu_muc_apk, so_file, nguong):
    """Ghi noi them ket qua vao Excel. Dong nao trung SHA-256 thi thay bang ban moi."""
    dd = duong_dan_excel(thu_muc)
    cu = doc_excel(thu_muc)

    if os.path.exists(dd):
        ban_sao = os.path.join(thu_muc, "_ban_cu")
        os.makedirs(ban_sao, exist_ok=True)
        shutil.copy2(dd, os.path.join(
            ban_sao, "Ket_qua_VirusTotal_%s.xlsx"
            % datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")))

    theo_hash = {}
    thu_tu = []
    for d in cu:
        h = str(d.get("SHA-256", "")).strip().lower()
        if not h:
            continue
        if h not in theo_hash:
            thu_tu.append(h)
        theo_hash[h] = d
    for d in dong_moi:
        h = str(d.get("SHA-256", "")).strip().lower()
        cu_d = theo_hash.get(h) or {}
        if h not in theo_hash:
            thu_tu.append(h)
        x = dict(d)
        x["Lan_chay"] = nhan_lan_chay
        # Nhung cot do script khac ghi vao thi giu lai, dung de lan quet sau xoa mat.
        for k in COT_GIU_LAI:
            if not x.get(k) and cu_d.get(k):
                x[k] = cu_d[k]
        theo_hash[h] = x

    du_lieu = [theo_hash[h] for h in thu_tu]

    wb = Workbook()
    _ke_bang(wb.active, du_lieu)
    wb.active.title = S_KQ
    _ke_tong_hop(wb.create_sheet(S_TH), du_lieu, nguong, thu_muc_apk, so_file)
    wb.save(dd)
    return len(du_lieu)


# ------------------------------------------------- tinh lai tu JSON da luu

def thu_muc_cua(duong_dan):
    """Cat lay phan thu muc cua mot duong dan.

    Tu tach lay dau \\ hoac /, khong dung os.path.dirname, de con doc dung duong
    dan Windows ke ca khi script duoc chay tren may Linux.
    """
    t = str(duong_dan or "").strip()
    for i in range(len(t) - 1, -1, -1):
        if t[i] in "\\/":
            return t[:i]
    return ""


def mo_ta_thu_muc(du_lieu):
    """Liet ke cac thu muc APK xuat hien trong cot Duong_dan, thu muc nhieu mau len truoc."""
    dem = {}
    for d in du_lieu:
        t = thu_muc_cua(d.get("Duong_dan", "")) or "(khong ro)"
        dem[t] = dem.get(t, 0) + 1
    if not dem:
        return "(khong ro)"
    return " va ".join(t for t, _ in sorted(dem.items(), key=lambda kv: -kv[1]))


def tinh_lai(thu_muc_kq, thu_muc_json, nguong):
    """Dung lai Excel tu cac ban JSON da luu, khong goi API.

    Dung khi doi quy uoc nguong: so engine bao doc da nam san trong JSON roi, chi
    co cach quy tu so do ra ket luan la thay doi. Dong nao khong tim thay JSON
    (mau VirusTotal chua co, hoac loi tra cuu) thi giu nguyen nhu cu.
    """
    cu = doc_excel(thu_muc_kq)
    if not cu:
        raise SystemExit("Chua co %s trong %s de tinh lai."
                         % (TEN_FILE_EXCEL, thu_muc_kq))
    print("Doc %d dong tu %s" % (len(cu), duong_dan_excel(thu_muc_kq)))
    print("Doc ban JSON goc trong %s" % thu_muc_json)

    truoc = {}
    for d in cu:
        t = str(d.get("Ket_luan", "")) or "(trong)"
        truoc[t] = truoc.get(t, 0) + 1

    du_lieu, tinh, giu, hong = [], 0, 0, 0
    for d in cu:
        sha = str(d.get("SHA-256", "")).strip().lower()
        dd = os.path.join(thu_muc_json, sha + ".json")
        if not (HEX64.match(sha) and os.path.exists(dd)):
            du_lieu.append(d)
            giu += 1
            continue
        try:
            with open(dd, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print("  bo qua %s: doc JSON loi (%s)" % (sha[:12], e))
            du_lieu.append(d)
            hong += 1
            continue
        m = {"sha256": sha, "ten": d.get("Ten_file", ""),
             "duong_dan": d.get("Duong_dan", ""),
             "kich_thuoc": d.get("Dung_luong_byte", "")}
        moi = phan_tich(m, data, nguong)
        # Giu lai nhung cot khong sinh ra tu JSON: moc lan chay cu va nhan do
        # gan_nhan_gemini.py ghi nguoc vao.
        moi["Lan_chay"] = d.get("Lan_chay", "")
        for k in COT_GIU_LAI:
            moi[k] = d.get(k, "")
        du_lieu.append(moi)
        tinh += 1

    dd = duong_dan_excel(thu_muc_kq)
    ban_sao = os.path.join(thu_muc_kq, "_ban_cu")
    os.makedirs(ban_sao, exist_ok=True)
    shutil.copy2(dd, os.path.join(
        ban_sao, "Ket_qua_VirusTotal_%s.xlsx"
        % datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")))

    wb = Workbook()
    _ke_bang(wb.active, du_lieu)
    wb.active.title = S_KQ
    _ke_tong_hop(wb.create_sheet(S_TH), du_lieu, nguong,
                 mo_ta_thu_muc(du_lieu), len(du_lieu))
    wb.save(dd)

    sau = {}
    for d in du_lieu:
        t = str(d.get("Ket_luan", "")) or "(trong)"
        sau[t] = sau.get(t, 0) + 1

    print("\n--- Tinh lai xong (nguong %d engine) ---" % nguong)
    print("  Tinh lai tu JSON:   %d dong" % tinh)
    print("  Giu nguyen (khong co JSON): %d dong" % giu)
    if hong:
        print("  JSON doc khong duoc: %d dong" % hong)
    print("  Cot Ket_luan truoc va sau:")
    for t in sorted(set(list(truoc) + list(sau))):
        print("    %-24s %6d  ->  %6d" % (t, truoc.get(t, 0), sau.get(t, 0)))
    print("\nFile ket qua: %s" % dd)
    print("Ban Excel cu da chep vao: %s" % ban_sao)
    return 0


# ---------------------------------------------------------------------- main

def doi_pho_chan_ip(nhip_may, tham_so):
    """Nhieu key cung bi 429 mot luc: nghi mot lat roi chay tiep. False neu bo cuoc.

    Khong khai tu key nao trong truong hop nay. Han muc la cua tung key, ma nhieu
    key cung gay mot luc thi nguyen nhan nam o phia may nay chu khong o phia key.
    """
    ten = sorted({m for _, m in nhip_may.vap_gan_day})
    print("\n!! %d key khac nhau cung bi 429 trong vong %d giay. Han muc rieng cua tung "
          "key khong giai thich duoc chuyen nay - nhieu kha nang VirusTotal dang chan "
          "theo dia chi IP cua may." % (len(ten), int(CUA_SO_CHAN_IP)))
    if tham_so.khong_cho:
        print("   Dang de --khong-cho nen dung lai o day. Bo tham so do di de script tu "
              "nghi roi chay tiep.")
        return False
    if not nhip_may.nghi():
        print("   Da nghi %d lan ma van vay, dung lai. Thu lai sau vai gio, hoac chay tu "
              "mang khac (4G dien thoai) de kiem chung." % SO_LAN_NGHI_TOI_DA)
        return False
    print("   Da nghi %d phut, nhip chung gio la %.0f giay mot luot. Chay tiep.\n"
          % (int(NGHI_KHI_CHAN_IP // 60), nhip_may.nhip))
    return True


def main():
    tham_so = doc_tham_so()
    thu_muc_script = os.path.dirname(os.path.abspath(__file__))
    thu_muc_kq = tham_so.ket_qua or thu_muc_script
    os.makedirs(thu_muc_kq, exist_ok=True)
    thu_muc_json = os.path.join(thu_muc_kq, "phan_hoi_json")
    os.makedirs(thu_muc_json, exist_ok=True)

    # Tinh lai tu JSON da luu: khong can API key, khong dung mot luot quota nao.
    if tham_so.tinh_lai:
        return tinh_lai(thu_muc_kq, thu_muc_json, tham_so.nguong)

    khoa = doc_khoa(tham_so, thu_muc_script)
    if not khoa:
        chuan_hoa_file_key(thu_muc_script, [])
        raise SystemExit(
            "Chua co API key. Mo file %s trong thu muc nay va dan key VirusTotal vao, "
            "moi key mot dong, hoac chay lai kem --key <key>."
            % os.path.join(thu_muc_script, TEN_FILE_KEY))
    if chuan_hoa_file_key(thu_muc_script, khoa):
        print("Da chuan hoa lai %s: moi key mot dong, co san cho de dan key tiep theo."
              % TEN_FILE_KEY)

    if tham_so.kiem_tra_key:
        return kiem_tra_key(khoa, tham_so.gioi_han_ngay, thu_muc_kq)

    print("Dang liet ke file trong %s ..." % tham_so.thu_muc)
    mau = liet_ke_mau(tham_so.thu_muc, tham_so.tat_ca_file, tham_so.bat_buoc_bam)
    print("  tim thay %d mau APK duy nhat theo SHA-256" % len(mau))

    da_co = {}
    for d in doc_excel(thu_muc_kq):
        h = str(d.get("SHA-256", "")).strip().lower()
        if h:
            da_co[h] = d
    xong = {h for h, d in da_co.items()
            if str(d.get("Trang_thai", "")).strip() in DA_XU_LY}

    if tham_so.quet_lai:
        can_tra = list(mau)
    elif tham_so.quet_lai_thieu:
        # Trang thai "Chua co tren VirusTotal" nam trong DA_XU_LY nen lan chay
        # thuong bo qua vinh vien. Che do nay lay lai dung nhung dong do.
        chua_that = {h for h, d in da_co.items()
                     if str(d.get("Trang_thai", "")).strip() != TT_CO}
        can_tra = [m for m in mau
                   if m["sha256"] not in xong or m["sha256"] in chua_that]
        so_lay_lai = sum(1 for m in mau
                         if m["sha256"] in xong and m["sha256"] in chua_that)
        print("  che do --quet-lai-thieu: lay lai %d dong da ghi nhung chua co "
              "ket qua that" % so_lay_lai)
    else:
        can_tra = [m for m in mau if m["sha256"] not in xong]
    print("  da co ket qua tu truoc: %d mau; con phai tra: %d mau"
          % (len(mau) - len(can_tra), len(can_tra)))

    if tham_so.dat_lai_quota:
        da_dung, da_het = {}, set()
        print("  da xoa bo dem quota cua hom nay theo yeu cau (--dat-lai-quota)")
    else:
        da_dung, da_het = doc_quota(thu_muc_kq)
    bo_khoa = BoKhoa(khoa, tham_so.gioi_han_ngay, da_dung, da_het,
                     noi_tiep=tham_so.noi_tiep, nhip=tham_so.nhip)
    if not tham_so.khong_hoi_han_muc:
        # Hoi han muc khong ton luot tra file nao. Neu ca N key deu bi 429 ngay o
        # buoc nay thi khong the la het han muc cua tung key - do la dau hieu bi
        # chan theo IP, va cach chua duy nhat la nghi mot lat roi thu lai.
        for lan in range(1, 4):
            print("  dang hoi VirusTotal so luot that su da dung cua tung key...")
            hoi_duoc = sum(1 for x in bo_khoa.ds if bo_khoa.dong_bo(x))
            bo_khoa.luu(thu_muc_kq)
            if hoi_duoc:
                break
            ly_do = bo_khoa.ds[0].get("loi_han_muc") or "khong ro"
            if "429" not in ly_do or tham_so.khong_cho or lan == 3:
                print("  khong hoi duoc key nao (%s), danh tin tam bo dem trong %s"
                      % (ly_do, TEN_FILE_QUOTA))
                break
            cho = 300.0 * lan
            print("  ca %d key deu bi 429 ngay o buoc hoi han muc, ma buoc nay khong ton "
                  "luot tra file nao." % len(bo_khoa.ds))
            print("  Day la dau hieu bi chan theo dia chi IP chu khong phai het han muc. "
                  "Nghi %d phut roi thu lai (lan %d/3)." % (int(cho // 60), lan))
            time.sleep(cho)
    print("  co %d key, han muc hom nay (moc dat lai: 7 gio sang gio Viet Nam):" % len(khoa))
    bo_khoa.in_trang_thai()
    con_lai_ngay = bo_khoa.con_lai()
    print("  tong con %d luot dung duoc trong hom nay" % con_lai_ngay)
    if con_lai_ngay == 0:
        if any(x.get("vt") for x in bo_khoa.ds):
            print("Chinh VirusTotal bao la khong con key nao con luot hom nay.")
        else:
            print("Theo bo dem cua may nay thi khong con key nao dung duoc hom nay. "
                  "Chay --kiem-tra-key de hoi thang VirusTotal, hoac --dat-lai-quota "
                  "de xoa bo dem.")
        print("Them key moi vao %s, hoac doi den 7 gio sang mai."
              % os.path.join(thu_muc_script, TEN_FILE_KEY))
        return 0

    han = con_lai_ngay
    if tham_so.gioi_han:
        han = min(han, tham_so.gioi_han)
    can_tra = can_tra[:han]
    if not can_tra:
        print("Khong con mau nao can tra. Ket qua nam trong %s"
              % duong_dan_excel(thu_muc_kq))
        return 0

    nhan_lan_chay = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    so_key_song = sum(1 for x in bo_khoa.ds if bo_khoa.dung_duoc(x))
    nhip_may = NhipMay(tham_so.nhip_chung)
    nhip_ky_vong = (tham_so.nhip if tham_so.noi_tiep
                    else tham_so.nhip / max(1, so_key_song))
    print("\nBat dau tra %d mau bang %d key con dung duoc, che do %s. "
          "Moi key cach lan goi truoc %.0f giay; giua cac key KHAC NHAU khong cho. "
          "Nhip trung binh ly thuyet ~%.1f giay/mau, uoc tinh %s.\n"
          % (len(can_tra), so_key_song,
             "noi tiep tung key" if tham_so.noi_tiep else "quay vong",
             tham_so.nhip, nhip_ky_vong,
             str(datetime.timedelta(seconds=int(len(can_tra) * nhip_ky_vong)))))


    dong_moi, dem = [], {"ma_doc": 0, "nghi_ngo": 0, "lanh_tinh": 0,
                         "chua_co": 0, "loi": 0}
    het_quota = False

    try:
        vi_tri = 0
        while vi_tri < len(can_tra):
            m = can_tra[vi_tri]
            i = vi_tri + 1

            k = bo_khoa.chon()
            if k is None:
                print("\nKhong con key nao dung duoc. Dung lai o mau thu %d." % i)
                het_quota = True
                break

            # Dong ho nay CHI ap dung cho key vua duoc chon.
            # Key khac vua goi xong khong lam key nay phai cho.
            # Moi key toi da 4 luot/60 giay; voi nhip 15 giay/key, vong quay
            # nhieu key se chay gan nhu lien tuc.
            cho = bo_khoa.cho_bao_lau(k)
            if cho > 0:
                time.sleep(cho)
            # KHONG cho them giua hai key khac nhau.
            # bo_khoa.danh_dau() chi dat dong ho cho CHINH key vua dung.
            bo_khoa.danh_dau(k)

            data, loi = goi_api(m["sha256"], k["key"])
            # Lan bi tu choi vi 429/401 khong tinh la mot luot da dung.
            if not (loi.startswith("429") or loi.startswith("401")):
                k["dung"] += 1
            bo_khoa.luu(thu_muc_kq)

            if loi.startswith("401"):
                k["hong"] = "bi tu choi (401)"
                print("%s bi VirusTotal tu choi (401) - bo qua key nay, chuyen key khac. "
                      "Kiem tra lai dong tuong ung trong %s." % (k["nhan"], TEN_FILE_KEY))
                continue
            if loi.startswith("429"):
                tb = loi[4:].strip()
                # Khong doan nua: hoi thang VirusTotal xem key nay con bao nhieu
                # luot. 429 co the la het han ngay, het han gio, hoac chi la goi
                # qua nhanh - ba chuyen khac han nhau ma cung mot ma loi.
                if bo_khoa.dong_bo(k):
                    bo_khoa.luu(thu_muc_kq)
                    hm = k["vt"]
                    if k["hong"]:
                        print("%s %s. Con %d luot o cac key khac."
                              % (k["nhan"], k["hong"], bo_khoa.con_lai()))
                    elif k["het_ngay"]:
                        print("%s het han muc ngay that (VirusTotal: %d/%d). "
                              "Con %d luot o cac key khac."
                              % ((k["nhan"],) + hm.get("ngay", (k["dung"], k["tran_rieng"]))
                                 + (bo_khoa.con_lai(),)))
                    elif bo_khoa.het_gio(k):
                        print("%s het han muc gio (%d/%d), hoan den dau gio sau, "
                              "chuyen sang key khac ngay." % ((k["nhan"],) + hm["gio"]))
                    else:
                        # Han muc con du ma van 429: khong phai chuyen cua key nay.
                        # Ha nhip ca may xuong roi chay tiep bang key khac.
                        bo_khoa.hoan(k, CHO_KHI_429)
                        moi, chan_ip = nhip_may.vap(k["ma"])
                        print("%s bao 429 nhung VirusTotal moi ghi nhan %d/%d luot ngay "
                              "-> khong phai het han muc.%s"
                              % ((k["nhan"],) + hm.get("ngay", (k["dung"], k["tran_rieng"]))
                                 + (("  Gian nhip chung len %.0f giay." % moi) if moi else "",)))
                        if chan_ip and not doi_pho_chan_ip(nhip_may, tham_so):
                            het_quota = True
                            break
                else:
                    # Khong hoi duoc han muc: doan theo thong bao, nhung chi khai tu
                    # mot key khi cac key khac van chay binh thuong. Dang bi chan
                    # theo IP thi key nao cung 429, khai tu la khai tu oan het.
                    k["lien_tiep"] += 1
                    moi, chan_ip = nhip_may.vap(k["ma"])
                    doan = het_han_ngay(tb)
                    if not chan_ip and (doan is True or k["lien_tiep"] >= SO_LAN_429_LA_HET_NGAY):
                        k["het_ngay"] = True
                        bo_khoa.luu(thu_muc_kq)
                        print("%s het han muc ngay sau %d luot%s. Con %d luot o cac key khac."
                              % (k["nhan"], k["dung"],
                                 (" (VirusTotal bao: %s)" % tb) if tb else "",
                                 bo_khoa.con_lai()))
                    else:
                        bo_khoa.hoan(k, CHO_KHI_429)
                        con = sum(1 for x in bo_khoa.ds if bo_khoa.dung_duoc(x))
                        print("%s bao 429 (%s) - lan thu %d, khong hoi duoc han muc that. "
                              "Hoan key nay %d giay, chuyen sang key khac (%d key kha dung).%s"
                              % (k["nhan"], tb or "khong kem thong bao", k["lien_tiep"],
                                 int(CHO_KHI_429), con,
                                 ("  Gian nhip chung len %.0f giay." % moi) if moi else ""))
                    if chan_ip and not doi_pho_chan_ip(nhip_may, tham_so):
                        het_quota = True
                        break
                continue
            k["lien_tiep"] = 0
            moi = nhip_may.tron()
            if moi is not None:
                print("   ... chay tron tru, rut nhip chung xuong %.1f giay mot luot" % moi)

            if loi == "404":
                d = dong_that_bai(m, TT_KHONG,
                                  "VirusTotal chưa có mẫu này. Cần gửi riêng hoặc đối chiếu "
                                  "nguồn khác, chưa kết luận được.")
                dem["chua_co"] += 1
                print("[%d/%d] %s  chua co tren VT" % (i, len(can_tra), m["sha256"][:12]))
            elif loi:
                d = dong_that_bai(m, TT_LOI, "Lỗi khi tra cứu: %s" % loi)
                dem["loi"] += 1
                print("[%d/%d] %s  loi: %s" % (i, len(can_tra), m["sha256"][:12], loi))
            else:
                d = phan_tich(m, data, tham_so.nguong)
                if d["Ket_luan"] == KL_DOC:
                    dem["ma_doc"] += 1
                elif d["Ket_luan"] == KL_NGHI:
                    dem["nghi_ngo"] += 1
                else:
                    dem["lanh_tinh"] += 1
                goi_tat = {KL_DOC: "MA DOC", KL_NGHI: "nghi ngo", KL_LANH: "lanh tinh"}
                print("[%d/%d] %s  %s/%s engine  -> %s  %s"
                      % (i, len(can_tra), m["sha256"][:12], d["So_engine_phat_hien"],
                         d["Tong_so_engine"], goi_tat.get(d["Ket_luan"], "?"),
                         d["Ho_ma_doc"][:40]))
                ban_luu = data if tham_so.json_day_du else rut_gon(data)
                with open(os.path.join(thu_muc_json, m["sha256"] + ".json"),
                          "w", encoding="utf-8") as f:
                    json.dump(ban_luu, f, ensure_ascii=False, indent=1)

            dong_moi.append(d)
            vi_tri += 1
            if len(dong_moi) % 315 == 0:
                ghi_them(thu_muc_kq, dong_moi, nhan_lan_chay, tham_so.thu_muc,
                         len(mau), tham_so.nguong)
                print("   ... da luu tam %d dong vao Excel (con %d luot quota)"
                      % (len(dong_moi), bo_khoa.con_lai()))

    except KeyboardInterrupt:
        print("\nDa dung theo yeu cau. Dang luu phan da lam...")

    tong_dong = ghi_them(thu_muc_kq, dong_moi, nhan_lan_chay, tham_so.thu_muc,
                         len(mau), tham_so.nguong)

    da_xong = set(xong)
    for d in dong_moi:
        if str(d.get("Trang_thai", "")).strip() in DA_XU_LY:
            da_xong.add(str(d["SHA-256"]).lower())
        else:
            da_xong.discard(str(d["SHA-256"]).lower())
    con = sum(1 for m in mau if m["sha256"] not in da_xong)
    print("\n--- Ket qua lan chay nay ---")
    print("  Ma doc (tu %d engine tro len): %d" % (tham_so.nguong, dem["ma_doc"]))
    if tham_so.nguong > 1:
        print("  Nghi ngo (1 den %d engine):    %d" % (tham_so.nguong - 1, dem["nghi_ngo"]))
    print("  Lanh tinh (0 engine):          %d" % dem["lanh_tinh"])
    print("  Chua co tren VT:               %d" % dem["chua_co"])
    print("  Loi khi goi API:               %d" % dem["loi"])
    print("  Quota tung key trong ngay:")
    bo_khoa.in_trang_thai("    ")
    print("  Con dung duoc hom nay:         %d luot" % bo_khoa.con_lai())
    print("  Tong so dong trong Excel:      %d" % tong_dong)
    print("  Con lai chua tra:              %d mau" % max(0, con))
    print("\nFile ket qua: %s" % duong_dan_excel(thu_muc_kq))
    print("Ban JSON goc:  %s" % thu_muc_json)
    if con > 0 and not het_quota:
        print("\nChay lai dung lenh nay de tra tiep phan con lai.")
    elif con > 0 and het_quota:
        print("\nCon %d mau chua tra. Them key moi vao %s roi chay lai lenh nay, "
              "hoac doi den 7 gio sang mai (moc VirusTotal dat lai han muc ngay)."
              % (con, os.path.join(thu_muc_script, TEN_FILE_KEY)))
        print("Muon xem han muc that cua tung key: python %s --kiem-tra-key"
              % os.path.basename(__file__))
        print("Neu VirusTotal bao con luot ma van bi 429, ha nhip ca may xuong nua: "
              "--nhip-chung 10 (6 luot/phut) hoac --nhip-chung 15 (4 luot/phut).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
