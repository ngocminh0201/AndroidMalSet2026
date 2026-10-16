# -*- coding: utf-8 -*-
"""gan_nhan_gemini.py - chuan hoa ket qua tho cua VirusTotal ve 5 nhan cuoi bang Gemini.

Day la Giai doan 2 cua buoc gan nhan trong quy trinh xay dung AndroidMalSet2026:
ket qua tho cua VirusTotal duoc dua vao mo hinh Gemini de gan nhan cuoi cung.
Mau co it nhat mot engine bao doc hai la malware, nguoc lai la benign; mau
malware duoc xep tiep vao bon nhom Riskware, Banking malware, SMS malware, Adware.

Dau vao la thu muc phan_hoi_json do quet_virustotal.py sinh ra (ban tra loi goc cua
VirusTotal cho tung mau, dat ten theo SHA-256). Script khong goi lai VirusTotal.

Mot cot nhan duy nhat - Nhan_bai_bao - theo quy uoc mac dinh cua bo du lieu:
co it nhat 1 engine bao doc la malware, khong engine nao bao la benign. Truoc day
script con ghi them cot doi chieu theo nguong 4 engine; da bo han de bo du lieu
chi ton tai mot quy uoc nhan.

Tiet kiem quota: free tier cua Gemini chan o SO LUOT GOI trong ngay (RPD 20 cho
gemini-2.5-flash), khong chan o so mau. Vi vay:
  - Quyet dinh malware/benign la quy tac dem engine, khong can hoi Gemini. Chi mau
    co it nhat 1 engine bao doc moi phai goi API. Mau 0 engine gan Benign truc tiep.
  - Moi luot goi mang theo 70 mau (doi bang --lo), nen 20 luot phu duoc 1.400 mau.
  - Bo dem quota tinh rieng cho tung model va dat lai theo gio Thai Binh Duong,
    dung nhu cach Google tinh. Het luot cua gemini-2.5-flash thi chay tiep bang
    --model gemini-2.5-flash-lite de dung bo dem thu hai.

Ket qua ghi noi them vao Ket_qua_GanNhan.xlsx (khong bao gio ghi de), ban tra loi
goc cua Gemini luu trong thu muc phan_hoi_gemini de lam minh chung.

Che do --tinh-lai: dung lai Ket_qua_GanNhan.xlsx tu chinh cac dong da co, khong
goi API va khong ton luot quota nao. Dung khi doi cau truc cot cua bang ket qua.

Vi du chay:
    python gan_nhan_gemini.py
    python gan_nhan_gemini.py --gioi-han 20
    python gan_nhan_gemini.py --model gemini-3.5-flash --lo 5
    python gan_nhan_gemini.py --tinh-lai
"""

import argparse
import copy as _copy
import datetime
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

API = "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent"
TEN_FILE_EXCEL = "Ket_qua_GanNhan.xlsx"
TEN_FILE_EXCEL_VT = "Ket_qua_VirusTotal.xlsx"
S_KQ_VT = "Ket_qua_VT"
COT_NHAN_VT = "Nhan_Gemini"   # cot ghi nguoc vao bang VirusTotal
TEN_FILE_QUOTA = "_quota_gemini.json"
TEN_FILE_CAU_HINH = "_cau_hinh_model.json"
S_KQ, S_TH = "Nhan_cuoi", "Tong_hop"

COT = ["Lan_chay", "SHA-256", "Ten_file", "Goi_Android", "So_engine_phat_hien",
       "Tong_so_engine", "Ho_ma_doc", "Nhom_de_doa", "Nhan_bai_bao",
       "Nhan_goi_y_VT", "Khop_goi_y", "Do_tin_cay", "Ly_do", "Nguon_nhan",
       "Model", "Trang_thai", "Ghi_chu"]
COT_SO = {"So_engine_phat_hien", "Tong_so_engine"}

FONT = "Times New Roman"
XANH = PatternFill("solid", fgColor="1F4E78")
XAM = PatternFill("solid", fgColor="D9E1F2")

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")

BENIGN = "Benign"
NHAN_MA_DOC = ["Banking malware", "SMS malware", "Adware", "Riskware"]
NHAN_HET = [BENIGN] + NHAN_MA_DOC
NHAN_CHUA = "Chưa xác định"

TT_XONG, TT_LOI, TT_THIEU = "Đã gán nhãn", "Lỗi gọi Gemini", "Chưa có dữ liệu VirusTotal"
NGUON_QUY_TAC = "Quy tắc 0 engine"
NGUON_GEMINI = "Gemini"

# (khong dung) bang tham chieu cu, giu lai cho tuong thich.
_THAM_CHIEU_CU = [("Benign", 2220), ("Riskware", 830), ("Adware", 829),
      ("SMS malware", 81), ("Banking malware", 60)]

MO_TA_NHAN = """- Banking malware: ma doc nham vao thong tin tai chinh va du lieu ngan hang cua
  nguoi dung. Hanh vi dac trung: danh cap thong tin dang nhap, chen lop phu (overlay
  attack) len ung dung ngan hang, doc tin nhan OTP, chuyen huong giao dich. Ho ma doc
  thuong gap: cerberus, anubis, hydra, teabot, sharkbot, flubot, medusa, octo, ermac,
  svpeng, marcher, asacub, coper, vultur, alien, brata, sova, xenomorph, banker, banbot.
- SMS malware: ma doc loi dung API SMS de gui tin nhan trai phep, chan hoac doc noi
  dung SMS, hoac dang ky dich vu mat phi. Thuong khai thac quyen SEND_SMS va READ_SMS.
  Ho thuong gap: smsreg, smssend, smsthief, opfake, fakeinst, smforw, podec, boxer,
  wapsx, joker, jocker, harly, smspay, autosms.
- Adware: ma doc hien thi quang cao khong mong muon, chen quang cao ngoai ung dung,
  thu thap du lieu phuc vu quang cao. Ho thuong gap: airpush, dowgin, kuguo, revmob,
  youmi, adwo, hiddenad, hiddad, ewind, leadbolt, inmobi, startapp, mobidash, shedun,
  batmobi, adflex, adpush.
- Riskware: ung dung co kha nang gay rui ro bao mat do su dung chuc nang nhay cam
  hoac tiem an kha nang bi lam dung, khai thac quyen truy cap rong, can thiep sau vao
  he thong. Khong nhat thiet duoc thiet ke voi muc dich doc hai. Bao gom ca cac mau bi
  engine danh dau la packer/obfuscator/tool/monitor/tracker. Ho thuong gap: riskware,
  riskool, skymobi, wapron, secapk, jiagu, packer, hiddenapp, agentsmith, revenue."""


# ---------------------------------------------------------------- doc tham so

def doc_tham_so():
    p = argparse.ArgumentParser(
        description="Chuan hoa ket qua VirusTotal ve 5 nhan cuoi bang mo hinh Gemini.")
    p.add_argument("--thu-muc-json", default="",
                   help="thu muc chua ban tra loi VirusTotal; mac dinh phan_hoi_json "
                        "trong thu muc chua script nay")
    p.add_argument("--ket-qua", default="",
                   help="thu muc ghi Excel va JSON; mac dinh la thu muc chua script nay")
    p.add_argument("--key", default="",
                   help="API key Gemini; de trong thi doc file api_key_gemini.txt "
                        "hoac bien moi truong GEMINI_API_KEY")
    p.add_argument("--model", default="gemini-2.5-flash",
                   help="ten model Gemini (mac dinh gemini-2.5-flash)")
    p.add_argument("--lo", type=int, default=70,
                   help="so mau gui trong mot lan goi API (mac dinh 70). Free tier bi "
                        "chan o so LUOT/ngay (RPD 20) chu khong phai so mau, nen lo cang "
                        "lon cang loi; giam xuong 40 neu model hay bo sot mau")
    p.add_argument("--nhip", type=float, default=20.0,
                   help="so giay cho giua hai lan goi API (mac dinh 20, tuc 3 luot/phut - "
                        "duoi ca tran RPM 5 lan tran TPM 250K)")
    p.add_argument("--gioi-han-ngay", type=int, default=20,
                   help="tran so LUOT GOI trong mot ngay (mac dinh 20, dung bang RPD cua "
                        "free tier); dem rieng cho tung model")
    p.add_argument("--gioi-han", type=int, default=0,
                   help="chi xu ly toi da bay nhieu mau trong lan chay nay; 0 = khong gioi han")
    p.add_argument("--so-engine", type=int, default=25,
                   help="so dong ket qua engine toi da dua vao prompt cho moi mau (mac dinh 25); "
                        "cac dong dau da du nhan dien ho ma doc, cat bot de nhoi duoc nhieu mau "
                        "hon vao mot luot goi")
    p.add_argument("--uu-tien", default="Banking malware,SMS malware,Adware,Riskware",
                   help="thu tu uu tien khi mot mau co dau hieu cua nhieu nhom")
    p.add_argument("--tinh-lai", action="store_true",
                   help="dung lai Excel tu chinh cac dong da co (dung khi doi cau truc "
                        "cot), khong goi API, khong ton quota")
    p.add_argument("--gan-lai", action="store_true",
                   help="gan lai ca nhung mau da co nhan trong Excel")
    p.add_argument("--suy-luan", action="store_true",
                   help="de model tu quyet che do suy luan; mac dinh script ha xuong "
                        "muc thap nhat cho nhanh va re (thinkingBudget cho dong 2.5, "
                        "thinkingLevel cho dong 3.x)")
    p.add_argument("--khong-ghi-vt", action="store_true",
                   help="khong ghi cot %s nguoc vao %s"
                        % (COT_NHAN_VT, TEN_FILE_EXCEL_VT))
    p.add_argument("--thu", action="store_true",
                   help="chay thu: in prompt cua lo dau tien roi dung, khong goi API")
    return p.parse_args()


def lay_key(tham_so, thu_muc_script):
    if tham_so.key.strip():
        return tham_so.key.strip()
    if os.environ.get("GEMINI_API_KEY", "").strip():
        return os.environ["GEMINI_API_KEY"].strip()
    for ten in ("api_key_gemini.txt", "gemini_api_key.txt"):
        dd = os.path.join(thu_muc_script, ten)
        if os.path.exists(dd):
            with open(dd, "r", encoding="utf-8") as f:
                for dong in f:
                    dong = dong.strip()
                    if dong and not dong.startswith("#"):
                        return dong
    return ""


# -------------------------------------------------------- doc du lieu dau vao

def doc_excel_vt(thu_muc):
    """Doc Ket_qua_VirusTotal.xlsx de lay ten file, duong dan va nhan goi y."""
    dd = os.path.join(thu_muc, TEN_FILE_EXCEL_VT)
    if not os.path.exists(dd):
        return {}
    try:
        wb = load_workbook(dd, read_only=True, data_only=True)
    except Exception:
        return {}
    if "Ket_qua_VT" not in wb.sheetnames:
        wb.close()
        return {}
    ws = wb["Ket_qua_VT"]
    tieu_de = [c.value for c in ws[1]]
    ra = {}
    for hang in ws.iter_rows(min_row=2, values_only=True):
        if all(v is None for v in hang):
            continue
        d = {t: ("" if v is None else v) for t, v in zip(tieu_de, hang)}
        h = str(d.get("SHA-256", "")).strip().lower()
        if h:
            ra[h] = d
    wb.close()
    return ra


def liet_ke_mau(thu_muc_json, thong_tin_vt):
    """Doc tat ca file JSON cua VirusTotal, tra ve danh sach mau da rut gon."""
    if not os.path.isdir(thu_muc_json):
        raise SystemExit(
            "Khong thay thu muc %s.\nChay quet_virustotal.py truoc de co du lieu tho, "
            "hoac chi ro bang --thu-muc-json." % thu_muc_json)

    ra = []
    for ten in sorted(os.listdir(thu_muc_json)):
        if not ten.lower().endswith(".json"):
            continue
        goc = os.path.splitext(ten)[0]
        if not HEX64.match(goc):
            continue
        dd = os.path.join(thu_muc_json, ten)
        try:
            with open(dd, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print("  bo qua %s (khong doc duoc: %s)" % (ten, e))
            continue
        m = rut_thong_tin(goc.lower(), data, thong_tin_vt.get(goc.lower(), {}))
        if m:
            ra.append(m)
    return ra


def rut_thong_tin(sha, data, dong_vt):
    """Gom thong tin can thiet tu ban tra loi VirusTotal ve mot dict phang."""
    a = (data.get("attributes") or {}) if isinstance(data, dict) else {}
    if not a:
        return None
    tk = a.get("last_analysis_stats", {}) or {}
    doc_hai = int(tk.get("malicious", 0) or 0)
    nghi = int(tk.get("suspicious", 0) or 0)
    tong = sum(int(tk.get(k, 0) or 0) for k in
               ("malicious", "suspicious", "undetected", "harmless", "timeout"))

    pt = a.get("popular_threat_classification", {}) or {}
    ho = pt.get("suggested_threat_label", "") or ""
    nhom = ", ".join("%s (%d)" % (x.get("value", ""), x.get("count", 0))
                     for x in (pt.get("popular_threat_category") or [])[:3])
    ten_ho = ", ".join("%s (%d)" % (x.get("value", ""), x.get("count", 0))
                       for x in (pt.get("popular_threat_name") or [])[:5])

    ket_qua = []
    for ten_engine, kq in sorted((a.get("last_analysis_results") or {}).items()):
        if not isinstance(kq, dict):
            continue
        if kq.get("category") in ("malicious", "suspicious") and kq.get("result"):
            ket_qua.append("%s: %s" % (ten_engine, kq.get("result")))

    ag = a.get("androguard") or {}
    goi = str(ag.get("Package") or "") if isinstance(ag, dict) else ""

    return {
        "sha256": sha,
        "ten": str(dong_vt.get("Ten_file", "") or a.get("meaningful_name", "") or ""),
        "goi": goi,
        "doc_hai": doc_hai,
        "nghi": nghi,
        "tong": tong,
        "ho": ho,
        "ten_ho": ten_ho,
        "nhom": nhom,
        "the": ", ".join(a.get("tags") or [])[:200],
        "ket_qua_engine": ket_qua,
        "nhan_goi_y_vt": str(dong_vt.get("Nhan_goi_y", "") or ""),
    }


# ------------------------------------------------------------------- prompt

def mo_ta_mau(m, so_engine):
    """Bien mot mau thanh doan van ban ngan gon de dua vao prompt."""
    dong = ["SHA256: %s" % m["sha256"]]
    if m["goi"]:
        dong.append("Package: %s" % m["goi"])
    dong.append("So engine bao doc hai: %d/%d (nghi ngo: %d)"
                % (m["doc_hai"], m["tong"], m["nghi"]))
    if m["ho"]:
        dong.append("Nhan ho do VirusTotal tong hop: %s" % m["ho"])
    if m["ten_ho"]:
        dong.append("Ten ho pho bien: %s" % m["ten_ho"])
    if m["nhom"]:
        dong.append("Nhom de doa pho bien: %s" % m["nhom"])
    if m["the"]:
        dong.append("Tag hanh vi: %s" % m["the"])
    if m["ket_qua_engine"]:
        dong.append("Ket qua tung engine (%d dong):" % min(len(m["ket_qua_engine"]), so_engine))
        dong.extend("  " + t for t in m["ket_qua_engine"][:so_engine])
    return "\n".join(dong)


def dung_prompt(lo, so_engine, uu_tien):
    phan = []
    for i, m in enumerate(lo, start=1):
        phan.append("### MAU %d\n%s" % (i, mo_ta_mau(m, so_engine)))
    return """Ban la chuyen gia phan tich ma doc Android. Nhiem vu: chuan hoa ket qua tho
cua VirusTotal thanh nhan cuoi cung cho bo du lieu.

Moi mau duoi day DA duoc xac dinh la ma doc (co it nhat mot engine bao doc hai).
Viec cua ban chi la xep no vao DUNG MOT trong bon nhom sau, dua tren ten ho ma doc
do cac engine dat, nhom de doa, tag hanh vi va ten goi ung dung:

%s

Quy tac quyet dinh:
1. Uu tien bang chung tu ten ho ma doc cu the (vi du "cerberus", "joker", "airpush")
   hon la nhan chung chung ("trojan", "malware", "generic", "artemis", "gen").
2. Neu mau co dau hieu cua nhieu nhom, chon theo thu tu uu tien: %s.
3. Neu khong co bang chung ro rang cho ba nhom dau, xep vao Riskware.
4. Khong duoc tra ve nhan "Benign" - moi mau trong danh sach nay deu la ma doc.
5. Truong "ly_do" viet bang tieng Viet, toi da 25 tu, neu ro bang chung da dua vao.
6. Truong "do_tin_cay" la so thuc 0-1: 0.9 tro len khi ten ho ma doc chi ro nhom,
   0.5-0.7 khi phai suy tu tag hanh vi hoac nhan chung chung, duoi 0.5 khi gan doan.

Tra ve DUNG mot mang JSON, moi phan tu ung voi mot mau theo dung thu tu, dang:
[{"mau": 1, "sha256": "...", "nhan": "Banking malware", "do_tin_cay": 0.95, "ly_do": "..."}]
Khong them bat ky van ban nao ngoai mang JSON.

%s""" % (MO_TA_NHAN, uu_tien, "\n\n".join(phan))


# ------------------------------------------------------------------- goi API

LUOC_DO = {
    "type": "ARRAY",
    "items": {
        "type": "OBJECT",
        "properties": {
            "mau": {"type": "INTEGER"},
            "sha256": {"type": "STRING"},
            "nhan": {"type": "STRING", "enum": NHAN_MA_DOC},
            "do_tin_cay": {"type": "NUMBER"},
            "ly_do": {"type": "STRING"},
        },
        "required": ["mau", "nhan", "do_tin_cay", "ly_do"],
    },
}


def dung_cau_hinh(bien_the, model, suy_luan, so_mau):
    """Dung generationConfig theo tung bien the, de do dan khi model tu choi.

    Cac dong model khai bao che do suy luan khac nhau: dong 2.5 dung
    thinkingBudget, dong 3.x dung thinkingLevel va tra ve 400 INVALID_ARGUMENT
    neu nhan phai thinkingBudget. Doan ten model cho phat dung ngay tu lan dau
    trong da so truong hop; bien the con lai la de do khi Google doi ten truong.

      0 - che do suy luan doan theo ten model + responseSchema
      1 - che do suy luan kieu con lai        + responseSchema
      2 - khong dat che do suy luan           + responseSchema
      3 - khong dat che do suy luan           + chi responseMimeType
      4 - khong dat gi them, dua hoan toan vao huong dan trong prompt
    """
    cau_hinh = {"temperature": 0.0,
                "maxOutputTokens": min(65536, 512 + 120 * max(1, so_mau))}
    if bien_the <= 2:
        cau_hinh["responseMimeType"] = "application/json"
        cau_hinh["responseSchema"] = LUOC_DO
    elif bien_the == 3:
        cau_hinh["responseMimeType"] = "application/json"

    if not suy_luan:
        dong_3 = model.lower().startswith("gemini-3")
        if bien_the == 0:
            cau_hinh["thinkingConfig"] = ({"thinkingLevel": "low"} if dong_3
                                          else {"thinkingBudget": 0})
        elif bien_the == 1:
            cau_hinh["thinkingConfig"] = ({"thinkingBudget": 0} if dong_3
                                          else {"thinkingLevel": "low"})
    return cau_hinh


def doc_bien_the(thu_muc, model):
    """Bien the da chay duoc voi model nay o lan truoc, de khoi do lai tu dau."""
    dd = os.path.join(thu_muc, TEN_FILE_CAU_HINH)
    if os.path.exists(dd):
        try:
            with open(dd, "r", encoding="utf-8") as f:
                return int(json.load(f).get(model, 0))
        except Exception:
            pass
    return 0


def ghi_bien_the(thu_muc, model, bien_the):
    dd = os.path.join(thu_muc, TEN_FILE_CAU_HINH)
    d = {}
    if os.path.exists(dd):
        try:
            with open(dd, "r", encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            d = {}
    if d.get(model) == bien_the:
        return
    d[model] = bien_the
    with open(dd, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)


def goi_gemini(prompt, key, model, suy_luan, so_mau=1, thu_muc="", so_lan=3):
    """Tra ve (van_ban, loi, ly_do_dung, so_yeu_cau).

    so_yeu_cau la so lan thuc su goi len API - moi lan deu tinh vao han muc ngay,
    ke ca lan bi tu choi hay phai thu lai, nen ham tra ve de ben goi cong dung.
    loi == "429" nghia la cham tran quota.
    """
    bien_the = doc_bien_the(thu_muc, model) if thu_muc else 0
    if suy_luan and bien_the < 2:
        bien_the = 2       # khong dat che do suy luan thi hai bien the dau trung nhau
    so_yeu_cau = 0
    lan_loi = 0

    while bien_the <= 4:
        cau_hinh = dung_cau_hinh(bien_the, model, suy_luan, so_mau)
        than = json.dumps({"contents": [{"role": "user", "parts": [{"text": prompt}]}],
                           "generationConfig": cau_hinh}).encode("utf-8")
        yc = urllib.request.Request(API % model, data=than, headers={
            "x-goog-api-key": key, "Content-Type": "application/json",
            "User-Agent": "gan_nhan_gemini/1.0"})
        so_yeu_cau += 1
        try:
            with urllib.request.urlopen(yc, timeout=180) as p:
                d = json.loads(p.read().decode("utf-8"))
            if thu_muc:
                ghi_bien_the(thu_muc, model, bien_the)
            ung = (d.get("candidates") or [{}])[0]
            phan = ((ung.get("content") or {}).get("parts") or [])
            van_ban = "".join(x.get("text", "") for x in phan)
            ly_do_dung = str(ung.get("finishReason", "") or "")
            if not van_ban.strip():
                return "", ("Model tra ve rong (finishReason=%s)" % ly_do_dung), \
                    ly_do_dung, so_yeu_cau
            return van_ban, "", ly_do_dung, so_yeu_cau

        except urllib.error.HTTPError as e:
            try:
                chi_tiet = " ".join(e.read().decode("utf-8", "replace").split())[:300]
            except Exception:
                chi_tiet = ""
            if e.code == 429:
                return "", "429", "", so_yeu_cau
            if e.code in (401, 403):
                return "", "%d: %s" % (e.code, chi_tiet), "", so_yeu_cau
            if e.code == 404:
                return "", ("404: khong co model ten '%s'. Xem danh sach hien hanh o "
                            "https://ai.google.dev/gemini-api/docs/models" % model), \
                    "", so_yeu_cau
            if e.code == 400:
                if bien_the < 4:
                    print("   model tu choi cau hinh (bien the %d): %s"
                          % (bien_the, chi_tiet[:120]))
                    print("   thu lai voi bien the %d ..." % (bien_the + 1))
                    bien_the += 1
                    continue
                return "", "HTTP 400: %s" % chi_tiet, "", so_yeu_cau
            if e.code in (500, 502, 503, 504) and lan_loi < so_lan - 1:
                lan_loi += 1
                time.sleep(15 * lan_loi)
                continue
            return "", "HTTP %d: %s" % (e.code, chi_tiet), "", so_yeu_cau

        except Exception as e:
            if lan_loi < so_lan - 1:
                lan_loi += 1
                time.sleep(15 * lan_loi)
                continue
            return "", "Loi ket noi: %s" % e, "", so_yeu_cau

    return "", "Khong cau hinh nao duoc model chap nhan", "", so_yeu_cau


def doc_tra_loi(van_ban, lo):
    """Ghep tra loi cua model voi tung mau trong lo. Tra ve dict sha256 -> ket qua."""
    van_ban = van_ban.strip()
    if van_ban.startswith("```"):
        van_ban = re.sub(r"^```[a-zA-Z]*\s*", "", van_ban)
        van_ban = re.sub(r"```\s*$", "", van_ban).strip()
    try:
        d = json.loads(van_ban)
    except Exception:
        d = None
        khop = re.search(r"\[.*\]", van_ban, re.S)
        if khop:
            try:
                d = json.loads(khop.group(0))
            except Exception:
                d = None
        if d is None:
            # Chuoi bi cat giua chung (thuong do cham tran token dau ra). Nhat lai
            # tung phan tu con nguyen ven - moi luot goi ton 5% han muc ngay nen
            # cuu duoc mau nao hay mau do.
            d = []
            for manh in re.findall(r"\{[^{}]*\}", van_ban, re.S):
                try:
                    d.append(json.loads(manh))
                except Exception:
                    pass
            if not d:
                return {}
    if isinstance(d, dict):
        d = [d]
    if not isinstance(d, list):
        return {}

    theo_sha = {m["sha256"]: m for m in lo}
    ra = {}
    for i, x in enumerate(d):
        if not isinstance(x, dict):
            continue
        sha = str(x.get("sha256", "")).strip().lower()
        if sha not in theo_sha:
            # Model khong tra lai sha256 dung: dua vao so thu tu mau.
            try:
                vt = int(x.get("mau", i + 1)) - 1
            except Exception:
                vt = i
            if not (0 <= vt < len(lo)):
                continue
            sha = lo[vt]["sha256"]
        nhan = str(x.get("nhan", "")).strip()
        khop = [n for n in NHAN_MA_DOC if n.lower() == nhan.lower()]
        if not khop:
            khop = [n for n in NHAN_MA_DOC if n.lower().split()[0] in nhan.lower()]
        if not khop:
            continue
        try:
            tin = round(float(x.get("do_tin_cay", 0)), 2)
        except Exception:
            tin = ""
        ra[sha] = {"nhan": khop[0], "do_tin_cay": tin,
                   "ly_do": str(x.get("ly_do", "")).strip()[:300]}
    return ra


# ---------------------------------------------------------------- quota ngay

def ngay_quota():
    """Google dat lai han muc ngay theo gio Thai Binh Duong, tuc khoang 14-15h gio Viet Nam.

    Dung dung moc do de bo dem cua script khong lech voi bo dem cua Google.
    """
    try:
        from zoneinfo import ZoneInfo
        return datetime.datetime.now(ZoneInfo("America/Los_Angeles")).date().isoformat()
    except Exception:
        return (datetime.datetime.now(datetime.timezone.utc)
                - datetime.timedelta(hours=8)).date().isoformat()


def doc_quota(thu_muc, model):
    """Tra ve so luot da goi trong ngay cho rieng model nay."""
    dd = os.path.join(thu_muc, TEN_FILE_QUOTA)
    if os.path.exists(dd):
        try:
            with open(dd, "r", encoding="utf-8") as f:
                d = json.load(f)
            if d.get("ngay") == ngay_quota():
                return int((d.get("theo_model") or {}).get(model, 0))
        except Exception:
            pass
    return 0


def ghi_quota(thu_muc, model, so_luot):
    dd = os.path.join(thu_muc, TEN_FILE_QUOTA)
    d = {}
    if os.path.exists(dd):
        try:
            with open(dd, "r", encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            d = {}
    if d.get("ngay") != ngay_quota():
        d = {"ngay": ngay_quota(), "theo_model": {}}
    d.setdefault("theo_model", {})[model] = so_luot
    with open(dd, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)


# ------------------------------------------------------------- dung dong ket qua

def dong_ket_qua(m, nhan_ma_doc, nguon, model, do_tin_cay="", ly_do="",
                 trang_thai=TT_XONG, ghi_chu=""):
    """Dung dong ket qua tu so engine bao doc va nhan ma doc do Gemini xep.

    Quy uoc nhan mac dinh cua bo du lieu: co it nhat 1 engine bao doc thi la
    malware va lay nhom ma doc do Gemini xep, khong engine nao bao thi la benign.
    """
    nhan_1 = BENIGN if m["doc_hai"] < 1 else (nhan_ma_doc or NHAN_CHUA)
    goi_y = m.get("nhan_goi_y_vt", "")
    if goi_y and nhan_1 not in ("", NHAN_CHUA):
        khop = "Khớp" if goi_y.strip().lower() == nhan_1.lower() else "Lệch"
    else:
        khop = ""
    return {
        "SHA-256": m["sha256"], "Ten_file": m["ten"], "Goi_Android": m["goi"],
        "So_engine_phat_hien": m["doc_hai"], "Tong_so_engine": m["tong"],
        "Ho_ma_doc": " | ".join(t for t in (m["ho"], m["ten_ho"]) if t),
        "Nhom_de_doa": m["nhom"],
        "Nhan_bai_bao": nhan_1, "Nhan_goi_y_VT": goi_y, "Khop_goi_y": khop,
        "Do_tin_cay": do_tin_cay, "Ly_do": ly_do,
        "Nguon_nhan": nguon, "Model": model if nguon == NGUON_GEMINI else "",
        "Trang_thai": trang_thai, "Ghi_chu": ghi_chu,
    }


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

    cot_tin = COT.index("Do_tin_cay") + 1
    for hang in ws.iter_rows(min_row=2):
        for o in hang:
            o.font = Font(name=FONT, size=10)
            o.alignment = Alignment(vertical="top")
        hang[cot_tin - 1].number_format = "0.00"
        hang[cot_tin - 1].alignment = Alignment(horizontal="center", vertical="top")

    for i, ten in enumerate(COT, start=1):
        rong = max([len(str(ten))] + [len(str(d.get(ten, ""))) for d in du_lieu[:500]]) + 2
        ws.column_dimensions[get_column_letter(i)].width = min(max(rong, 9), 46)
    if du_lieu:
        ws.auto_filter.ref = "A1:%s%d" % (get_column_letter(len(COT)), len(du_lieu) + 1)
    ws.freeze_panes = "C2"


def _ke_tong_hop(ws, du_lieu, model, thu_muc_json):
    ws["A1"] = "TỔNG HỢP NHÃN CUỐI SAU BƯỚC CHUẨN HÓA BẰNG GEMINI"
    ws["A1"].font = Font(name=FONT, size=14, bold=True)
    ws.merge_cells("A1:E1")

    chu_thich = [
        "Số liệu lập ngày %s. Dữ liệu thô: %s (%d mẫu có kết quả VirusTotal). "
        "Model dùng để chuẩn hóa nhãn: %s."
        % (datetime.date.today().strftime("%d/%m/%Y"), thu_muc_json, len(du_lieu), model),
        "Giai đoạn 2 của bước gán nhãn: kết quả thô "
        "của VirusTotal được đưa vào mô hình Gemini để phân tích và gán nhãn cuối cùng. "
        "Mẫu có ít nhất một engine báo độc hại được xác định là malware, ngược lại là benign; "
        "với mẫu malware, mô hình xếp tiếp vào bốn nhóm Riskware, Banking malware, SMS malware, Adware.",
        "Cột Nhan_bai_bao là nhãn cuối duy nhất của bộ dữ liệu, dùng đúng ngưỡng 1 engine như quy "
        "ước đã công bố. Mẫu chỉ bị một vài engine báo độc vẫn là mã độc, không tách riêng thành "
        "vùng nghi ngờ — bộ dữ liệu chỉ tồn tại một quy ước nhãn để mọi số liệu báo cáo đều nhất quán.",
        "Cột Nhan_goi_y_VT lấy từ bước đối chiếu từ khóa máy móc trong script quét VirusTotal, "
        "cột Khop_goi_y so nhãn đó với nhãn cuối do Gemini xếp. Tỷ lệ lệch giữa hai cách là số liệu "
        "định lượng cho mức độ khó của bước gán nhãn.",
        "Bản trả lời gốc của Gemini cho từng mẫu nằm trong thư mục phan_hoi_gemini, đặt tên theo "
        "SHA-256; bản trả lời theo lô nằm trong phan_hoi_gemini\\_lo. Dùng làm minh chứng khi báo cáo.",
    ]
    hang = 3
    for t in chu_thich:
        o = ws.cell(row=hang, column=1, value=t)
        o.font = Font(name=FONT, size=9, italic=True, color="404040")
        o.alignment = Alignment(wrap_text=True, vertical="top")
        ws.merge_cells(start_row=hang, start_column=1, end_row=hang, end_column=5)
        ws.row_dimensions[hang].height = 26 if len(t) < 150 else 44
        hang += 1

    for rong, i in ((10, 1), (44, 2), (14, 3), (12, 4), (16, 5)):
        ws.column_dimensions[get_column_letter(i)].width = rong

    def bang(tieu_de, cap, tong, cot_them=None):
        nonlocal hang
        hang += 1
        o = ws.cell(row=hang, column=2, value=tieu_de)
        o.font = Font(name=FONT, size=12, bold=True)
        hang += 1
        tieu = ["STT", "Hạng mục", "Số mẫu", "Tỷ lệ"] + ([cot_them] if cot_them else [])
        for i, ten in enumerate(tieu, start=1):
            c = ws.cell(row=hang, column=i, value=ten)
            c.font = Font(name=FONT, size=11, bold=True, color="FFFFFF")
            c.fill = XANH
            c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        for stt, muc in enumerate(cap, start=1):
            ten, so = muc[0], muc[1]
            hang += 1
            ws.cell(row=hang, column=1, value=stt)
            ws.cell(row=hang, column=2, value=ten)
            ws.cell(row=hang, column=3, value=so)
            c = ws.cell(row=hang, column=4, value=(so / tong) if tong else 0)
            c.number_format = "0.0%"
            if cot_them and len(muc) > 2:
                ws.cell(row=hang, column=5, value=muc[2])
            for i in range(1, 6 if cot_them else 5):
                x = ws.cell(row=hang, column=i)
                x.font = Font(name=FONT, size=10)
                x.alignment = Alignment(horizontal="left" if i == 2 else "center")
        hang += 1
        ws.cell(row=hang, column=2, value="TỔNG CỘNG")
        ws.cell(row=hang, column=3, value=tong)
        for i in range(1, 6 if cot_them else 5):
            x = ws.cell(row=hang, column=i)
            x.font = Font(name=FONT, size=11, bold=True)
            x.fill = XAM
            x.alignment = Alignment(horizontal="left" if i == 2 else "center")
        hang += 1

    tong = len(du_lieu)

    def dem_theo(cot):
        d = {}
        for x in du_lieu:
            t = str(x.get(cot, "")) or "(trống)"
            d[t] = d.get(t, 0) + 1
        return d

    dem1 = dem_theo("Nhan_bai_bao")
    ten_nhan = NHAN_HET + [t for t in sorted(dem1) if t not in NHAN_HET]
    bang("Theo nhãn cuối (ngưỡng 1 engine, quy ước mặc định)",
         [(t, dem1.get(t, 0)) for t in ten_nhan], tong)

    khop = sum(1 for x in du_lieu if x.get("Khop_goi_y") == "Khớp")
    lech_gy = sum(1 for x in du_lieu if x.get("Khop_goi_y") == "Lệch")
    trong = tong - khop - lech_gy
    bang("Đối chiếu nhãn cuối với nhãn gợi ý theo từ khóa của VirusTotal",
         [("Khớp", khop), ("Lệch", lech_gy), ("Không so được", trong)], tong)

    nguon = dem_theo("Nguon_nhan")
    bang("Theo nguồn gán nhãn", sorted(nguon.items(), key=lambda kv: -kv[1]), tong)

    trang = dem_theo("Trang_thai")
    bang("Theo trạng thái xử lý", sorted(trang.items(), key=lambda kv: -kv[1]), tong)


def ghi_them(thu_muc, dong_moi, nhan_lan_chay, model, thu_muc_json):
    """Ghi noi them ket qua vao Excel. Dong nao trung SHA-256 thi thay bang ban moi."""
    dd = duong_dan_excel(thu_muc)
    cu = doc_excel(thu_muc)

    if os.path.exists(dd):
        ban_sao = os.path.join(thu_muc, "_ban_cu")
        os.makedirs(ban_sao, exist_ok=True)
        shutil.copy2(dd, os.path.join(
            ban_sao, "Ket_qua_GanNhan_%s.xlsx"
            % datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")))

    theo_hash, thu_tu = {}, []
    for d in cu:
        h = str(d.get("SHA-256", "")).strip().lower()
        if not h:
            continue
        if h not in theo_hash:
            thu_tu.append(h)
        theo_hash[h] = d
    for d in dong_moi:
        h = str(d.get("SHA-256", "")).strip().lower()
        if h not in theo_hash:
            thu_tu.append(h)
        x = dict(d)
        x["Lan_chay"] = nhan_lan_chay
        theo_hash[h] = x

    du_lieu = [theo_hash[h] for h in thu_tu]

    wb = Workbook()
    _ke_bang(wb.active, du_lieu)
    wb.active.title = S_KQ
    _ke_tong_hop(wb.create_sheet(S_TH), du_lieu, model, thu_muc_json)
    wb.save(dd)
    return len(du_lieu)


# ------------------------------------------------- ghi nguoc vao bang VirusTotal

def cap_nhat_excel_vt(thu_muc, nhan_theo_sha):
    """Chen cot Nhan_Gemini vao Ket_qua_VirusTotal.xlsx, ngay sau cot Nhan_goi_y.

    De nguoi doc so duoc nhan gao y theo tu khoa va nhan cuoi sau buoc Gemini tren
    cung mot dong, khong phai mo hai file. Cot chi duoc chen mot lan; nhung lan sau
    chi ghi de gia tri. quet_virustotal.py da duoc sua de giu lai cot nay khi no ghi
    lai file.
    """
    dd = os.path.join(thu_muc, TEN_FILE_EXCEL_VT)
    if not nhan_theo_sha or not os.path.exists(dd):
        return 0
    try:
        wb = load_workbook(dd)
    except Exception as e:
        print("  khong mo duoc %s de ghi cot %s: %s" % (TEN_FILE_EXCEL_VT, COT_NHAN_VT, e))
        return 0
    if S_KQ_VT not in wb.sheetnames:
        wb.close()
        return 0
    ws = wb[S_KQ_VT]

    tieu_de = [c.value for c in ws[1]]
    if COT_NHAN_VT not in tieu_de:
        cot = (tieu_de.index("Nhan_goi_y") + 2) if "Nhan_goi_y" in tieu_de \
            else len(tieu_de) + 1
        ws.insert_cols(cot)
        o = ws.cell(row=1, column=cot, value=COT_NHAN_VT)
        o.font = Font(name=FONT, size=11, bold=True, color="FFFFFF")
        o.fill = XANH
        o.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        ws.column_dimensions[get_column_letter(cot)].width = 18
        ws.auto_filter.ref = "A1:%s%d" % (get_column_letter(ws.max_column), ws.max_row)
        tieu_de = [c.value for c in ws[1]]

    if "SHA-256" not in tieu_de:
        wb.close()
        return 0
    cot = tieu_de.index(COT_NHAN_VT) + 1
    i_sha = tieu_de.index("SHA-256") + 1

    dem = 0
    for r in range(2, ws.max_row + 1):
        h = str(ws.cell(row=r, column=i_sha).value or "").strip().lower()
        nhan = nhan_theo_sha.get(h)
        if not nhan:
            continue
        o = ws.cell(row=r, column=cot, value=nhan)
        o.font = Font(name=FONT, size=10)
        o.alignment = Alignment(vertical="top")
        ben_canh = ws.cell(row=r, column=cot - 1 if cot > 1 else cot + 1)
        try:
            o.fill = _copy.copy(ben_canh.fill)
        except Exception:
            pass
        dem += 1

    ban_sao = os.path.join(thu_muc, "_ban_cu")
    os.makedirs(ban_sao, exist_ok=True)
    shutil.copy2(dd, os.path.join(
        ban_sao, "Ket_qua_VirusTotal_%s.xlsx"
        % datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")))
    try:
        wb.save(dd)
    except PermissionError:
        print("  KHONG ghi duoc cot %s: %s dang mo trong Excel. Dong file roi chay "
              "lai lenh nay, phan nhan da luu khong mat." % (COT_NHAN_VT, TEN_FILE_EXCEL_VT))
        return 0
    except Exception as e:
        print("  khong ghi duoc cot %s: %s" % (COT_NHAN_VT, e))
        return 0
    return dem


# ------------------------------------------------------ dung lai bang ket qua

def tinh_lai(thu_muc_kq, model, thu_muc_json):
    """Dung lai Ket_qua_GanNhan.xlsx tu chinh cac dong da co, khong goi API.

    Nhan cuoi khong doi (van la nguong 1 engine nhu quy uoc bai bao), viec duy nhat
    can lam la ghi lai file theo bo cot moi: bo hai cot doi chieu nguong 4 va bo
    phan to vang. Dong nao trong Excel cu cung duoc giu nguyen noi dung.
    """
    dd = duong_dan_excel(thu_muc_kq)
    cu = doc_excel(thu_muc_kq)
    if not cu:
        raise SystemExit("Chua co %s trong %s de tinh lai." % (TEN_FILE_EXCEL, thu_muc_kq))
    print("Doc %d dong tu %s" % (len(cu), dd))

    # Lay ten model tu chinh cac dong da co, dung de ghi lai chu thich cho khop;
    # neu bang chua ghi model nao thi moi dung gia tri truyen vao.
    dem_model = {}
    for d in cu:
        t = str(d.get("Model", "") or "").strip()
        if t:
            dem_model[t] = dem_model.get(t, 0) + 1
    if dem_model:
        model = max(dem_model.items(), key=lambda kv: kv[1])[0]
        print("Model da dung de gan nhan: %s" % ", ".join(
            "%s (%d mau)" % (t, n) for t, n in sorted(dem_model.items(), key=lambda kv: -kv[1])))

    ban_sao = os.path.join(thu_muc_kq, "_ban_cu")
    os.makedirs(ban_sao, exist_ok=True)
    shutil.copy2(dd, os.path.join(
        ban_sao, "Ket_qua_GanNhan_%s.xlsx"
        % datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")))

    wb = Workbook()
    _ke_bang(wb.active, cu)
    wb.active.title = S_KQ
    _ke_tong_hop(wb.create_sheet(S_TH), cu, model, thu_muc_json)
    wb.save(dd)

    dem = {}
    for d in cu:
        t = str(d.get("Nhan_bai_bao", "")) or "(trong)"
        dem[t] = dem.get(t, 0) + 1
    print("\n--- Tinh lai xong ---")
    print("  Bang chi con mot cot nhan duy nhat: Nhan_bai_bao (nguong 1 engine).")
    print("  Phan bo nhan cuoi:")
    for t, n in sorted(dem.items(), key=lambda kv: -kv[1]):
        print("    %-20s %6d" % (t, n))
    print("  Tong cong: %d dong" % len(cu))
    print("\nFile ket qua: %s" % dd)
    print("Ban Excel cu da chep vao: %s" % ban_sao)
    return 0


# ---------------------------------------------------------------------- main

def main():
    tham_so = doc_tham_so()
    thu_muc_script = os.path.dirname(os.path.abspath(__file__))
    thu_muc_kq = tham_so.ket_qua or thu_muc_script
    os.makedirs(thu_muc_kq, exist_ok=True)
    thu_muc_json = tham_so.thu_muc_json or os.path.join(thu_muc_script, "phan_hoi_json")
    thu_muc_bc = os.path.join(thu_muc_kq, "phan_hoi_gemini")
    thu_muc_lo = os.path.join(thu_muc_bc, "_lo")
    os.makedirs(thu_muc_lo, exist_ok=True)

    # Dung lai bang ket qua theo bo cot moi: khong can API key, khong ton quota.
    if tham_so.tinh_lai:
        return tinh_lai(thu_muc_kq, tham_so.model, thu_muc_json)

    print("Dang doc ket qua VirusTotal trong %s ..." % thu_muc_json)
    thong_tin_vt = doc_excel_vt(thu_muc_kq)
    mau = liet_ke_mau(thu_muc_json, thong_tin_vt)
    print("  doc duoc %d mau co ket qua VirusTotal" % len(mau))
    if not mau:
        print("Khong co mau nao de gan nhan.")
        return 0

    lanh = [m for m in mau if m["doc_hai"] < 1]
    can_hoi = [m for m in mau if m["doc_hai"] >= 1]
    print("  %d mau 0 engine bao doc  -> Benign theo quy tac, khong ton luot goi API"
          % len(lanh))
    print("  %d mau co engine bao doc -> can Gemini xep nhom" % len(can_hoi))

    da_co = {}
    for d in doc_excel(thu_muc_kq):
        h = str(d.get("SHA-256", "")).strip().lower()
        if h:
            da_co[h] = d
    xong = {h for h, d in da_co.items()
            if str(d.get("Trang_thai", "")).strip() == TT_XONG}

    dong_moi = []

    def ghi_nguoc_vt():
        """Day nhan cuoi sang cot Nhan_Gemini cua bang VirusTotal."""
        if tham_so.khong_ghi_vt:
            return
        nhan = {str(d["SHA-256"]).lower(): d["Nhan_bai_bao"] for d in dong_moi
                if str(d.get("Trang_thai", "")).strip() == TT_XONG
                and d.get("Nhan_bai_bao")}
        n = cap_nhat_excel_vt(thu_muc_kq, nhan)
        if n:
            print("  da ghi cot %s cho %d dong trong %s"
                  % (COT_NHAN_VT, n, TEN_FILE_EXCEL_VT))

    if not tham_so.gan_lai:
        lanh = [m for m in lanh if m["sha256"] not in xong]
        can_hoi = [m for m in can_hoi if m["sha256"] not in xong]
    print("  da gan nhan tu truoc: %d mau" % len(xong))

    # Mau lanh tinh xu ly ngay, khong can API.
    for m in lanh:
        dong_moi.append(dong_ket_qua(
            m, "", NGUON_QUY_TAC, tham_so.model, do_tin_cay=1.0,
            ly_do="Không engine nào trên VirusTotal báo độc hại."))
    if lanh:
        print("  da gan Benign cho %d mau bang quy tac" % len(lanh))

    if tham_so.gioi_han:
        can_hoi = can_hoi[:tham_so.gioi_han]

    if not can_hoi:
        if dong_moi:
            tong_dong = ghi_them(thu_muc_kq, dong_moi,
                                 datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
                                 tham_so.model, thu_muc_json)
            ghi_nguoc_vt()
            print("\nDa ghi %d dong vao %s" % (tong_dong, duong_dan_excel(thu_muc_kq)))
        else:
            print("Khong con mau nao can gan nhan. Ket qua nam trong %s"
                  % duong_dan_excel(thu_muc_kq))
        return 0

    kich_thuoc_lo = max(1, tham_so.lo)
    cac_lo = [can_hoi[i:i + kich_thuoc_lo]
              for i in range(0, len(can_hoi), kich_thuoc_lo)]

    if tham_so.thu:
        prompt = dung_prompt(cac_lo[0], tham_so.so_engine, tham_so.uu_tien)
        print("\n--- Prompt cua lo dau tien (%d mau) ---\n" % len(cac_lo[0]))
        print(prompt)
        # Uoc luong tho: tieng Viet khong dau va ten ho ma doc roi vao khoang
        # 3,5 ky tu moi token. Chi de biet co cham tran TPM hay khong.
        token = int(len(prompt) / 3.5)
        print("\n--- Uoc luong ---")
        print("  Do dai prompt:        %d ky tu, khoang %d token dau vao" % (len(prompt), token))
        print("  Tran token dau ra:    %d" % min(65536, 512 + 120 * len(cac_lo[0])))
        print("  So luot goi can:      %d lo cho %d mau" % (len(cac_lo), len(can_hoi)))
        print("  Han muc TPM cua free tier la 250.000 token/phut, con xa.")
        print("\n--- Het. Khong goi API vi dang chay --thu. ---")
        return 0

    key = lay_key(tham_so, thu_muc_script)
    if not key:
        raise SystemExit(
            "Chua co API key Gemini. Mo file api_key_gemini.txt trong thu muc nay va "
            "dan key vao dong dau tien, hoac chay lai kem --key <key>.\n"
            "Lay key mien phi tai https://aistudio.google.com/apikey")

    da_dung = doc_quota(thu_muc_kq, tham_so.model)
    con_lai_ngay = max(0, tham_so.gioi_han_ngay - da_dung)
    print("  quota hom nay cua %s: da dung %d/%d luot goi, con %d luot"
          % (tham_so.model, da_dung, tham_so.gioi_han_ngay, con_lai_ngay))
    if con_lai_ngay == 0:
        print("Da cham tran so luot trong ngay cua model nay.")
        print("Han muc ngay dat lai theo gio Thai Binh Duong, tuc khoang 14-15h gio Viet Nam.")
        print("Muon lam tiep ngay bay gio thi doi model, vi dan moi model co bo dem rieng:")
        print("    python gan_nhan_gemini.py --model gemini-2.5-flash-lite")
        if dong_moi:
            ghi_them(thu_muc_kq, dong_moi,
                     datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
                     tham_so.model, thu_muc_json)
            ghi_nguoc_vt()
        return 0

    if len(cac_lo) > con_lai_ngay:
        phu = con_lai_ngay * kich_thuoc_lo
        print("  con %d luot goi x %d mau/lo = %d mau phu duoc trong hom nay, "
              "thieu %d mau." % (con_lai_ngay, kich_thuoc_lo, phu, len(can_hoi) - phu))
        print("  Muon phu het trong mot ngay thi tang --lo (vi du --lo %d)."
              % min(150, -(-len(can_hoi) // max(1, con_lai_ngay))))
    cac_lo = cac_lo[:con_lai_ngay]

    nhan_lan_chay = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    so_mau = sum(len(l) for l in cac_lo)
    print("\nBat dau gan nhan %d mau qua %d lan goi API (%d mau/lo), nhip %.0f giay, "
          "uoc tinh %s.\n"
          % (so_mau, len(cac_lo), kich_thuoc_lo, tham_so.nhip,
             str(datetime.timedelta(seconds=int(len(cac_lo) * tham_so.nhip)))))

    dem = {t: 0 for t in NHAN_MA_DOC}
    dem["loi"] = 0
    het_quota = False
    lan_truoc = 0.0

    try:
        for so_lo, lo in enumerate(cac_lo, start=1):
            cho = tham_so.nhip - (time.time() - lan_truoc)
            if lan_truoc and cho > 0:
                time.sleep(cho)
            lan_truoc = time.time()

            prompt = dung_prompt(lo, tham_so.so_engine, tham_so.uu_tien)
            van_ban, loi, ly_do_dung, so_yeu_cau = goi_gemini(
                prompt, key, tham_so.model, tham_so.suy_luan,
                so_mau=len(lo), thu_muc=thu_muc_kq)
            # Moi lan gui len API deu tinh vao han muc ngay, ke ca lan bi tu choi
            # vi cau hinh, nen cong dung so lan da goi chu khong cong 1.
            da_dung += so_yeu_cau
            ghi_quota(thu_muc_kq, tham_so.model, da_dung)

            if loi == "429":
                print("Gemini bao het quota (429). Dung lai o lo %d." % so_lo)
                print("Neu moi chay duoc it lo thi la cham tran so luot/phut - tang --nhip len 15.")
                print("Neu da chay nhieu thi la het luot trong ngay - mai chay lai lenh nay.")
                het_quota = True
                break
            if loi.startswith("401") or loi.startswith("403"):
                print("API key bi tu choi (%s). Kiem tra lai api_key_gemini.txt." % loi[:3])
                het_quota = True
                break

            ket_qua = doc_tra_loi(van_ban, lo) if not loi else {}
            if van_ban:
                with open(os.path.join(
                        thu_muc_lo, "%s_lo%03d.json"
                        % (datetime.datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss"), so_lo)),
                        "w", encoding="utf-8") as f:
                    json.dump({"model": tham_so.model,
                               "thoi_diem": datetime.datetime.now().isoformat(timespec="seconds"),
                               "sha256_trong_lo": [m["sha256"] for m in lo],
                               "tra_loi_tho": van_ban}, f, ensure_ascii=False, indent=1)

            for m in lo:
                kq = ket_qua.get(m["sha256"])
                if kq:
                    d = dong_ket_qua(m, kq["nhan"], NGUON_GEMINI, tham_so.model,
                                     do_tin_cay=kq["do_tin_cay"],
                                     ly_do=kq["ly_do"])
                    dem[kq["nhan"]] = dem.get(kq["nhan"], 0) + 1
                    with open(os.path.join(thu_muc_bc, m["sha256"] + ".json"),
                              "w", encoding="utf-8") as f:
                        json.dump({"sha256": m["sha256"], "model": tham_so.model,
                                   "thoi_diem": datetime.datetime.now().isoformat(timespec="seconds"),
                                   "du_lieu_gui": mo_ta_mau(m, tham_so.so_engine),
                                   "ket_qua": kq}, f, ensure_ascii=False, indent=1)
                else:
                    d = dong_ket_qua(
                        m, "", NGUON_GEMINI, tham_so.model, trang_thai=TT_LOI,
                        ghi_chu="Không lấy được nhãn: %s" % (loi or "model trả về thiếu mẫu này"))
                    dem["loi"] += 1
                dong_moi.append(d)

            if ly_do_dung and ly_do_dung not in ("STOP", "FINISH_REASON_UNSPECIFIED"):
                print("   canh bao: model dung voi finishReason=%s. Neu lap lai nhieu lan "
                      "thi giam --lo." % ly_do_dung)
            xong_lo = sum(1 for m in lo if m["sha256"] in ket_qua)
            print("[lo %d/%d] %d/%d mau co nhan  %s"
                  % (so_lo, len(cac_lo), xong_lo, len(lo),
                     ("  loi: " + loi) if loi else
                     ", ".join("%s %s" % (m["sha256"][:8],
                                          ket_qua.get(m["sha256"], {}).get("nhan", "?"))
                               for m in lo[:3]) + ("..." if len(lo) > 3 else "")))

            if so_lo % 5 == 0:
                ghi_them(thu_muc_kq, dong_moi, nhan_lan_chay,
                         tham_so.model, thu_muc_json)
                ghi_nguoc_vt()
                print("   ... da luu tam %d dong vao Excel" % len(dong_moi))

    except KeyboardInterrupt:
        print("\nDa dung theo yeu cau. Dang luu phan da lam...")

    tong_dong = ghi_them(thu_muc_kq, dong_moi, nhan_lan_chay,
                         tham_so.model, thu_muc_json)
    ghi_nguoc_vt()

    da_xong = set(xong)
    for d in dong_moi:
        if str(d.get("Trang_thai", "")).strip() == TT_XONG:
            da_xong.add(str(d["SHA-256"]).lower())
        else:
            da_xong.discard(str(d["SHA-256"]).lower())
    con = sum(1 for m in mau if m["sha256"] not in da_xong)

    print("\n--- Ket qua lan chay nay ---")
    for t in NHAN_MA_DOC:
        print("  %-18s %d" % (t + ":", dem.get(t, 0)))
    print("  %-18s %d" % ("Benign (quy tac):", len(lanh)))
    print("  %-18s %d" % ("Loi/thieu nhan:", dem["loi"]))
    print("  Quota da dung trong ngay:  %d/%d luot goi"
          % (da_dung, tham_so.gioi_han_ngay))
    print("  Tong so dong trong Excel:  %d" % tong_dong)
    print("  Con lai chua gan nhan:     %d mau" % max(0, con))
    print("\nFile ket qua:   %s" % duong_dan_excel(thu_muc_kq))
    if not tham_so.khong_ghi_vt:
        print("Cot %s da duoc ghi nguoc vao %s"
              % (COT_NHAN_VT, os.path.join(thu_muc_kq, TEN_FILE_EXCEL_VT)))
    print("Ban tra loi goc: %s" % thu_muc_bc)
    if con > 0 and not het_quota:
        print("\nChay lai dung lenh nay de gan tiep phan con lai.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
