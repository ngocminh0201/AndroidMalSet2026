"""Giao diện Tkinter cho bộ trích xuất thuộc tính động APK.

Chạy: python gui.py  (hoặc bấm đúp chay_gui.bat)
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from dataclasses import fields
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

try:
    import yaml
except ImportError:  # Python của máy chưa có PyYAML: tự cài một lần rồi chạy tiếp
    print("Đang cài PyYAML cho", sys.executable, "...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "PyYAML>=6.0,<7.0"])
    import yaml

import main as cli
from adb import ANDROID_SDK, boot_completed, emulator_exe, list_avds, list_devices, run_command, start_emulator
from config import Settings

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "config.yaml"

SAFETY_NOTE = (
    "CẢNH BÁO AN TOÀN: chỉ chạy trên emulator/máy ảo cô lập, không đăng nhập tài khoản thật, "
    "không chứa dữ liệu thật, không kết nối mạng nội bộ. Không chạy APK nghi độc hại trên điện thoại thật."
)

CONFIG_LABELS = {
    "runtime_seconds": "Thời gian quan sát (giây)",
    "sample_interval_seconds": "Chu kỳ lấy mẫu (giây)",
    "monkey_events": "Số sự kiện Monkey",
    "monkey_throttle_ms": "Monkey throttle (ms)",
    "install_timeout_seconds": "Timeout cài đặt (giây)",
    "command_timeout_seconds": "Timeout lệnh adb (giây)",
    "adaptive_stop": "Adaptive stop (chưa dùng)",
    "minimum_runtime_seconds": "Runtime tối thiểu (giây)",
    "idle_seconds_before_stop": "Idle trước khi dừng (giây)",
    "keep_raw": "Lưu dữ liệu thô (raw/)",
}

RESULT_COLUMNS = [
    ("apk_name", "APK", 220),
    ("package_name", "Package", 180),
    ("device_serial", "Thiết bị", 100),
    ("install_success", "Cài", 40),
    ("launch_success", "Mở", 40),
    ("execution_success", "Chạy", 45),
    ("cpu_percent_mean", "CPU% TB", 70),
    ("pss_kb_max", "PSS max (KB)", 90),
    ("rx_bytes_delta", "RX bytes", 80),
    ("tx_bytes_delta", "TX bytes", 80),
    ("crashed", "Crash", 50),
    ("error", "Lỗi", 300),
]


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Trích xuất thuộc tính động APK")
        self.geometry("1100x760")
        self.minsize(900, 600)

        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.total = self.done = self.ok = self.failed = 0
        self.rows: list[dict] = []

        self.apk_dir = tk.StringVar(value=str(HERE / "apks"))
        self.output_dir = tk.StringVar(value=str(HERE / "output"))
        self.test_apk = tk.StringVar()
        self.staging_dir = tk.StringVar(value=str(cli.DEFAULT_STAGING))
        self.use_staging = tk.BooleanVar(value=True)
        self.adb_path = tk.StringVar(value=shutil.which("adb") or "adb")
        self.resume = tk.BooleanVar(value=True)
        self.apk_count = tk.StringVar()
        self.status = tk.StringVar(value="Sẵn sàng")
        self.only_failed = tk.BooleanVar(value=False)
        self.avd = tk.StringVar()
        self.clean_emulator = tk.BooleanVar(value=True)
        self.config_vars: dict[str, tk.Variable] = {}

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=6, pady=6)
        self.run_tab = ttk.Frame(notebook, padding=8)
        self.result_tab = ttk.Frame(notebook, padding=8)
        notebook.add(self.run_tab, text="Chạy phân tích")
        notebook.add(self.result_tab, text="Kết quả")
        self.notebook = notebook

        self._build_run_tab()
        self._build_result_tab()
        self._load_config()
        self._count_apks()
        self.apk_dir.trace_add("write", lambda *_: self._count_apks())
        self.log(SAFETY_NOTE)
        if ANDROID_SDK:
            self.log(f"Android SDK: {ANDROID_SDK} (đã tự thêm adb, aapt, emulator vào PATH của chương trình)")
        else:
            self.log("KHÔNG tìm thấy Android SDK. Cài Android Studio + SDK Platform-Tools, hoặc đặt biến ANDROID_HOME.")
        self.after(100, self.refresh_devices)
        self.after(150, self.refresh_avds)
        self.after(200, self._poll_events)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ UI
    def _path_row(self, parent: ttk.Frame, row: int, label: str, var: tk.StringVar, kind: str) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=2)
        entry = ttk.Entry(parent, textvariable=var)
        entry.grid(row=row, column=1, sticky="ew", padx=4, pady=2)
        ttk.Button(parent, text="Chọn…", command=lambda: self._browse(var, kind)).grid(row=row, column=2, pady=2)
        self.lockable.append(entry)

    def _build_run_tab(self) -> None:
        self.lockable: list[tk.Widget] = []
        top = ttk.Frame(self.run_tab)
        top.pack(fill="x")
        top.columnconfigure(0, weight=3)
        top.columnconfigure(1, weight=1)

        paths = ttk.LabelFrame(top, text="Đường dẫn", padding=6)
        paths.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        paths.columnconfigure(1, weight=1)
        self._path_row(paths, 0, "Thư mục APK", self.apk_dir, "dir")
        ttk.Label(paths, textvariable=self.apk_count, foreground="gray").grid(row=1, column=1, sticky="w", padx=4)
        self._path_row(paths, 2, "Thư mục output", self.output_dir, "dir")
        self._path_row(paths, 3, "APK chạy thử (tùy chọn)", self.test_apk, "apk")
        self._path_row(paths, 4, "Đường dẫn adb", self.adb_path, "exe")
        self._path_row(paths, 5, "Thư mục tạm (ổ trong máy)", self.staging_dir, "dir")
        staging = ttk.Checkbutton(
            paths, variable=self.use_staging,
            text="Chép từng APK sang thư mục tạm rồi mới cài (đọc ổ ngoài đúng 1 lần/APK, xong thì xóa bản chép)",
        )
        staging.grid(row=6, column=1, sticky="w", padx=4)
        self.lockable.append(staging)
        tools = ttk.Frame(paths)
        tools.grid(row=7, column=1, sticky="w", padx=4, pady=(4, 0))
        ttk.Button(tools, text="Kiểm tra môi trường", command=self.check_env).pack(side="left")
        ttk.Button(tools, text="Xóa APK chạy thử", command=lambda: self.test_apk.set("")).pack(side="left", padx=4)

        dev = ttk.LabelFrame(top, text="Emulator (chọn để chạy song song)", padding=6)
        dev.grid(row=0, column=1, sticky="nsew")
        self.device_list = tk.Listbox(dev, selectmode="multiple", height=6, exportselection=False)
        self.device_list.pack(fill="both", expand=True)
        ttk.Button(dev, text="Làm mới", command=self.refresh_devices).pack(fill="x", pady=(4, 0))
        launch = ttk.Frame(dev)
        launch.pack(fill="x", pady=(6, 0))
        self.avd_box = ttk.Combobox(launch, textvariable=self.avd, state="readonly", width=18)
        self.avd_box.pack(side="left", fill="x", expand=True)
        self.launch_btn = ttk.Button(launch, text="Bật emulator", command=self.launch_emulator)
        self.launch_btn.pack(side="left", padx=(4, 0))
        ttk.Checkbutton(dev, text="Không lưu trạng thái khi tắt (giữ máy ảo sạch)", variable=self.clean_emulator).pack(anchor="w")

        cfg = ttk.LabelFrame(self.run_tab, text="Cấu hình (config.yaml)", padding=6)
        cfg.pack(fill="x", pady=6)
        for index, item in enumerate(fields(Settings)):
            r, c = divmod(index, 3)
            ttk.Label(cfg, text=CONFIG_LABELS.get(item.name, item.name)).grid(row=r, column=c * 2, sticky="w", padx=(8, 2), pady=2)
            if item.type in (bool, "bool"):
                var: tk.Variable = tk.BooleanVar()
                widget = ttk.Checkbutton(cfg, variable=var)
            else:
                var = tk.StringVar()
                widget = ttk.Entry(cfg, textvariable=var, width=10)
            widget.grid(row=r, column=c * 2 + 1, sticky="w", pady=2)
            self.config_vars[item.name] = var
            self.lockable.append(widget)
        buttons = ttk.Frame(cfg)
        buttons.grid(row=(len(fields(Settings)) + 2) // 3, column=0, columnspan=6, sticky="w", pady=(6, 0))
        ttk.Button(buttons, text="Lưu config.yaml", command=self.save_config).pack(side="left", padx=(8, 4))
        ttk.Button(buttons, text="Nạp lại", command=self._load_config).pack(side="left")
        resume = ttk.Checkbutton(buttons, text="Resume (bỏ qua APK đã chạy thành công)", variable=self.resume)
        resume.pack(side="left", padx=16)
        self.lockable.append(resume)

        control = ttk.Frame(self.run_tab)
        control.pack(fill="x")
        self.start_btn = ttk.Button(control, text="▶ Bắt đầu", command=self.start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(control, text="■ Dừng", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=4)
        ttk.Button(control, text="Mở thư mục output", command=self.open_output).pack(side="left", padx=4)
        ttk.Label(control, textvariable=self.status).pack(side="left", padx=12)
        self.progress = ttk.Progressbar(self.run_tab, mode="determinate")
        self.progress.pack(fill="x", pady=4)

        self.log_box = ScrolledText(self.run_tab, height=12, state="disabled", font=("Consolas", 9))
        self.log_box.pack(fill="both", expand=True)

    def _build_result_tab(self) -> None:
        bar = ttk.Frame(self.result_tab)
        bar.pack(fill="x")
        ttk.Button(bar, text="Tải lại", command=self.load_results).pack(side="left")
        ttk.Checkbutton(bar, text="Chỉ hiện mẫu lỗi", variable=self.only_failed, command=self._fill_results).pack(side="left", padx=8)
        ttk.Button(bar, text="Mở dynamic_features.csv", command=self.open_csv).pack(side="left", padx=4)
        ttk.Button(bar, text="Mở thư mục output", command=self.open_output).pack(side="left", padx=4)
        self.result_info = tk.StringVar()
        ttk.Label(bar, textvariable=self.result_info).pack(side="left", padx=12)
        ttk.Label(self.result_tab, text="Nhấp đúp vào một dòng để xem toàn bộ thuộc tính và logcat.", foreground="gray").pack(anchor="w", pady=(4, 2))

        frame = ttk.Frame(self.result_tab)
        frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(frame, columns=[c[0] for c in RESULT_COLUMNS], show="headings")
        for key, title, width in RESULT_COLUMNS:
            self.tree.heading(key, text=title, command=lambda k=key: self._sort_by(k))
            self.tree.column(key, width=width, anchor="w" if key in ("apk_name", "package_name", "error", "device_serial") else "center")
        self.tree.tag_configure("failed", foreground="#c62828")
        ys = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        xs = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.tree.bind("<Double-1>", self._open_detail)
        self._sort_state: tuple[str, bool] | None = None

    # ------------------------------------------------------------- helpers
    def log(self, message: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", message + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _browse(self, var: tk.StringVar, kind: str) -> None:
        current = var.get()
        if kind == "dir":
            path = filedialog.askdirectory(initialdir=current or str(HERE))
        elif kind == "apk":
            path = filedialog.askopenfilename(initialdir=self.apk_dir.get(), filetypes=[("APK", "*.apk"), ("Tất cả", "*.*")])
        else:
            path = filedialog.askopenfilename(filetypes=[("Chương trình", "*.exe"), ("Tất cả", "*.*")])
        if path:
            var.set(str(Path(path)))

    def _count_apks(self) -> None:
        folder = Path(self.apk_dir.get())
        if folder.is_dir():
            self.apk_count.set(f"Tìm thấy {sum(1 for _ in folder.rglob('*.apk'))} file .apk")
        else:
            self.apk_count.set("Thư mục không tồn tại")

    def _load_config(self) -> None:
        try:
            settings = Settings.load(CONFIG_PATH if CONFIG_PATH.exists() else None)
        except Exception as exc:
            messagebox.showerror("Lỗi config", str(exc))
            settings = Settings()
        for name, var in self.config_vars.items():
            var.set(getattr(settings, name))

    def _settings_from_form(self) -> Settings:
        values = {}
        for item in fields(Settings):
            var = self.config_vars[item.name]
            default = getattr(Settings(), item.name)
            if isinstance(default, bool):
                values[item.name] = bool(var.get())
                continue
            text = str(var.get()).strip()
            try:
                values[item.name] = type(default)(float(text)) if isinstance(default, int) else float(text)
            except ValueError:
                raise ValueError(f"Giá trị không hợp lệ cho '{CONFIG_LABELS.get(item.name, item.name)}': {text!r}")
        return Settings(**values)

    def save_config(self) -> None:
        try:
            settings = self._settings_from_form()
        except ValueError as exc:
            messagebox.showerror("Lỗi", str(exc))
            return
        CONFIG_PATH.write_text(yaml.safe_dump(dict(settings.__dict__), sort_keys=False, allow_unicode=True), encoding="utf-8")
        self.log(f"Đã lưu {CONFIG_PATH}")

    def refresh_devices(self) -> None:
        adb_path = self.adb_path.get()

        def task() -> None:
            try:
                self.events.put(("devices", list_devices(adb_path)))
            except Exception as exc:
                self.events.put(("log", f"Không lấy được danh sách thiết bị: {exc}"))
                self.events.put(("devices", []))

        threading.Thread(target=task, daemon=True).start()

    def check_env(self) -> None:
        adb_path = self.adb_path.get()

        def task() -> None:
            self.events.put(("log", "--- Kiểm tra môi trường ---"))
            try:
                self.events.put(("log", f"{'✓' if ANDROID_SDK else '✗'} Android SDK: {ANDROID_SDK or 'không tìm thấy'}"))
                result = run_command([adb_path, "version"], timeout=15)
                first = result.stdout.strip().splitlines()[0] if result.returncode == 0 and result.stdout.strip() else result.stderr.strip()
                self.events.put(("log", f"{'✓' if result.returncode == 0 else '✗'} adb ({adb_path}): {first or 'không chạy được'}"))
                aapt = shutil.which("aapt")
                apkanalyzer = shutil.which("apkanalyzer")
                self.events.put(("log", f"{'✓' if aapt else '✗'} aapt: {aapt or 'không tìm thấy'}"))
                if apkanalyzer:
                    self.events.put(("log", f"✓ apkanalyzer: {apkanalyzer}"))
                if not (aapt or apkanalyzer):
                    self.events.put(("log", "  → Cài 'Android SDK Build-Tools' trong Android Studio (SDK Manager) để xác định package name."))
                emu = emulator_exe()
                self.events.put(("log", f"{'✓' if emu else '✗'} emulator: {emu or 'không tìm thấy'}"))
                avds = list_avds()
                self.events.put(("log", f"{'✓' if avds else '✗'} AVD đã tạo: {', '.join(avds) or 'chưa có (tạo trong Device Manager của Android Studio)'}"))
                if result.returncode == 0:
                    devices = list_devices(adb_path)
                    self.events.put(("log", f"{'✓' if devices else '✗'} Thiết bị đang online: {', '.join(devices) or 'chưa có — chọn AVD rồi bấm Bật emulator'}"))
            except Exception as exc:
                self.events.put(("log", f"✗ Lỗi khi kiểm tra: {type(exc).__name__}: {exc}"))

        threading.Thread(target=task, daemon=True).start()

    def refresh_avds(self) -> None:
        def task() -> None:
            try:
                self.events.put(("avds", list_avds()))
            except Exception as exc:
                self.events.put(("log", f"Không đọc được danh sách AVD: {exc}"))

        threading.Thread(target=task, daemon=True).start()

    def launch_emulator(self) -> None:
        avd = self.avd.get()
        if not avd:
            messagebox.showinfo("Thông báo", "Chưa có AVD. Hãy tạo một máy ảo trong Device Manager của Android Studio.")
            return
        adb_path = self.adb_path.get()
        clean = self.clean_emulator.get()
        self.launch_btn.configure(state="disabled")

        def task() -> None:
            try:
                before = set(list_devices(adb_path))
                proc = start_emulator(avd, clean=clean)
                self.events.put(("log", f"Đang khởi động {avd}... (lần đầu có thể mất 1–3 phút)"))
                deadline = time.monotonic() + 300
                while time.monotonic() < deadline:
                    time.sleep(3)
                    if proc.poll() is not None:
                        self.events.put(("log", f"Emulator {avd} đã thoát (mã {proc.returncode}). "
                                                "Có thể AVD này đang chạy rồi, hoặc thiếu ảo hóa (bật Windows Hypervisor Platform/BIOS VT-x)."))
                        break
                    try:
                        devices = list_devices(adb_path)
                    except Exception:
                        continue
                    new = [s for s in devices if s.startswith("emulator-") and s not in before]
                    if any(boot_completed(adb_path, s) for s in new):
                        self.events.put(("log", f"Emulator {avd} đã sẵn sàng: {', '.join(new)}"))
                        self.events.put(("devices", devices))
                        break
                else:
                    self.events.put(("log", "Quá 5 phút emulator chưa boot xong. Bấm 'Làm mới' khi màn hình chính hiện ra."))
            except Exception as exc:
                self.events.put(("log", f"Không bật được emulator: {exc}"))
            finally:
                self.events.put(("launch_done", None))

        threading.Thread(target=task, daemon=True).start()

    def open_output(self) -> None:
        path = Path(self.output_dir.get())
        if path.is_dir():
            os.startfile(path)
        else:
            messagebox.showinfo("Thông báo", "Thư mục output chưa tồn tại.")

    def open_csv(self) -> None:
        path = Path(self.output_dir.get()) / "dynamic_features.csv"
        if path.is_file():
            os.startfile(path)
        else:
            messagebox.showinfo("Thông báo", f"Chưa có {path.name}.")

    def _set_running(self, running: bool) -> None:
        self.start_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")
        for widget in self.lockable:
            widget.configure(state="disabled" if running else "normal")

    def _update_status(self) -> None:
        self.progress.configure(maximum=max(self.total, 1), value=self.done)
        self.status.set(f"Đã xử lý {self.done}/{self.total} — OK {self.ok} — Lỗi {self.failed}")

    # ------------------------------------------------------------- run
    def start(self) -> None:
        try:
            settings = self._settings_from_form()
        except ValueError as exc:
            messagebox.showerror("Lỗi", str(exc))
            return
        apk_dir = Path(self.apk_dir.get())
        test_apk = Path(self.test_apk.get()) if self.test_apk.get().strip() else None
        if test_apk and not test_apk.is_file():
            messagebox.showerror("Lỗi", "File APK chạy thử không tồn tại.")
            return
        if not test_apk and not apk_dir.is_dir():
            messagebox.showerror("Lỗi", "Thư mục APK không tồn tại.")
            return
        if not self.output_dir.get().strip():
            messagebox.showerror("Lỗi", "Chưa chọn thư mục output.")
            return
        serials = [self.device_list.get(i) for i in self.device_list.curselection()]
        if not serials:
            messagebox.showerror("Lỗi", "Hãy chọn ít nhất một emulator (bấm 'Làm mới' nếu danh sách trống).")
            return
        args = argparse.Namespace(
            apk_dir=apk_dir, output=Path(self.output_dir.get()), adb=self.adb_path.get(),
            workers=len(serials), serials=",".join(serials), resume=self.resume.get(), test_apk=test_apk,
            staging_dir=Path(self.staging_dir.get()) if self.staging_dir.get().strip() else cli.DEFAULT_STAGING,
            no_staging=not self.use_staging.get(),
        )
        self.total = self.done = self.ok = self.failed = 0
        self._update_status()
        self.stop_event.clear()
        self._set_running(True)
        self.log(f"=== Bắt đầu: runtime={settings.runtime_seconds}s, thiết bị={', '.join(serials)} ===")

        def task() -> None:
            try:
                cli.run(
                    args, settings,
                    log=lambda m: self.events.put(("log", m)),
                    on_result=lambda row: self.events.put(("result", row)),
                    on_total=lambda n: self.events.put(("total", n)),
                    stop_event=self.stop_event,
                )
            except BaseException as exc:  # SystemExit from run() when no device
                self.events.put(("log", f"LỖI: {exc}"))
            finally:
                self.events.put(("finished", None))

        self.worker = threading.Thread(target=task, daemon=True)
        self.worker.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.stop_btn.configure(state="disabled")
        self.log("Đang dừng... APK đang chạy sẽ hoàn tất và gỡ cài đặt trước khi dừng.")

    def _poll_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self.log(str(payload))
                elif kind == "total":
                    self.total = int(payload)
                    self._update_status()
                elif kind == "result":
                    self.done += 1
                    if payload.get("execution_success"):
                        self.ok += 1
                    else:
                        self.failed += 1
                    self._update_status()
                elif kind == "devices":
                    self._fill_devices(payload)
                elif kind == "avds":
                    self.avd_box.configure(values=payload)
                    if payload and self.avd.get() not in payload:
                        self.avd.set(payload[0])
                elif kind == "launch_done":
                    self.launch_btn.configure(state="normal")
                elif kind == "finished":
                    self._set_running(False)
                    self.status.set(self.status.get() + " — Hoàn tất")
                    self.load_results()
        except queue.Empty:
            pass
        self.after(200, self._poll_events)

    def _fill_devices(self, devices: list[str]) -> None:
        selected = {self.device_list.get(i) for i in self.device_list.curselection()}
        self.device_list.delete(0, "end")
        for serial in devices:
            self.device_list.insert("end", serial)
        for index, serial in enumerate(devices):
            if serial in selected or (not selected and serial.startswith("emulator-")):
                self.device_list.selection_set(index)
        if not devices:
            self.log("Không tìm thấy thiết bị online. Hãy khởi động emulator rồi bấm 'Làm mới'.")

    def _on_close(self) -> None:
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno("Thoát", "Đang chạy phân tích. Thoát ngay có thể để lại app chưa gỡ trên emulator. Vẫn thoát?"):
                return
            self.stop_event.set()
        self.destroy()

    # ------------------------------------------------------------- results
    def load_results(self) -> None:
        path = Path(self.output_dir.get()) / "processed.jsonl"
        self.rows = cli.read_latest_rows(path) if path.is_file() else []
        self._fill_results()

    def _fill_results(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for index, row in enumerate(self.rows):
            if self.only_failed.get() and row.get("execution_success"):
                continue
            values = [str(row.get(key, "")).replace("\n", " ") for key, _, _ in RESULT_COLUMNS]
            self.tree.insert("", "end", iid=str(index), values=values, tags=() if row.get("execution_success") else ("failed",))
        ok = sum(1 for r in self.rows if r.get("execution_success"))
        self.result_info.set(f"Tổng {len(self.rows)} mẫu — thành công {ok} — lỗi {len(self.rows) - ok}")

    def _sort_by(self, key: str) -> None:
        reverse = self._sort_state == (key, False)
        self._sort_state = (key, reverse)

        def sort_key(iid: str):
            value = self.tree.set(iid, key)
            try:
                return (0, float(value), "")
            except ValueError:
                return (1, 0.0, value.lower())

        for pos, iid in enumerate(sorted(self.tree.get_children(), key=sort_key, reverse=reverse)):
            self.tree.move(iid, "", pos)

    def _open_detail(self, _event: object) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        row = self.rows[int(selection[0])]
        raw_dir = Path(self.output_dir.get()) / "raw" / str(row.get("sha256", ""))
        features_file = raw_dir / "features.json"
        data = row
        if features_file.is_file():
            try:
                data = json.loads(features_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass

        win = tk.Toplevel(self)
        win.title(f"Chi tiết — {row.get('apk_name', '')}")
        win.geometry("700x600")
        bar = ttk.Frame(win, padding=6)
        bar.pack(fill="x")
        ttk.Button(bar, text="Xem logcat", command=lambda: self._open_logcat(raw_dir / "logcat.txt")).pack(side="left")
        ttk.Button(bar, text="Mở thư mục raw", command=lambda: os.startfile(raw_dir) if raw_dir.is_dir() else None).pack(side="left", padx=4)
        tree = ttk.Treeview(win, columns=("key", "value"), show="headings")
        tree.heading("key", text="Thuộc tính")
        tree.heading("value", text="Giá trị")
        tree.column("key", width=220)
        tree.column("value", width=460)
        scroll = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=(0, 6))
        scroll.pack(side="left", fill="y", pady=(0, 6))
        for key in sorted(data):
            tree.insert("", "end", values=(key, str(data[key]).replace("\n", " ")))

    def _open_logcat(self, path: Path) -> None:
        if not path.is_file():
            messagebox.showinfo("Thông báo", "Không có logcat.txt cho mẫu này (keep_raw tắt hoặc chưa chạy).")
            return
        win = tk.Toplevel(self)
        win.title(f"Logcat — {path.parent.name[:16]}…")
        win.geometry("1000x650")
        bar = ttk.Frame(win, padding=6)
        bar.pack(fill="x")
        query = tk.StringVar()
        ttk.Label(bar, text="Tìm:").pack(side="left")
        entry = ttk.Entry(bar, textvariable=query, width=40)
        entry.pack(side="left", padx=4)
        info = tk.StringVar()
        text = ScrolledText(win, font=("Consolas", 9), wrap="none")
        text.pack(fill="both", expand=True)
        text.insert("1.0", path.read_text(encoding="utf-8", errors="replace"))
        text.tag_configure("hit", background="#fff59d")
        text.tag_configure("error", foreground="#c62828")
        start = "1.0"
        while True:
            pos = text.search(" E ", start, stopindex="end")
            if not pos:
                break
            text.tag_add("error", f"{pos} linestart", f"{pos} lineend")
            start = f"{pos} lineend"
        text.configure(state="disabled")

        def find(*_: object) -> None:
            text.tag_remove("hit", "1.0", "end")
            needle = query.get()
            if not needle:
                info.set("")
                return
            count, first, start = 0, None, "1.0"
            while True:
                pos = text.search(needle, start, stopindex="end", nocase=True)
                if not pos:
                    break
                end = f"{pos}+{len(needle)}c"
                text.tag_add("hit", pos, end)
                first = first or pos
                count += 1
                start = end
            if first:
                text.see(first)
            info.set(f"{count} kết quả")

        entry.bind("<Return>", find)
        ttk.Button(bar, text="Tìm", command=find).pack(side="left")
        ttk.Label(bar, textvariable=info).pack(side="left", padx=8)


if __name__ == "__main__":
    App().mainloop()
