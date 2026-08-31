#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Standalone Windows GUI for 秒杀小哈.

The GUI is intentionally a thin process wrapper around the stable CLI.  This
keeps the scanner, safety checks, execution reports, exit codes and toolbox
integration on one implementation path.
"""

from __future__ import print_function

import datetime
import os
import queue
import re
import subprocess
import sys
import threading
import uuid
from pathlib import Path

import xiaoha_cleaner as core


APP_NAME = "秒杀小哈"
CREATE_NO_WINDOW = 0x08000000
BASE_DPI = 96.0
REPORT_PATTERNS = {
    "scan": re.compile(r"(?im)^JSON report:\s*(.+?)\s*$"),
    "clean": re.compile(r"(?im)^Quarantine/report:\s*(.+?)\s*$"),
    "restore": re.compile(r"(?im)^Restore report:\s*(.+?)\s*$"),
}


def enable_high_dpi_awareness():
    """Enable crisp per-monitor rendering before the first Tk window exists."""
    if os.name != "nt":
        return "not-windows"
    try:
        import ctypes
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        setter = user32.SetProcessDpiAwarenessContext
        setter.argtypes = [ctypes.c_void_p]
        setter.restype = ctypes.c_bool
        if setter(ctypes.c_void_p(-4)):
            return "per-monitor-v2"
        if ctypes.get_last_error() == 5:
            return "manifest-or-existing"
    except (AttributeError, OSError):
        pass
    try:
        import ctypes
        shcore = ctypes.WinDLL("shcore")
        setter = shcore.SetProcessDpiAwareness
        setter.argtypes = [ctypes.c_int]
        setter.restype = ctypes.c_long
        result = int(setter(2))
        if result == 0:
            return "per-monitor"
        if result in (-2147024891, 0x80070005):
            return "manifest-or-existing"
    except (AttributeError, OSError):
        pass
    try:
        import ctypes
        if ctypes.windll.user32.SetProcessDPIAware():
            return "system"
    except (AttributeError, OSError):
        pass
    return "unavailable"


def tk_scaling_for_dpi(dpi):
    return max(0.75, min(4.0, float(dpi) / 72.0))


def logical_pixels(value, dpi):
    return max(1, int(round(float(value) * float(dpi) / BASE_DPI)))


def window_dpi(root):
    if os.name == "nt":
        try:
            import ctypes
            user32 = ctypes.WinDLL("user32")
            getter = user32.GetDpiForWindow
            getter.argtypes = [ctypes.c_void_p]
            getter.restype = ctypes.c_uint
            dpi = int(getter(ctypes.c_void_p(root.winfo_id())))
            if dpi > 0:
                return dpi
        except (AttributeError, OSError):
            pass
    try:
        dpi = int(round(float(root.winfo_fpixels("1i"))))
        if dpi > 0:
            return dpi
    except Exception:
        pass
    return int(BASE_DPI)


def application_directory():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).absolute().parent
    return Path(__file__).absolute().parent


def report_root(environ=None):
    values = os.environ if environ is None else environ
    local_app_data = str(values.get("LOCALAPPDATA", "")).strip()
    if local_app_data:
        base = Path(local_app_data)
    else:
        base = Path.home() / "AppData" / "Local"
    return base / "XiaohaCleaner" / "reports"


def unique_output_directory(prefix, base=None, now=None, token=None):
    timestamp = (now or datetime.datetime.now()).strftime("%Y%m%d-%H%M%S-%f")[:-3]
    suffix = token or uuid.uuid4().hex[:8]
    return Path(base or report_root()) / "{}-{}-{}".format(prefix, timestamp, suffix)


def cli_command(arguments, executable=None, frozen=None, launcher_path=None):
    """Build the same-process CLI command for source and PyInstaller modes."""
    is_frozen = getattr(sys, "frozen", False) if frozen is None else bool(frozen)
    python_or_exe = str(executable or sys.executable)
    if is_frozen:
        return [python_or_exe] + list(arguments)
    launcher = Path(launcher_path or (Path(__file__).absolute().parent / "xiaoha-cleaner.py"))
    return [python_or_exe, str(launcher)] + list(arguments)


def target_validation_error(value, app_dir=None):
    text = str(value or "").strip()
    if not text:
        return "请选择 FiveM server-data、resources 或单个资源目录。"
    try:
        target = Path(text).absolute()
    except Exception as exc:
        return "目标目录无效：{}".format(exc)
    if not target.is_dir():
        return "目标目录不存在：{}".format(target)
    anchor = Path(target.anchor).absolute() if target.anchor else None
    if anchor and target == anchor:
        return "不能扫描整个磁盘，请选择 server-data、resources 或单个资源目录。"
    own_dir = Path(app_dir or application_directory()).absolute()
    if target == own_dir:
        return "不能扫描秒杀小哈程序自身目录。"
    return ""


def extract_report_path(output, operation, expected_path=None, clean_root=None):
    match = REPORT_PATTERNS[operation].search(output or "")
    if match:
        value = Path(match.group(1).strip())
        if operation == "clean":
            value = value / "run-report.json"
        return value
    if expected_path:
        expected = Path(expected_path)
        if expected.is_file():
            return expected
    if operation == "clean" and clean_root:
        candidates = sorted(
            Path(clean_root).glob("**/run-report.json"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        if candidates:
            return candidates[0]
    return None


class CleanerWindow(object):
    def __init__(self, root):
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk

        self.tk = tk
        self.ttk = ttk
        self.filedialog = filedialog
        self.messagebox = messagebox
        self.root = root
        self.dpi = window_dpi(root)
        self.process = None
        self.events = queue.Queue()
        self.output_lines = []
        self.operation = ""
        self.expected_report = None
        self.clean_root = None
        self.last_report = None
        self.cancel_requested = False

        self.target_var = tk.StringVar()
        self.server_cfg_var = tk.StringVar()
        self.mysql_var = tk.StringVar()
        self.restore_var = tk.StringVar()
        self.sql_var = tk.BooleanVar(value=False)
        self.backup_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="先执行只读扫描，确认范围后再清理。")
        self.result_var = tk.StringVar(value="等待任务")

        self._configure_window()
        self._build_ui()
        self._set_running(False)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(100, self._poll_events)

    def _configure_window(self):
        self.root.title("{} v{}".format(APP_NAME, core.VERSION))
        self.root.configure(background="#0e1117")
        try:
            self.root.tk.call("tk", "scaling", tk_scaling_for_dpi(self.dpi))
        except Exception:
            pass
        width = logical_pixels(940, self.dpi)
        height = logical_pixels(720, self.dpi)
        max_width = max(640, int(self.root.winfo_screenwidth()) - logical_pixels(40, self.dpi))
        max_height = max(520, int(self.root.winfo_screenheight()) - logical_pixels(80, self.dpi))
        width = min(width, max_width)
        height = min(height, max_height)
        self.root.geometry("{}x{}".format(width, height))
        self.root.minsize(
            min(logical_pixels(820, self.dpi), width),
            min(logical_pixels(640, self.dpi), height),
        )

        style = self.ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Root.TFrame", background="#0e1117")
        style.configure("Card.TFrame", background="#161b22")
        style.configure("Title.TLabel", background="#0e1117", foreground="#f0f6fc", font=("Microsoft YaHei UI", 22, "bold"))
        style.configure("Subtitle.TLabel", background="#0e1117", foreground="#8b949e", font=("Microsoft YaHei UI", 10))
        style.configure("CardTitle.TLabel", background="#161b22", foreground="#f0f6fc", font=("Microsoft YaHei UI", 11, "bold"))
        style.configure("CardText.TLabel", background="#161b22", foreground="#c9d1d9", font=("Microsoft YaHei UI", 9))
        style.configure("Status.TLabel", background="#0e1117", foreground="#8b949e", font=("Microsoft YaHei UI", 9))
        style.configure("Result.TLabel", background="#0e1117", foreground="#58a6ff", font=("Microsoft YaHei UI", 10, "bold"))
        style.configure("TCheckbutton", background="#161b22", foreground="#c9d1d9", font=("Microsoft YaHei UI", 9))
        style.map("TCheckbutton", background=[("active", "#161b22")])
        style.configure("Primary.TButton", font=("Microsoft YaHei UI", 10, "bold"), padding=(14, 10))
        style.configure("Danger.TButton", font=("Microsoft YaHei UI", 10, "bold"), padding=(14, 10))
        style.configure("Quiet.TButton", font=("Microsoft YaHei UI", 9), padding=(10, 7))

    def _build_ui(self):
        outer = self.ttk.Frame(self.root, style="Root.TFrame", padding=20)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(5, weight=1)

        header = self.ttk.Frame(outer, style="Root.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        header.columnconfigure(0, weight=1)
        self.ttk.Label(header, text=APP_NAME, style="Title.TLabel").grid(row=0, column=0, sticky="w")
        self.ttk.Label(
            header,
            text="FiveM 小哈 / HGAdmin 资源、注入、配置与数据库清理",
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.ttk.Label(header, textvariable=self.result_var, style="Result.TLabel").grid(row=0, column=1, rowspan=2, sticky="e")

        target_card = self.ttk.Frame(outer, style="Card.TFrame", padding=14)
        target_card.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        target_card.columnconfigure(0, weight=1)
        self.ttk.Label(target_card, text="服务器目录", style="CardTitle.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
        self.ttk.Label(
            target_card,
            text="选择 server-data、resources 或单个资源目录；扫描不会执行目标中的脚本。",
            style="CardText.TLabel",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(3, 9))
        self.target_entry = self.ttk.Entry(target_card, textvariable=self.target_var)
        self.target_entry.grid(row=2, column=0, sticky="ew", padx=(0, 8))
        self.target_button = self.ttk.Button(target_card, text="选择目录", command=self.choose_target, style="Quiet.TButton")
        self.target_button.grid(row=2, column=1)

        database_card = self.ttk.Frame(outer, style="Card.TFrame", padding=14)
        database_card.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        database_card.columnconfigure(0, weight=1)
        self.ttk.Label(database_card, text="数据库清理（危险操作，默认关闭）", style="CardTitle.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
        self.sql_check = self.ttk.Checkbutton(
            database_card,
            text="同时删除小哈 / HGAdmin 创建的表和新增列",
            variable=self.sql_var,
            command=self._update_database_controls,
        )
        self.sql_check.grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 3))
        self.backup_check = self.ttk.Checkbutton(
            database_card,
            text="我已停止服务器并完成数据库备份",
            variable=self.backup_var,
        )
        self.backup_check.grid(row=2, column=0, columnspan=3, sticky="w", pady=(0, 8))

        self.ttk.Label(database_card, text="server.cfg（可选）", style="CardText.TLabel").grid(row=3, column=0, sticky="w")
        self.server_cfg_entry = self.ttk.Entry(database_card, textvariable=self.server_cfg_var)
        self.server_cfg_entry.grid(row=4, column=0, sticky="ew", padx=(0, 8))
        self.server_cfg_button = self.ttk.Button(database_card, text="选择配置", command=self.choose_server_cfg, style="Quiet.TButton")
        self.server_cfg_button.grid(row=4, column=1, padx=(0, 14))
        self.ttk.Label(database_card, text="mysql.exe（PATH 中存在可留空）", style="CardText.TLabel").grid(row=3, column=2, sticky="w")
        mysql_frame = self.ttk.Frame(database_card, style="Card.TFrame")
        mysql_frame.grid(row=4, column=2, sticky="ew")
        mysql_frame.columnconfigure(0, weight=1)
        self.mysql_entry = self.ttk.Entry(mysql_frame, textvariable=self.mysql_var, width=28)
        self.mysql_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.mysql_button = self.ttk.Button(mysql_frame, text="选择", command=self.choose_mysql, style="Quiet.TButton")
        self.mysql_button.grid(row=0, column=1)

        action_frame = self.ttk.Frame(outer, style="Root.TFrame")
        action_frame.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        for column in range(3):
            action_frame.columnconfigure(column, weight=1)
        self.scan_button = self.ttk.Button(action_frame, text="只读扫描", command=self.scan, style="Primary.TButton")
        self.scan_button.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.clean_button = self.ttk.Button(action_frame, text="执行清理", command=self.clean, style="Danger.TButton")
        self.clean_button.grid(row=0, column=1, sticky="ew", padx=5)
        self.cancel_button = self.ttk.Button(action_frame, text="停止任务", command=self.cancel, style="Quiet.TButton")
        self.cancel_button.grid(row=0, column=2, sticky="ew", padx=(5, 0))

        restore_card = self.ttk.Frame(outer, style="Card.TFrame", padding=14)
        restore_card.grid(row=4, column=0, sticky="ew", pady=(0, 10))
        restore_card.columnconfigure(0, weight=1)
        self.ttk.Label(restore_card, text="文件恢复", style="CardTitle.TLabel").grid(row=0, column=0, columnspan=4, sticky="w")
        self.restore_entry = self.ttk.Entry(restore_card, textvariable=self.restore_var)
        self.restore_entry.grid(row=1, column=0, sticky="ew", padx=(0, 8), pady=(8, 0))
        self.restore_choose_button = self.ttk.Button(restore_card, text="选择报告", command=self.choose_restore_report, style="Quiet.TButton")
        self.restore_choose_button.grid(row=1, column=1, padx=(0, 8), pady=(8, 0))
        self.restore_button = self.ttk.Button(restore_card, text="恢复文件", command=self.restore, style="Quiet.TButton")
        self.restore_button.grid(row=1, column=2, padx=(0, 8), pady=(8, 0))
        self.open_report_button = self.ttk.Button(restore_card, text="打开本次报告", command=self.open_report, style="Quiet.TButton")
        self.open_report_button.grid(row=1, column=3, pady=(8, 0))

        log_card = self.ttk.Frame(outer, style="Card.TFrame", padding=12)
        log_card.grid(row=5, column=0, sticky="nsew")
        log_card.columnconfigure(0, weight=1)
        log_card.rowconfigure(0, weight=1)
        self.log = self.tk.Text(
            log_card,
            background="#0d1117",
            foreground="#c9d1d9",
            insertbackground="#c9d1d9",
            relief="flat",
            wrap="none",
            font=("Consolas", 9),
            padx=10,
            pady=8,
            state="disabled",
        )
        self.log.grid(row=0, column=0, sticky="nsew")
        scroll = self.ttk.Scrollbar(log_card, orient="vertical", command=self.log.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scroll.set)

        footer = self.ttk.Frame(outer, style="Root.TFrame")
        footer.grid(row=6, column=0, sticky="ew", pady=(8, 0))
        footer.columnconfigure(0, weight=1)
        self.ttk.Label(footer, textvariable=self.status_var, style="Status.TLabel").grid(row=0, column=0, sticky="w")
        self.ttk.Label(footer, text="数据库 DROP 只能从备份恢复", style="Status.TLabel").grid(row=0, column=1, sticky="e")
        self._update_database_controls()

    def _update_database_controls(self):
        enabled = bool(self.sql_var.get()) and self.process is None
        state = "normal" if enabled else "disabled"
        for widget in (
            self.backup_check,
            self.server_cfg_entry,
            self.server_cfg_button,
            self.mysql_entry,
            self.mysql_button,
        ):
            widget.configure(state=state)

    def _set_running(self, running, label=""):
        state = "disabled" if running else "normal"
        for widget in (
            getattr(self, "scan_button", None),
            getattr(self, "clean_button", None),
            getattr(self, "restore_button", None),
            getattr(self, "target_button", None),
            getattr(self, "restore_choose_button", None),
            getattr(self, "sql_check", None),
        ):
            if widget is not None:
                widget.configure(state=state)
        if hasattr(self, "cancel_button"):
            self.cancel_button.configure(state="normal" if running else "disabled")
        if hasattr(self, "open_report_button"):
            self.open_report_button.configure(state="normal" if (not running and self.last_report) else "disabled")
        if running:
            self.result_var.set(label or "正在运行")
            self.status_var.set("正在运行秒杀小哈，可随时停止任务。")
        self._update_database_controls()

    def _append_log(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", str(text) + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def choose_target(self):
        selected = self.filedialog.askdirectory(title="选择 FiveM 服务器目录")
        if selected:
            self.target_var.set(selected)

    def choose_server_cfg(self):
        selected = self.filedialog.askopenfilename(title="选择 server.cfg", filetypes=[("CFG", "*.cfg"), ("所有文件", "*.*")])
        if selected:
            self.server_cfg_var.set(selected)

    def choose_mysql(self):
        selected = self.filedialog.askopenfilename(title="选择 MySQL / MariaDB 客户端", filetypes=[("EXE", "*.exe"), ("所有文件", "*.*")])
        if selected:
            self.mysql_var.set(selected)

    def choose_restore_report(self):
        selected = self.filedialog.askopenfilename(title="选择 run-report.json", filetypes=[("运行报告", "run-report.json"), ("JSON", "*.json")])
        if selected:
            self.restore_var.set(selected)

    def _validated_target(self):
        error = target_validation_error(self.target_var.get())
        if error:
            self.messagebox.showerror(APP_NAME, error)
            return None
        return Path(self.target_var.get().strip()).absolute()

    def scan(self):
        target = self._validated_target()
        if not target:
            return
        output = unique_output_directory("scan")
        self._start("scan", ["scan", str(target), "--output", str(output)], expected_report=output / "scan-report.json")

    def clean(self):
        target = self._validated_target()
        if not target:
            return
        apply_sql = bool(self.sql_var.get())
        if apply_sql and not self.backup_var.get():
            self.messagebox.showerror(APP_NAME, "启用数据库清理前，必须确认已停止服务器并完成数据库备份。")
            return

        warning = "即将隔离确认归属的小哈 / HGAdmin 资源并修改启动引用：\n\n{}".format(target)
        if apply_sql:
            warning += "\n\n同时会删除数据库表和新增列，包括 bans、warns。数据库只能从备份恢复。"
        else:
            warning += "\n\n本次不会连接数据库，只会生成 cleanup_database.sql。"
        if not self.messagebox.askyesno("确认执行秒杀小哈", warning, icon="warning"):
            return

        clean_root = target.parent / "_xiaoha_quarantine" / (
            "standalone-" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")[:-3] + "-" + uuid.uuid4().hex[:6]
        )
        arguments = ["clean", str(target), "--yes", "--quarantine-root", str(clean_root)]
        if apply_sql:
            arguments.extend(["--apply-sql", "--yes-drop-tables"])
            server_cfg = self.server_cfg_var.get().strip()
            if server_cfg:
                cfg_path = Path(server_cfg).absolute()
                if not cfg_path.is_file():
                    self.messagebox.showerror(APP_NAME, "server.cfg 不存在：{}".format(cfg_path))
                    return
                arguments.extend(["--server-cfg", str(cfg_path)])
            mysql_command = self.mysql_var.get().strip()
            if mysql_command:
                mysql_path = Path(mysql_command).absolute()
                if not mysql_path.is_file():
                    self.messagebox.showerror(APP_NAME, "MySQL 客户端不存在：{}".format(mysql_path))
                    return
                arguments.extend(["--mysql-command", str(mysql_path)])
        self._start("clean", arguments, clean_root=clean_root)

    def restore(self):
        report_text = self.restore_var.get().strip()
        report = Path(report_text).absolute() if report_text else None
        if not report or not report.is_file() or report.name.lower() != "run-report.json":
            self.messagebox.showerror(APP_NAME, "请选择有效的 run-report.json。")
            return
        if not self.messagebox.askyesno(
            "确认恢复文件",
            "即将按报告恢复文件系统修改：\n\n{}\n\n数据库 DROP 操作不会恢复。".format(report),
            icon="warning",
        ):
            return
        self._start("restore", ["restore", str(report), "--yes"], expected_report=report.parent / "restore-report.json")

    def _start(self, operation, arguments, expected_report=None, clean_root=None):
        if self.process is not None:
            self.messagebox.showwarning(APP_NAME, "已有任务正在运行。")
            return
        command = cli_command(arguments)
        environment = os.environ.copy()
        environment["PYTHONUNBUFFERED"] = "1"
        environment["PYTHONIOENCODING"] = "utf-8"
        creation_flags = CREATE_NO_WINDOW if os.name == "nt" else 0

        self._clear_log()
        self.output_lines = []
        self.operation = operation
        self.expected_report = Path(expected_report) if expected_report else None
        self.clean_root = Path(clean_root) if clean_root else None
        self.last_report = None
        self.cancel_requested = False
        self._set_running(True, {"scan": "正在扫描", "clean": "正在清理", "restore": "正在恢复"}[operation])
        self._append_log("命令已启动：{}".format(APP_NAME))
        try:
            self.process = subprocess.Popen(
                command,
                cwd=str(application_directory()),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                encoding="utf-8",
                errors="replace",
                env=environment,
                creationflags=creation_flags,
            )
        except Exception as exc:
            self.process = None
            self._set_running(False)
            self.result_var.set("启动失败")
            self.status_var.set(str(exc))
            self.messagebox.showerror(APP_NAME, "无法启动任务：{}".format(exc))
            return

        process = self.process

        def read_process():
            try:
                for line in iter(process.stdout.readline, ""):
                    self.events.put(("output", line.rstrip("\r\n")))
                process.stdout.close()
                exit_code = process.wait()
                self.events.put(("exit", exit_code))
            except Exception as exc:
                self.events.put(("reader-error", str(exc)))

        thread = threading.Thread(target=read_process, name="xiaoha-cleaner-output")
        thread.daemon = True
        thread.start()

    def _poll_events(self):
        try:
            while True:
                event, value = self.events.get_nowait()
                if event == "output":
                    self.output_lines.append(value)
                    self._append_log(value)
                elif event == "reader-error":
                    self._append_log("读取任务输出失败：{}".format(value))
                elif event == "exit":
                    self._finish(int(value))
        except queue.Empty:
            pass
        try:
            self.root.after(100, self._poll_events)
        except Exception:
            pass

    def _finish(self, exit_code):
        output = "\n".join(self.output_lines)
        report = extract_report_path(
            output,
            self.operation,
            expected_path=self.expected_report,
            clean_root=self.clean_root,
        )
        self.process = None
        if report and report.is_file():
            self.last_report = report
            if report.name.lower() == "run-report.json":
                self.restore_var.set(str(report))
            self._append_log("本次报告：{}".format(report))

        was_cancelled = self.cancel_requested
        self.cancel_requested = False
        self._set_running(False)
        if was_cancelled:
            self.result_var.set("任务已停止")
            self.status_var.set("任务已停止；请以报告状态和实际文件为准。")
        elif exit_code == 0:
            label = {"scan": "扫描完成", "clean": "清理完成", "restore": "恢复完成"}.get(self.operation, "任务完成")
            self.result_var.set(label)
            self.status_var.set("报告已生成；数据库清理前请确认服务器已停止并完成备份。")
        else:
            self.result_var.set("任务失败")
            self.status_var.set("进程退出码：{}；请查看输出和本次报告。".format(exit_code))

    def cancel(self):
        process = self.process
        if process is None:
            return
        if not self.messagebox.askyesno(APP_NAME, "强制停止可能发生在文件或数据库操作中间，是否继续？", icon="warning"):
            return
        self.cancel_requested = True
        self.status_var.set("正在停止任务……")
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=CREATE_NO_WINDOW,
                    check=False,
                )
            else:
                process.terminate()
        except Exception as exc:
            self.messagebox.showerror(APP_NAME, "停止任务失败：{}".format(exc))

    def open_report(self):
        if not self.last_report or not self.last_report.is_file():
            self.messagebox.showinfo(APP_NAME, "本次任务还没有可用报告。")
            return
        try:
            if os.name == "nt":
                os.startfile(str(self.last_report))
            else:
                subprocess.Popen(["xdg-open", str(self.last_report)])
        except Exception as exc:
            self.messagebox.showerror(APP_NAME, "无法打开报告：{}".format(exc))

    def close(self):
        if self.process is not None:
            if not self.messagebox.askyesno(APP_NAME, "任务仍在运行。停止任务并退出吗？", icon="warning"):
                return
            process = self.process
            try:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=CREATE_NO_WINDOW,
                        check=False,
                    )
                else:
                    process.terminate()
            except Exception:
                pass
        self.root.destroy()


def smoke_test():
    """Construct the GUI without showing it; used by release CI."""
    try:
        awareness = enable_high_dpi_awareness()
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        window = CleanerWindow(root)
        root.update_idletasks()
        root.destroy()
        print(
            "GUI smoke test passed: {} {} dpi={} awareness={}".format(
                APP_NAME, core.VERSION, window.dpi, awareness
            )
        )
        return 0
    except Exception as exc:
        print("GUI smoke test failed: {}".format(exc), file=sys.stderr)
        return 1


def main():
    enable_high_dpi_awareness()
    import tkinter as tk
    try:
        root = tk.Tk()
    except Exception as exc:
        print("ERROR: 无法启动{}界面：{}".format(APP_NAME, exc), file=sys.stderr)
        return 1
    CleanerWindow(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
