"""
ui.py  —  Windows Vuln Scanner v2.0 PRO
Interfaz SOC con: chart, historial, remediation, notificaciones, dark/light, escaneo programado.
"""
import json
import math
import os
import re
import base64
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk

from analyzer import SecurityAnalyzer
from app_logger import setup_logger
from report_exporter import export_html, export_json, export_txt
from scanner import WindowsScanner

APP_NAME    = "Windows Vuln Scanner"
APP_VERSION = "v2.0 PRO"
HISTORY_FILE = Path("scan_history.json")
FIX_HISTORY_FILE = Path("fix_history.jsonl")

# ─────────────────────────────────────────────
# THEMES
# ─────────────────────────────────────────────
THEMES = {
    "dark": {
        "BG_DEEP":   "#060d18",
        "BG_PANEL":  "#0c1a2e",
        "BG_CARD":   "#0f2340",
        "BG_HOVER":  "#162e50",
        "ACCENT":    "#00d4ff",
        "RED":       "#ff3b5c",
        "YELLOW":    "#fbbf24",
        "GREEN":     "#10d48e",
        "BORDER":    "#1a3a5c",
        "TEXT_PRI":  "#e8f4ff",
        "TEXT_SEC":  "#6a90b8",
    },
    "light": {
        "BG_DEEP":   "#f0f4f8",
        "BG_PANEL":  "#ffffff",
        "BG_CARD":   "#e8f0f7",
        "BG_HOVER":  "#d0e0f0",
        "ACCENT":    "#0066cc",
        "RED":       "#cc1133",
        "YELLOW":    "#cc7700",
        "GREEN":     "#007744",
        "BORDER":    "#b0c8e0",
        "TEXT_PRI":  "#0a1a2e",
        "TEXT_SEC":  "#4a6080",
    }
}

SEV_COLORS = {
    "critical": "#ff3b5c",
    "high":     "#ff6b35",
    "medium":   "#fbbf24",
    "low":      "#10d48e",
}


# ─────────────────────────────────────────────
# WIDGETS
# ─────────────────────────────────────────────
class MetricCard(tk.Frame):
    def __init__(self, parent, label, value="—", color="#00d4ff",
                 bg="#0f2340", border="#1a3a5c", width=160, **kw):
        super().__init__(parent, bg=bg,
                         highlightbackground=border, highlightthickness=1,
                         width=width, height=90, **kw)
        self.pack_propagate(False)
        self._bg = bg

        self._bar = tk.Frame(self, bg=color, height=2)
        self._bar.place(x=0, y=0, relwidth=1)

        tk.Label(self, text=label, bg=bg, fg="#6a90b8",
                 font=("Consolas", 8, "bold")).pack(anchor="w", padx=12, pady=(10, 0))

        self.val_lbl = tk.Label(self, text=value, bg=bg, fg=color,
                                font=("Consolas", 26, "bold"))
        self.val_lbl.pack(anchor="w", padx=12)

    def update(self, value, color=None, bg=None):
        if bg:
            self._bg = bg
            self.config(bg=bg)
            self.val_lbl.config(bg=bg)
            for child in self.winfo_children():
                try:
                    child.config(bg=bg)
                except Exception:
                    pass
        self.val_lbl.config(text=str(value))
        if color:
            self.val_lbl.config(fg=color)
            self._bar.config(bg=color)


class SeverityChart(tk.Canvas):
    """Donut chart de severidades."""
    def __init__(self, parent, bg="#0c1a2e", size=160, **kw):
        super().__init__(parent, width=size, height=size, bg=bg,
                         highlightthickness=0, **kw)
        self._size = size
        self._bg   = bg
        self.draw({})

    def draw(self, counts):
        self.delete("all")
        cx = cy = self._size / 2
        r_out = cx - 8
        r_in  = cx - 32
        total = sum(counts.values()) or 1

        colors = [
            ("#ff3b5c", counts.get("critical", 0)),
            ("#ff6b35", counts.get("high",     0)),
            ("#fbbf24", counts.get("medium",   0)),
            ("#10d48e", counts.get("low",      0)),
        ]

        start = -90
        for color, val in colors:
            extent = (val / total) * 360
            if extent > 0:
                self.create_arc(cx - r_out, cy - r_out, cx + r_out, cy + r_out,
                                start=start, extent=extent,
                                fill=color, outline="")
            start += extent

        # inner hole
        self.create_oval(cx - r_in, cy - r_in, cx + r_in, cy + r_in,
                         fill=self._bg, outline="")

        total_real = sum(counts.values())
        self.create_text(cx, cy - 10, text=str(total_real),
                         fill="white", font=("Consolas", 18, "bold"))
        self.create_text(cx, cy + 10, text="hallazgos",
                         fill="#6a90b8", font=("Consolas", 8))


class FindingRow(tk.Frame):
    def __init__(self, parent, finding, index, t, on_fix=None):
        bg = t["BG_PANEL"] if index % 2 == 0 else t["BG_CARD"]
        super().__init__(parent, bg=bg)
        self.pack(fill="x")

        sev   = finding["severity"]
        color = SEV_COLORS.get(sev, t["TEXT_SEC"])

        badge = tk.Label(self, text=f" {sev.upper()} ", bg=color,
                         fg="#000000", font=("Consolas", 8, "bold"), padx=4)
        badge.pack(side="left", padx=(10, 8), pady=6)

        tk.Label(self, text=finding["title"], bg=bg, fg=t["TEXT_PRI"],
                 font=("Consolas", 10), anchor="w").pack(side="left", pady=6)

        for tag in finding.get("mitre", [])[:1]:
            short = tag.split(" - ")[0]
            tk.Label(self, text=short, bg=t["BG_HOVER"], fg=t["ACCENT"],
                     font=("Consolas", 8), padx=6).pack(side="right", padx=(0, 10), pady=6)

        if on_fix:
            btn = tk.Button(self, text="Fix ▶", bg=t["BG_HOVER"], fg=t["GREEN"],
                            font=("Consolas", 8, "bold"), bd=0, padx=6, pady=2,
                            cursor="hand2",
                            command=lambda f=finding: on_fix(f))
            btn.pack(side="right", padx=4, pady=4)


# ─────────────────────────────────────────────
# MAIN APP
# ─────────────────────────────────────────────
class WindowsSecurityAuditorUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"  {APP_NAME}  {APP_VERSION}")
        self.root.geometry("1360x820")
        self.root.minsize(1100, 680)

        self.logger   = setup_logger()
        self.scanner  = WindowsScanner(self.logger)
        self.analyzer = SecurityAnalyzer(self.logger)

        self.is_scanning   = False
        self.findings_all  = []
        self.system_info   = {}
        self.last_score    = 0
        self.filter_sev    = tk.StringVar(value="ALL")
        self.theme_name    = tk.StringVar(value="dark")
        self.schedule_var  = tk.StringVar(value="Off")
        self.remediation_mode = tk.BooleanVar(value=False)
        self._schedule_job = None

        self.t = THEMES["dark"]
        self.root.configure(bg=self.t["BG_DEEP"])

        self._build()

    # ─── BUILD ───
    def _build(self):
        self._build_topbar()
        body = tk.Frame(self.root, bg=self.t["BG_DEEP"])
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        self._build_sidebar(body)

        right = tk.Frame(body, bg=self.t["BG_DEEP"])
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(3, weight=1)

        self._build_metric_row(right)
        self._build_progress_bar(right)
        self._build_notebook(right)   # paneles primero
        self._build_tab_bar(right)    # tab bar después (necesita los paneles)

    # ─── TOP BAR ───
    def _build_topbar(self):
        bar = tk.Frame(self.root, bg=self.t["BG_PANEL"], height=50)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        left = tk.Frame(bar, bg=self.t["BG_PANEL"])
        left.pack(side="left", padx=20)

        tk.Label(left, text="⬡", bg=self.t["BG_PANEL"], fg=self.t["ACCENT"],
                 font=("Segoe UI Symbol", 22)).pack(side="left", padx=(0, 8))
        tk.Label(left, text=APP_NAME, bg=self.t["BG_PANEL"], fg=self.t["TEXT_PRI"],
                 font=("Consolas", 13, "bold")).pack(side="left")
        tk.Label(left, text=APP_VERSION, bg=self.t["BG_PANEL"], fg=self.t["TEXT_SEC"],
                 font=("Consolas", 9)).pack(side="left", padx=8)

        right = tk.Frame(bar, bg=self.t["BG_PANEL"])
        right.pack(side="right", padx=20)

        # theme toggle
        tk.Button(right, text="☀ / ☾", command=self.toggle_theme,
                  bg=self.t["BG_CARD"], fg=self.t["ACCENT"],
                  font=("Consolas", 9), bd=0, padx=10, pady=4,
                  cursor="hand2").pack(side="right", padx=6)

        self.clock_lbl = tk.Label(right, text="", bg=self.t["BG_PANEL"],
                                  fg=self.t["TEXT_SEC"], font=("Consolas", 9))
        self.clock_lbl.pack(side="right", padx=12)
        self._tick_clock()

        tk.Frame(self.root, bg=self.t["ACCENT"], height=2).pack(fill="x")

    def _tick_clock(self):
        self.clock_lbl.config(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.root.after(1000, self._tick_clock)

    # ─── SIDEBAR ───
    def _build_sidebar(self, parent):
        self.sidebar = tk.Frame(parent, bg=self.t["BG_PANEL"], width=240)
        self.sidebar.grid(row=0, column=0, sticky="nsw")
        self.sidebar.pack_propagate(False)
        s = self.sidebar

        tk.Label(s, text="ACCIONES", bg=self.t["BG_PANEL"], fg=self.t["TEXT_SEC"],
                 font=("Consolas", 8, "bold")).pack(anchor="w", padx=18, pady=(22, 6))

        self.scan_btn = self._sbtn(s, "▶  Iniciar escaneo", self.start_scan, self.t["ACCENT"])
        self._sbtn(s, "📄  Exportar HTML",   lambda: self.export_report("html"))
        self._sbtn(s, "{ }  Exportar JSON",  lambda: self.export_report("json"))
        self._sbtn(s, "📝  Exportar TXT",    lambda: self.export_report("txt"))
        self._sbtn(s, "🧾  Exportar Fix Log", self.export_fix_log)
        self._sbtn(s, "🗑  Limpiar",         self.clear_all)

        tk.Frame(s, bg=self.t["BORDER"], height=1).pack(fill="x", padx=18, pady=14)

        tk.Label(s, text="MODO DE EJECUCION", bg=self.t["BG_PANEL"], fg=self.t["TEXT_SEC"],
                 font=("Consolas", 8, "bold")).pack(anchor="w", padx=18, pady=(0, 6))
        mode_frame = tk.Frame(s, bg=self.t["BG_PANEL"])
        mode_frame.pack(fill="x", padx=18, pady=(0, 8))
        tk.Radiobutton(
            mode_frame,
            text="Auditoria (solo lectura)",
            variable=self.remediation_mode,
            value=False,
            bg=self.t["BG_PANEL"],
            fg=self.t["TEXT_PRI"],
            selectcolor=self.t["BG_HOVER"],
            activebackground=self.t["BG_PANEL"],
            font=("Consolas", 9),
            indicatoron=True,
            command=self._on_mode_change
        ).pack(anchor="w", pady=1)
        tk.Radiobutton(
            mode_frame,
            text="Remediacion (Fix activo)",
            variable=self.remediation_mode,
            value=True,
            bg=self.t["BG_PANEL"],
            fg=self.t["GREEN"],
            selectcolor=self.t["BG_HOVER"],
            activebackground=self.t["BG_PANEL"],
            font=("Consolas", 9, "bold"),
            indicatoron=True,
            command=self._on_mode_change
        ).pack(anchor="w", pady=1)
        self.mode_lbl = tk.Label(
            s,
            text="Modo actual: Auditoria",
            bg=self.t["BG_PANEL"],
            fg=self.t["YELLOW"],
            font=("Consolas", 8, "bold")
        )
        self.mode_lbl.pack(anchor="w", padx=18, pady=(0, 8))
        self._on_mode_change()

        tk.Frame(s, bg=self.t["BORDER"], height=1).pack(fill="x", padx=18, pady=8)

        # ── FILTRO ──
        tk.Label(s, text="FILTRAR SEVERIDAD", bg=self.t["BG_PANEL"], fg=self.t["TEXT_SEC"],
                 font=("Consolas", 8, "bold")).pack(anchor="w", padx=18, pady=(0, 6))

        for sev in ["ALL", "critical", "high", "medium", "low"]:
            color = SEV_COLORS.get(sev, self.t["TEXT_PRI"])
            rb = tk.Radiobutton(
                s, text=sev.upper(), variable=self.filter_sev, value=sev,
                bg=self.t["BG_PANEL"], fg=color,
                selectcolor=self.t["BG_HOVER"],
                activebackground=self.t["BG_PANEL"], activeforeground=color,
                font=("Consolas", 10, "bold"), indicatoron=False,
                bd=0, padx=12, pady=5, relief="flat",
                command=self._apply_filter
            )
            rb.pack(fill="x", padx=18, pady=1)

        tk.Frame(s, bg=self.t["BORDER"], height=1).pack(fill="x", padx=18, pady=14)

        # ── ESCANEO PROGRAMADO ──
        tk.Label(s, text="ESCANEO AUTOMÁTICO", bg=self.t["BG_PANEL"], fg=self.t["TEXT_SEC"],
                 font=("Consolas", 8, "bold")).pack(anchor="w", padx=18, pady=(0, 6))

        sched_frame = tk.Frame(s, bg=self.t["BG_PANEL"])
        sched_frame.pack(fill="x", padx=18)
        for opt in ["Off", "30 min", "1 hora", "6 horas"]:
            rb = tk.Radiobutton(sched_frame, text=opt, variable=self.schedule_var,
                                value=opt, bg=self.t["BG_PANEL"], fg=self.t["TEXT_PRI"],
                                selectcolor=self.t["BG_HOVER"],
                                activebackground=self.t["BG_PANEL"],
                                font=("Consolas", 9), indicatoron=True,
                                command=self._apply_schedule)
            rb.pack(anchor="w", pady=1)

        # ── LOGO ──
        logo_path = Path(__file__).with_name("logo.png")
        if logo_path.exists():
            try:
                base = tk.PhotoImage(file=str(logo_path))
                cropped = tk.PhotoImage()
                cropped.tk.call(cropped, "copy", base, "-from", 160, 80, 860, 650)
                img = cropped.subsample(4, 4)
                lbl = tk.Label(s, image=img, bg=self.t["BG_PANEL"], bd=0, highlightthickness=0)
                lbl.image = img
                lbl._base = base
                lbl._cropped = cropped
                lbl.pack(side="bottom", pady=20)
            except Exception:
                pass

        tk.Label(s, text="SOC Edition", bg=self.t["BG_PANEL"],
                 fg=self.t["TEXT_SEC"], font=("Consolas", 8)).pack(side="bottom", pady=4)

    def _sbtn(self, parent, text, cmd, fg=None):
        fg = fg or self.t["TEXT_PRI"]
        btn = tk.Button(parent, text=text, command=cmd,
                        bg=self.t["BG_CARD"], fg=fg,
                        activebackground=self.t["BG_HOVER"], activeforeground=fg,
                        font=("Consolas", 10, "bold"), bd=0, padx=14, pady=8,
                        relief="flat", cursor="hand2", anchor="w")
        btn.pack(fill="x", padx=12, pady=2)

        def on_enter(e): btn.config(bg=self.t["BG_HOVER"])
        def on_leave(e): btn.config(bg=self.t["BG_CARD"])
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        return btn

    def _on_mode_change(self):
        if hasattr(self, "mode_lbl"):
            if self.remediation_mode.get():
                self.mode_lbl.config(text="Modo actual: Remediacion", fg=self.t["GREEN"])
            else:
                self.mode_lbl.config(text="Modo actual: Auditoria", fg=self.t["YELLOW"])

    # ─── METRIC ROW ───
    def _build_metric_row(self, parent):
        row = tk.Frame(parent, bg=self.t["BG_DEEP"])
        row.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 0))

        kw = {"bg": self.t["BG_CARD"], "border": self.t["BORDER"]}
        self.card_score    = MetricCard(row, "SCORE",     "—",    self.t["RED"],    **kw, width=130)
        self.card_critical = MetricCard(row, "CRÍTICOS",  "0",    "#ff3b5c",        **kw, width=110)
        self.card_high     = MetricCard(row, "ALTOS",     "0",    "#ff6b35",        **kw, width=110)
        self.card_medium   = MetricCard(row, "MEDIOS",    "0",    self.t["YELLOW"], **kw, width=110)
        self.card_low      = MetricCard(row, "BAJOS",     "0",    self.t["GREEN"],  **kw, width=110)
        self.card_status   = MetricCard(row, "ESTADO",    "LISTO",self.t["ACCENT"], **kw, width=130)

        self.chart = SeverityChart(row, bg=self.t["BG_CARD"], size=90)

        for w in [self.card_score, self.card_critical, self.card_high,
                  self.card_medium, self.card_low, self.card_status]:
            w.pack(side="left", padx=(0, 8))

        self.chart.pack(side="left", padx=(8, 0))

    # ─── PROGRESS BAR ───
    def _build_progress_bar(self, parent):
        f = tk.Frame(parent, bg=self.t["BG_DEEP"])
        f.grid(row=1, column=0, sticky="ew", padx=16, pady=10)

        top = tk.Frame(f, bg=self.t["BG_DEEP"])
        top.pack(fill="x")

        self.progress_lbl = tk.Label(top, text="", bg=self.t["BG_DEEP"],
                                     fg=self.t["TEXT_SEC"], font=("Consolas", 8))
        self.progress_lbl.pack(side="left")
        self.progress_pct = tk.Label(top, text="", bg=self.t["BG_DEEP"],
                                     fg=self.t["ACCENT"], font=("Consolas", 8, "bold"))
        self.progress_pct.pack(side="right")

        self.bar_canvas = tk.Canvas(f, height=5, bg=self.t["BG_PANEL"],
                                    highlightthickness=0)
        self.bar_canvas.pack(fill="x", pady=(4, 0))

        # module chips
        self.step_frame = tk.Frame(f, bg=self.t["BG_DEEP"])
        self.step_frame.pack(fill="x", pady=(5, 0))

        modules = ["system_info", "users", "password_policy", "network",
                   "smb_shares", "processes", "signatures",
                   "tasks", "services", "registry_run", "startup",
                   "firewall", "windows_update"]
        self._step_labels = {}
        for m in modules:
            lbl = tk.Label(self.step_frame, text=m.replace("_", " "),
                           bg=self.t["BG_DEEP"], fg=self.t["TEXT_SEC"],
                           font=("Consolas", 7), padx=5, pady=2,
                           highlightbackground=self.t["BORDER"], highlightthickness=1)
            lbl.pack(side="left", padx=2)
            self._step_labels[m] = lbl

    def _draw_bar(self, pct):
        self.bar_canvas.update_idletasks()
        w = self.bar_canvas.winfo_width()
        self.bar_canvas.delete("all")
        self.bar_canvas.create_rectangle(0, 0, w, 5, fill=self.t["BG_PANEL"], outline="")
        filled = int(w * pct / 100)
        if filled > 0:
            self.bar_canvas.create_rectangle(0, 0, filled, 5,
                                              fill=self.t["ACCENT"], outline="")

    # ─── TAB BAR ───
    def _build_tab_bar(self, parent):
        self.tab_frame = tk.Frame(parent, bg=self.t["BG_DEEP"])
        self.tab_frame.grid(row=2, column=0, sticky="ew", padx=16)

        self._tabs = {}
        self._active_tab = tk.StringVar(value="findings")

        for name, label in [("findings", "🔍 Hallazgos"),
                             ("history",  "📈 Historial"),
                             ("info",     "🖥️  Sistema")]:
            btn = tk.Button(
                self.tab_frame, text=label,
                command=lambda n=name: self._switch_tab(n),
                bg=self.t["BG_CARD"], fg=self.t["TEXT_SEC"],
                font=("Consolas", 9, "bold"), bd=0, padx=14, pady=7,
                relief="flat", cursor="hand2"
            )
            btn.pack(side="left", padx=(0, 4))
            self._tabs[name] = btn

        self._switch_tab("findings")

    def _switch_tab(self, name):
        self._active_tab.set(name)
        for n, btn in self._tabs.items():
            if n == name:
                btn.config(bg=self.t["BG_HOVER"], fg=self.t["ACCENT"])
            else:
                btn.config(bg=self.t["BG_CARD"], fg=self.t["TEXT_SEC"])

        for panel in [self.panel_findings, self.panel_history, self.panel_info]:
            panel.grid_remove()

        {"findings": self.panel_findings,
         "history":  self.panel_history,
         "info":     self.panel_info}[name].grid()

    # ─── NOTEBOOK PANELS ───
    def _build_notebook(self, parent):
        container = tk.Frame(parent, bg=self.t["BG_DEEP"])
        container.grid(row=3, column=0, sticky="nsew", padx=16, pady=(4, 14))
        parent.rowconfigure(3, weight=1)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=1)

        self.panel_findings = self._build_findings_panel(container)
        self.panel_history  = self._build_history_panel(container)
        self.panel_info     = self._build_info_panel(container)

        for p in [self.panel_findings, self.panel_history, self.panel_info]:
            p.grid(row=0, column=0, sticky="nsew")

        self.panel_history.grid_remove()
        self.panel_info.grid_remove()

    def _scrollable(self, parent):
        outer = tk.Frame(parent, bg=self.t["BG_PANEL"],
                         highlightbackground=self.t["BORDER"], highlightthickness=1)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(0, weight=1)

        c = tk.Canvas(outer, bg=self.t["BG_PANEL"], highlightthickness=0)
        c.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(outer, orient="vertical", command=c.yview)
        sb.grid(row=0, column=1, sticky="ns")
        c.configure(yscrollcommand=sb.set)

        inner = tk.Frame(c, bg=self.t["BG_PANEL"])
        win = c.create_window((0, 0), window=inner, anchor="nw")

        inner.bind("<Configure>",
                   lambda e: c.configure(scrollregion=c.bbox("all")))
        c.bind("<Configure>",
               lambda e: c.itemconfig(win, width=e.width))
        c.bind_all("<MouseWheel>",
                   lambda e: c.yview_scroll(-1 * (e.delta // 120), "units"))
        return outer, inner

    # ── FINDINGS PANEL ──
    def _build_findings_panel(self, parent):
        f = tk.Frame(parent, bg=self.t["BG_DEEP"])

        header = tk.Frame(f, bg=self.t["BG_DEEP"])
        header.pack(fill="x", pady=(0, 6))
        tk.Label(header, text="HALLAZGOS DE SEGURIDAD", bg=self.t["BG_DEEP"],
                 fg=self.t["TEXT_PRI"], font=("Consolas", 11, "bold")).pack(side="left")
        self.count_lbl = tk.Label(header, text="", bg=self.t["BG_DEEP"],
                                  fg=self.t["TEXT_SEC"], font=("Consolas", 9))
        self.count_lbl.pack(side="right")

        _, self.findings_frame = self._scrollable(f)

        self._show_empty()
        return f

    # ── HISTORY PANEL ──
    def _build_history_panel(self, parent):
        f = tk.Frame(parent, bg=self.t["BG_DEEP"])

        header = tk.Frame(f, bg=self.t["BG_DEEP"])
        header.pack(fill="x", pady=(0, 6))
        tk.Label(header, text="HISTORIAL DE ESCANEOS", bg=self.t["BG_DEEP"],
                 fg=self.t["TEXT_PRI"], font=("Consolas", 11, "bold")).pack(side="left")
        tk.Button(header, text="🗑 Limpiar historial", command=self._clear_history,
                  bg=self.t["BG_CARD"], fg=self.t["RED"], font=("Consolas", 8),
                  bd=0, padx=8, cursor="hand2").pack(side="right")

        _, self.history_frame = self._scrollable(f)
        self._load_history_ui()
        return f

    # ── INFO PANEL ──
    def _build_info_panel(self, parent):
        f = tk.Frame(parent, bg=self.t["BG_DEEP"])

        tk.Label(f, text="INFORMACIÓN DEL SISTEMA", bg=self.t["BG_DEEP"],
                 fg=self.t["TEXT_PRI"], font=("Consolas", 11, "bold")).pack(anchor="w", pady=(0, 10))

        self.info_frame = tk.Frame(f, bg=self.t["BG_PANEL"],
                                   highlightbackground=self.t["BORDER"],
                                   highlightthickness=1)
        self.info_frame.pack(fill="both", expand=True)

        self.info_lbl = tk.Label(self.info_frame,
                                 text="Ejecuta un escaneo para ver la información del sistema.",
                                 bg=self.t["BG_PANEL"], fg=self.t["TEXT_SEC"],
                                 font=("Consolas", 10), justify="left", anchor="nw")
        self.info_lbl.pack(padx=20, pady=20, anchor="nw")
        return f

    # ─── SCAN ───
    def start_scan(self):
        if self.is_scanning:
            return
        self.is_scanning = True
        self.scan_btn.config(text="⏳  Escaneando...", state="disabled")
        self.card_status.update("SCAN", self.t["ACCENT"])

        for lbl in self._step_labels.values():
            lbl.config(fg=self.t["TEXT_SEC"], bg=self.t["BG_DEEP"])

        self._clear_findings_ui()
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self):
        results = self.scanner.collect_all(progress_callback=self._on_progress)
        findings, score = self.analyzer.analyze(results)

        self.findings_all = findings
        self.last_score   = score
        self.system_info  = results.get("system_info", {})

        self._save_history(score, findings)
        self.root.after(0, lambda: self._show_results(findings, score))

    def _on_progress(self, current, total, module):
        pct = int((current / total) * 100)

        def _up():
            self._draw_bar(pct)
            self.progress_lbl.config(text=f"Módulo: {module.replace('_', ' ')}")
            self.progress_pct.config(text=f"{pct}%")
            lbl = self._step_labels.get(module)
            if lbl:
                lbl.config(fg=self.t["GREEN"], bg=self.t["BG_HOVER"])
        self.root.after(0, _up)

    def _show_results(self, findings, score):
        counts = {s: sum(1 for f in findings if f["severity"] == s)
                  for s in ("critical", "high", "medium", "low")}

        score_color = (self.t["GREEN"] if score <= 30
                       else self.t["YELLOW"] if score <= 60
                       else self.t["RED"])

        self.card_score.update(f"{score}%", score_color)
        self.card_critical.update(counts["critical"], "#ff3b5c")
        self.card_high.update(counts["high"],     "#ff6b35")
        self.card_medium.update(counts["medium"], self.t["YELLOW"])
        self.card_low.update(counts["low"],       self.t["GREEN"])
        self.card_status.update("DONE", self.t["GREEN"])
        self.chart.draw(counts)

        self._draw_bar(100)
        self.progress_lbl.config(text="Escaneo completado")
        self.progress_pct.config(text="100%")

        self._render_findings(findings)
        self._update_info_panel()
        self._load_history_ui()

        # Windows notification
        self._notify(f"Score: {score}/100 — {len(findings)} hallazgos", counts)

        if counts["critical"]:
            messagebox.showwarning("⚠️  SOC Alert",
                                   f"{counts['critical']} vulnerabilidad(es) CRÍTICA(s) detectadas.\n"
                                   "Revisa los hallazgos de inmediato.")

        self.scan_btn.config(text="▶  Iniciar escaneo", state="normal")
        self.is_scanning = False

    # ─── RENDER FINDINGS ───
    def _render_findings(self, findings):
        self._clear_findings_ui()
        if not findings:
            self._show_empty(ok=True)
            self.count_lbl.config(text="0 hallazgos")
            return

        self.count_lbl.config(text=f"{len(findings)} hallazgo(s)")
        for i, f in enumerate(findings):
            FindingRow(self.findings_frame, f, i, self.t, on_fix=self._attempt_fix)

    def _apply_filter(self):
        sev = self.filter_sev.get()
        filtered = (self.findings_all if sev == "ALL"
                    else [f for f in self.findings_all if f["severity"] == sev])
        self._render_findings(filtered)

    def _clear_findings_ui(self):
        for w in self.findings_frame.winfo_children():
            w.destroy()

    def _show_empty(self, ok=False):
        text = "\n  ✅  Sin vulnerabilidades detectadas.\n" if ok else \
               "\n\n  Sin hallazgos todavía.  Inicia un escaneo ▶\n"
        color = self.t["GREEN"] if ok else self.t["TEXT_SEC"]
        tk.Label(self.findings_frame, text=text,
                 bg=self.t["BG_PANEL"], fg=color,
                 font=("Consolas", 10)).pack(anchor="w", padx=14)

    # ─── REMEDIATION ───
    def _quote_exe_path(self, raw_path):
        match = re.match(r"^(.+?\.exe)\b(.*)$", raw_path.strip(), re.IGNORECASE)
        if not match:
            return None
        exe = match.group(1).strip().strip('"')
        args = match.group(2).strip()
        if " " in exe:
            return f'"{exe}" {args}'.strip()
        return None

    def _get_fix_action(self, finding):
        title = finding.get("title", "")
        details = finding.get("details", "")
        title_l = title.lower()

        if "firewall desactivado" in title_l:
            return (
                "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
                "Firewall habilitado en todos los perfiles."
            )

        if "protocolo inseguro activo: telnet" in title_l:
            return (
                "Set-Service -Name TlntSvr -StartupType Disabled -ErrorAction SilentlyContinue; "
                "Stop-Service -Name TlntSvr -Force -ErrorAction SilentlyContinue",
                "Telnet deshabilitado."
            )

        if "protocolo inseguro activo: ftp" in title_l:
            return (
                "Set-Service -Name FTPSVC -StartupType Disabled -ErrorAction SilentlyContinue; "
                "Stop-Service -Name FTPSVC -Force -ErrorAction SilentlyContinue",
                "Servicio FTP deshabilitado."
            )

        if "puerto del sistema expuesto" in title_l or "puerto sensible en escucha" in title_l:
            m = re.search(r"\((\d+)\)", title)
            if m:
                port = m.group(1)
                return (
                    f"if (-not (Get-NetFirewallRule -DisplayName 'WVS Block Port {port}' -ErrorAction SilentlyContinue)) "
                    f"{{ New-NetFirewallRule -DisplayName 'WVS Block Port {port}' -Direction Inbound -Action Block -Protocol TCP -LocalPort {port} }}",
                    f"Regla de firewall creada para bloquear el puerto {port}."
                )

        if "cuenta invitado habilitada" in title_l:
            user = title.split(":")[-1].strip()
            return (f"Disable-LocalUser -Name '{user}'", f"Cuenta {user} deshabilitada.")

        if "passwordrequired=false" in title_l:
            user = title.split(":")[-1].strip()
            return (
                f"net user \"{user}\" /passwordreq:yes",
                f"Cuenta {user} configurada para requerir contraseña."
            )

        if "politica de contrasena debil" in title_l:
            return ("net accounts /minpwlen:12", "Longitud mínima de contraseña actualizada.")

        if "contrasenas sin rotacion adecuada" in title_l:
            return ("net accounts /maxpwage:90", "Expiración máxima de contraseña ajustada a 90 días.")

        if "sin bloqueo de cuenta por intentos fallidos" in title_l:
            return ("net accounts /lockoutthreshold:5", "Bloqueo por intentos fallidos configurado.")

        if "historial de contrasenas bajo" in title_l:
            return ("net accounts /uniquepw:10", "Historial de contraseñas configurado a 10.")

        if "smbv1 habilitado" in title_l:
            return (
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                "SMBv1 deshabilitado."
            )

        if "sesiones nulas smb no restringidas" in title_l:
            return (
                "Set-SmbServerConfiguration -RestrictNullSessAccess $true -Force",
                "Sesiones nulas SMB restringidas."
            )

        if "recursos compartidos adicionales detectados" in title_l:
            return (
                "Get-SmbShare | Where-Object { $_.Name -notmatch '^[A-Z]\\$$|^ADMIN\\$$|^IPC\\$$' } | "
                "ForEach-Object { Set-SmbShare -Name $_.Name -EncryptData $true -FolderEnumerationMode AccessBased -Force }",
                "Shares adicionales endurecidos (cifrado y acceso por permisos)."
            )

        if "proceso ejecutandose desde ruta sospechosa" in title_l:
            name = title.split(":")[-1].strip()
            return (
                f"Get-Process -Name '{name}' -ErrorAction SilentlyContinue | Stop-Process -Force",
                f"Proceso {name} finalizado (si estaba activo)."
            )

        if "lolbin activo:" in title_l:
            raw = title.split(":", 1)[-1].strip()
            name = raw.split("(")[0].strip()
            return (
                f"Get-Process -Name '{name}' -ErrorAction SilentlyContinue | Stop-Process -Force",
                f"Procesos {name} finalizados (si estaban activos)."
            )

        if "ejecutable con firma invalida" in title_l:
            raw = title.split(":", 1)[-1].strip()
            name = raw.split("(")[0].strip()
            return (
                f"Get-Process -Name '{name}' -ErrorAction SilentlyContinue | Stop-Process -Force",
                f"Proceso {name} finalizado para contención inicial."
            )

        if "actualizaciones pendientes" in title_l:
            return (
                "UsoClient StartScan; Start-Sleep -Seconds 3; UsoClient StartDownload; Start-Sleep -Seconds 3; UsoClient StartInstall",
                "Secuencia de Windows Update iniciada."
            )

        if "persistencia sospechosa en registro" in title_l:
            return (
                "$rk='HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'; "
                "$obj=Get-ItemProperty -Path $rk; "
                "$obj.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' -and ($_.Value -match '(?i)\\\\temp\\\\|\\\\public\\\\') } | "
                "ForEach-Object { Remove-ItemProperty -Path $rk -Name $_.Name -Force }",
                "Entradas sospechosas en Run key eliminadas (temp/public)."
            )

        if "persistencia sospechosa en carpeta startup" in title_l:
            return (
                "$sp=\"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"; "
                "Get-ChildItem $sp -File -ErrorAction SilentlyContinue | "
                "Where-Object { $_.FullName -match '(?i)\\\\temp\\\\|\\\\public\\\\|\\.ps1$' } | "
                "Remove-Item -Force",
                "Elementos sospechosos eliminados de Startup."
            )

        if "ruta de servicio sin comillas" in title_l:
            svc = title.split(":")[-1].strip()
            quoted = self._quote_exe_path(details)
            if quoted:
                return (
                    f"sc.exe config \"{svc}\" binPath= \"{quoted}\"",
                    f"Ruta de servicio {svc} corregida con comillas."
                )

        if "servicio desde ruta sospechosa" in title_l:
            svc = title.split(":")[-1].strip()
            return (
                f"Set-Service -Name \"{svc}\" -StartupType Disabled -ErrorAction SilentlyContinue; "
                f"Stop-Service -Name \"{svc}\" -Force -ErrorAction SilentlyContinue",
                f"Servicio {svc} detenido y deshabilitado."
            )

        return None

    def _attempt_fix(self, finding):
        if not self.remediation_mode.get():
            messagebox.showinfo(
                "Modo Auditoria",
                "El modo actual es Auditoria (solo lectura).\n\n"
                "Cambia a 'Remediacion (Fix activo)' para ejecutar comandos."
            )
            return

        action = self._get_fix_action(finding)
        if not action:
            messagebox.showinfo(
                "Remediation",
                f"No hay fix automático seguro para:\n{finding['title']}\n\n"
                f"Recomendación:\n{finding['recommendation']}"
            )
            return

        cmd, msg = action
        confirm = messagebox.askyesno(
            "Confirmar fix",
            f"¿Quieres resolver este hallazgo ahora?\n\n{finding['title']}\n\nComando:\n{cmd}"
        )
        if not confirm:
            return

        try:
            encoded_cmd = base64.b64encode(cmd.encode("utf-16le")).decode("ascii")
            runner = (
                "$isAdmin = ([Security.Principal.WindowsPrincipal] "
                "[Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("
                "[Security.Principal.WindowsBuiltInRole]::Administrator); "
                f"$payload = '{encoded_cmd}'; "
                "if (-not $isAdmin) { "
                "Start-Process powershell -Verb RunAs -ArgumentList @("
                "'-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$payload"
                ") -Wait; "
                "if ($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 0 } "
                "} "
                "$decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($payload)); "
                "& ([ScriptBlock]::Create($decoded))"
            )

            result = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", runner],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self._append_fix_history(finding, cmd, True, result.stdout)
                messagebox.showinfo("Fix aplicado", msg)
                if not self.is_scanning:
                    self.start_scan()
            else:
                stderr = (result.stderr or "").strip()
                stdout = (result.stdout or "").strip()
                error_msg = stderr or stdout or "Error desconocido."
                self._append_fix_history(finding, cmd, False, error_msg)
                messagebox.showerror("Error", f"No se pudo aplicar:\n{error_msg}")
        except Exception as e:
            self._append_fix_history(finding, cmd, False, str(e))
            messagebox.showerror("Error", str(e))

    # ─── SYSTEM INFO PANEL ───
    def _update_info_panel(self):
        for w in self.info_frame.winfo_children():
            w.destroy()

        info = self.system_info
        if not info:
            tk.Label(self.info_frame, text="Sin datos",
                     bg=self.t["BG_PANEL"], fg=self.t["TEXT_SEC"],
                     font=("Consolas", 10)).pack(padx=20, pady=20)
            return

        fields = [
            ("Hostname",         info.get("hostname", "—")),
            ("Sistema Operativo",info.get("os", "—")),
            ("Versión",          info.get("version", "—")),
            ("Arquitectura",     info.get("arch", "—")),
            ("Último arranque",  info.get("last_boot", "—")),
            ("Fecha de escaneo", info.get("scan_time", "—")),
        ]
        for label, val in fields:
            row = tk.Frame(self.info_frame, bg=self.t["BG_PANEL"])
            row.pack(fill="x", padx=20, pady=4)
            tk.Label(row, text=f"{label}:", bg=self.t["BG_PANEL"],
                     fg=self.t["TEXT_SEC"], font=("Consolas", 9, "bold"),
                     width=22, anchor="w").pack(side="left")
            tk.Label(row, text=val, bg=self.t["BG_PANEL"],
                     fg=self.t["TEXT_PRI"], font=("Consolas", 10)).pack(side="left")

    # ─── HISTORY ───
    def _append_fix_history(self, finding, command, success, output):
        entry = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "title": finding.get("title", ""),
            "severity": finding.get("severity", ""),
            "command": command,
            "success": bool(success),
            "output": (output or "")[:1500],
            "user": os.getenv("USERNAME", "unknown"),
        }
        try:
            with FIX_HISTORY_FILE.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            self.logger.error(f"No se pudo escribir fix_history.jsonl: {e}")

    def export_fix_log(self):
        if not FIX_HISTORY_FILE.exists():
            messagebox.showinfo("Fix Log", "Aun no hay fixes registrados.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".jsonl",
            filetypes=[("JSON Lines", "*.jsonl"), ("TXT", "*.txt")]
        )
        if not path:
            return
        try:
            content = FIX_HISTORY_FILE.read_text(encoding="utf-8")
            Path(path).write_text(content, encoding="utf-8")
            messagebox.showinfo("Fix Log", f"Bitacora exportada:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _save_history(self, score, findings):
        history = []
        if HISTORY_FILE.exists():
            try:
                history = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
            except Exception:
                history = []

        entry = {
            "date":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "score":    score,
            "total":    len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high":     sum(1 for f in findings if f["severity"] == "high"),
        }
        history.insert(0, entry)
        history = history[:50]  # keep last 50

        HISTORY_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")

    def _load_history_ui(self):
        for w in self.history_frame.winfo_children():
            w.destroy()

        history = []
        if HISTORY_FILE.exists():
            try:
                history = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass

        if not history:
            tk.Label(self.history_frame, text="\n  Sin historial todavía.\n",
                     bg=self.t["BG_PANEL"], fg=self.t["TEXT_SEC"],
                     font=("Consolas", 10)).pack(anchor="w", padx=14)
            return

        # header
        cols = [("FECHA", 200), ("SCORE", 80), ("HALLAZGOS", 100),
                ("CRÍTICOS", 90), ("ALTOS", 80)]
        hdr = tk.Frame(self.history_frame, bg=self.t["BG_HOVER"])
        hdr.pack(fill="x")
        for col, w in cols:
            tk.Label(hdr, text=col, bg=self.t["BG_HOVER"], fg=self.t["TEXT_SEC"],
                     font=("Consolas", 8, "bold"), width=w // 8,
                     anchor="w").pack(side="left", padx=8, pady=6)

        for i, entry in enumerate(history):
            bg = self.t["BG_PANEL"] if i % 2 == 0 else self.t["BG_CARD"]
            row = tk.Frame(self.history_frame, bg=bg)
            row.pack(fill="x")

            score_color = (self.t["GREEN"] if entry["score"] <= 30
                           else self.t["YELLOW"] if entry["score"] <= 60
                           else self.t["RED"])
            vals = [
                (entry["date"],             self.t["TEXT_PRI"]),
                (f"{entry['score']}%",      score_color),
                (str(entry["total"]),       self.t["TEXT_PRI"]),
                (str(entry["critical"]),    "#ff3b5c"),
                (str(entry["high"]),        "#ff6b35"),
            ]
            for val, color in vals:
                tk.Label(row, text=val, bg=bg, fg=color,
                         font=("Consolas", 10), width=12,
                         anchor="w").pack(side="left", padx=8, pady=5)

    def _clear_history(self):
        if messagebox.askyesno("Limpiar historial", "¿Eliminar todo el historial?"):
            if HISTORY_FILE.exists():
                HISTORY_FILE.unlink()
            self._load_history_ui()

    # ─── SCHEDULE ───
    def _apply_schedule(self):
        if self._schedule_job:
            self.root.after_cancel(self._schedule_job)
            self._schedule_job = None

        opt = self.schedule_var.get()
        intervals = {"30 min": 30 * 60 * 1000,
                     "1 hora": 60 * 60 * 1000,
                     "6 horas": 6 * 60 * 60 * 1000}
        if opt in intervals:
            self._schedule_job = self.root.after(intervals[opt], self._scheduled_scan)

    def _scheduled_scan(self):
        if not self.is_scanning:
            self.start_scan()
        # re-schedule
        self._apply_schedule()

    # ─── NOTIFICATION ───
    def _notify(self, msg, counts):
        """Toast nativo de Windows."""
        try:
            script = (
                f'Add-Type -AssemblyName System.Windows.Forms; '
                f'$n = New-Object System.Windows.Forms.NotifyIcon; '
                f'$n.Icon = [System.Drawing.SystemIcons]::Shield; '
                f'$n.Visible = $true; '
                f'$n.ShowBalloonTip(4000, "Windows Vuln Scanner", "{msg}", '
                f'[System.Windows.Forms.ToolTipIcon]::Warning); '
                f'Start-Sleep -s 5; $n.Dispose()'
            )
            subprocess.Popen(
                ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", script],
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
        except Exception:
            pass  # notificaciones no críticas

    # ─── EXPORT ───
    def export_report(self, fmt="html"):
        if not self.findings_all:
            messagebox.showinfo("Export", "No hay hallazgos. Ejecuta un escaneo primero.")
            return

        ext_map = {"html": ".html", "json": ".json", "txt": ".txt"}
        ft_map  = {"html": [("HTML", "*.html")],
                   "json": [("JSON", "*.json")],
                   "txt":  [("TXT",  "*.txt")]}

        path = filedialog.asksaveasfilename(
            defaultextension=ext_map[fmt],
            filetypes=ft_map[fmt])
        if not path:
            return

        si = self.system_info or {}
        try:
            if fmt == "html":
                export_html(self.findings_all, self.last_score, si, path)
            elif fmt == "json":
                export_json(self.findings_all, self.last_score, si, path)
            else:
                export_txt(self.findings_all, self.last_score, si, path)

            if fmt == "html" and messagebox.askyesno("Reporte HTML",
                                                     f"Reporte guardado.\n¿Abrir en el navegador?"):
                os.startfile(path)
            else:
                messagebox.showinfo("Export", f"Reporte guardado:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ─── CLEAR ALL ───
    def clear_all(self):
        self.findings_all = []
        self.last_score   = 0
        self._clear_findings_ui()
        self._show_empty()
        self.card_score.update("—", self.t["RED"])
        self.card_critical.update("0", "#ff3b5c")
        self.card_high.update("0", "#ff6b35")
        self.card_medium.update("0", self.t["YELLOW"])
        self.card_low.update("0", self.t["GREEN"])
        self.card_status.update("LISTO", self.t["ACCENT"])
        self.chart.draw({})
        self._draw_bar(0)
        self.progress_lbl.config(text="")
        self.progress_pct.config(text="")
        self.count_lbl.config(text="")
        for lbl in self._step_labels.values():
            lbl.config(fg=self.t["TEXT_SEC"], bg=self.t["BG_DEEP"])

    # ─── THEME TOGGLE ───
    def toggle_theme(self):
        new = "light" if self.theme_name.get() == "dark" else "dark"
        self.theme_name.set(new)
        self.t = THEMES[new]
        # rebuild UI
        for w in self.root.winfo_children():
            w.destroy()
        self.root.configure(bg=self.t["BG_DEEP"])
        self._build()


# ─────────────────────────────────────────────
def run_app():
    root = tk.Tk()
    app = WindowsSecurityAuditorUI(root)
    root.mainloop()
