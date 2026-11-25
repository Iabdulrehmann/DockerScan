"""
desktop_app.py
--------------
DockerScan desktop GUI (CustomTkinter). The scan runs in a background thread
and talks to the UI through a queue, so the window never freezes.
Built by Muhammad Abdul Rehman.
"""
import datetime
import os
import sys
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

import allowlist as allowlist_mod
import report_generator
import vulnerability_checker
from config_checker import SEVERITY_ORDER
from scanner import DockerImageScanner, ScanCancelled, ScanError

APP, AUTHOR, VERSION = "DockerScan", "Muhammad Abdul Rehman", "1.0"
C = {"bg": "#050816", "panel": "#0a1029", "card": "#0f1838", "card2": "#141f4a", "border": "#1f2f6b",
     "cyan": "#00e5ff", "purple": "#a855f7", "blue": "#3b82f6", "text": "#e6edff", "muted": "#8a97c4"}
SEV = {"Critical": "#ff2e63", "High": "#ff7a1a", "Medium": "#ffd300", "Low": "#3ddc97", "Informational": "#5aa9ff"}
SEV_ICON = {"Critical": "🔥", "High": "🚨", "Medium": "⚠️", "Low": "🟢", "Informational": "ℹ️"}
FONT, MONO = "Segoe UI", "Consolas"


class DockerScanApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        self.title(f"{APP} — by {AUTHOR}")
        self.geometry("1360x840")
        self.minsize(1120, 720)
        self.configure(fg_color=C["bg"])
        self._set_icon()

        self.result, self.history, self.filtered = None, [], []
        self.image_path, self.db_path = "", vulnerability_checker.default_db_path()
        self.allowlist_path, self.config_path, self.asked_config = "", "", False
        self.diff_old = self.diff_new = None
        self.q, self.cancel, self.scanning, self.spin = queue.Queue(), threading.Event(), False, 0
        self.pages, self.nav = {}, {}

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self._style_tree()
        self._build_header()
        self._build_sidebar()
        self._build_dashboard()
        self._build_findings()
        self._build_tables()
        self._build_diff()
        self._build_about()
        self.show_page("Dashboard")
        self.after(100, self._poll)
        self._pulse(True)

    def _set_icon(self):
        """Cricket-bat icon for the window and taskbar (CustomTkinter resets it, so apply again later)."""
        base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        ico, png = os.path.join(base, "icon.ico"), os.path.join(base, "icon.png")

        def apply():
            try:
                if sys.platform.startswith("win") and os.path.exists(ico):
                    self.iconbitmap(ico)
                elif os.path.exists(png):
                    self._icon_img = tk.PhotoImage(file=png)
                    self.iconphoto(True, self._icon_img)
            except tk.TclError:
                pass                                   # a missing icon must never stop the app
        apply()
        self.after(300, apply)

    # ------------------------------------------------------------ building UI
    def _style_tree(self):
        st = ttk.Style(self)
        st.theme_use("clam")
        st.configure("Treeview", background=C["card"], fieldbackground=C["card"], foreground=C["text"],
                     rowheight=28, borderwidth=0, font=(FONT, 10))
        st.configure("Treeview.Heading", background=C["panel"], foreground=C["cyan"], relief="flat",
                     font=(FONT, 10, "bold"))
        st.map("Treeview", background=[("selected", C["purple"])], foreground=[("selected", "#ffffff")])
        st.map("Treeview.Heading", background=[("active", C["card2"])])
        st.configure("Vertical.TScrollbar", background=C["card2"], troughcolor=C["card"], borderwidth=0,
                     arrowcolor=C["cyan"])

    def _build_header(self):
        h = ctk.CTkFrame(self, height=74, corner_radius=0, fg_color=C["panel"], border_width=0)
        h.grid(row=0, column=0, columnspan=2, sticky="ew")
        h.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(h, text="🏏 DockerScan", font=(FONT, 28, "bold"), text_color=C["cyan"]
                     ).grid(row=0, column=0, rowspan=2, padx=(24, 20), pady=8)
        ctk.CTkLabel(h, text=f"🚀 Built by {AUTHOR}", font=(FONT, 13, "bold"), text_color=C["text"]
                     ).grid(row=0, column=1, sticky="sw", pady=(14, 0))
        ctk.CTkLabel(h, text="Offline Docker image security scanner", font=(FONT, 11),
                     text_color=C["muted"]).grid(row=1, column=1, sticky="nw")
        self.tagline = ctk.CTkLabel(h, text="⚡ Stay Curious, Stay Secure", font=(FONT, 14, "bold"),
                                    text_color=C["purple"])
        self.tagline.grid(row=0, column=2, rowspan=2, padx=24)
        ctk.CTkFrame(self, height=2, fg_color=C["cyan"], corner_radius=0).grid(row=0, column=0, columnspan=2, sticky="sew")

    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=230, corner_radius=0, fg_color=C["panel"])
        sb.grid(row=1, column=0, sticky="nsw")
        sb.grid_propagate(False)
        ctk.CTkLabel(sb, text="COMMAND CENTER", font=(FONT, 11, "bold"), text_color=C["muted"]
                     ).pack(anchor="w", padx=22, pady=(22, 8))
        for name, icon in [("Dashboard", "📊"), ("Findings", "🔍"), ("Packages", "🧩"),
                           ("Layers", "📚"), ("History", "🕘"), ("Diff", "🔀"), ("About", "ℹ️")]:
            b = ctk.CTkButton(sb, text=f"  {icon}  {name}", anchor="w", height=42, corner_radius=10,
                              font=(FONT, 14, "bold"), fg_color="transparent", hover_color=C["card2"],
                              text_color=C["text"], command=lambda n=name: self.show_page(n))
            b.pack(fill="x", padx=14, pady=3)
            self.nav[name] = b
        ctk.CTkLabel(sb, text=f"🚀 Built by\n{AUTHOR}", font=(FONT, 12, "bold"), text_color=C["cyan"],
                     justify="left").pack(side="bottom", anchor="w", padx=22, pady=(0, 22))
        ctk.CTkLabel(sb, text="⚡ Stay Curious, Stay Secure", font=(FONT, 10), text_color=C["purple"]
                     ).pack(side="bottom", anchor="w", padx=22, pady=(0, 8))

    def _page(self, name):
        f = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        f.grid(row=1, column=1, sticky="nsew", padx=18, pady=14)
        self.pages[name] = f
        return f

    def _card(self, parent, **kw):
        return ctk.CTkFrame(parent, fg_color=C["card"], corner_radius=14, border_width=1,
                            border_color=C["border"], **kw)

    def _btn(self, parent, text, cmd, color=None, **kw):
        return ctk.CTkButton(parent, text=text, command=cmd, height=38, corner_radius=10,
                             font=(FONT, 13, "bold"), fg_color=color or C["blue"],
                             hover_color=C["purple"], **kw)

    def _tree(self, parent, cols, height=10):
        wrap = tk.Frame(parent, bg=C["card"])
        tree = ttk.Treeview(wrap, columns=[c[0] for c in cols], show="headings", height=height)
        for cid, head, width in cols:
            tree.heading(cid, text=head)
            tree.column(cid, width=width, anchor="w", stretch=(cid == cols[-1][0]))
        sc = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sc.set)
        tree.pack(side="left", fill="both", expand=True)
        sc.pack(side="right", fill="y")
        for s, col in SEV.items():
            tree.tag_configure(s, foreground=col)
        return wrap, tree

    def _textbox(self, parent, **kw):
        return ctk.CTkTextbox(parent, fg_color=C["panel"], text_color=C["text"], font=(MONO, 12),
                              corner_radius=10, border_width=1, border_color=C["border"], **kw)

    # --- dashboard
    def _build_dashboard(self):
        p = self._page("Dashboard")
        p.grid_columnconfigure(0, weight=1)
        p.grid_rowconfigure(3, weight=1)

        ctl = self._card(p)
        ctl.grid(row=0, column=0, sticky="ew")
        ctl.grid_columnconfigure(6, weight=1)
        self._btn(ctl, "📂 Select Image", self.select_image).grid(row=0, column=0, padx=(14, 6), pady=(14, 6))
        self._btn(ctl, "📁 Select Folder", self.select_folder).grid(row=0, column=1, padx=6, pady=(14, 6))
        self.btn_scan = self._btn(ctl, "▶ Start Scan", self.start_scan, "#12b886")
        self.btn_scan.grid(row=0, column=2, padx=6, pady=(14, 6))
        self.btn_cancel = self._btn(ctl, "⏹ Cancel", self.cancel_scan, "#e03131", state="disabled")
        self.btn_cancel.grid(row=0, column=3, padx=6, pady=(14, 6))
        self._btn(ctl, "💾 Export TXT", lambda: self.export("txt"), C["card2"]).grid(row=0, column=4, padx=6, pady=(14, 6))
        self._btn(ctl, "🧾 Export JSON", lambda: self.export("json"), C["card2"]).grid(row=0, column=5, padx=6, pady=(14, 6))
        self._btn(ctl, "🗄️ Vuln DB", self.select_db, C["purple"]).grid(row=1, column=0, padx=(14, 6), pady=(0, 6))
        self._btn(ctl, "🚫 Allowlist", self.select_allowlist, C["purple"]).grid(row=1, column=1, padx=6, pady=(0, 6))
        self.db_lbl = ctk.CTkLabel(ctl, text="", font=(FONT, 11), text_color=C["muted"], anchor="w")
        self.db_lbl.grid(row=1, column=2, columnspan=5, sticky="ew", padx=10, pady=(0, 6))
        self.path_lbl = ctk.CTkLabel(ctl, text="No input selected — choose a docker-save .tar/.tar.gz, or a folder",
                                     font=(FONT, 12), text_color=C["muted"], anchor="w")
        self.path_lbl.grid(row=2, column=0, columnspan=7, sticky="ew", padx=16, pady=(0, 10))
        self._refresh_labels()

        pr = self._card(p)
        pr.grid(row=1, column=0, sticky="ew", pady=10)
        pr.grid_columnconfigure(0, weight=1)
        self.status = ctk.CTkLabel(pr, text="💤 Idle — ready to scan", font=(FONT, 13, "bold"),
                                   text_color=C["cyan"], anchor="w")
        self.status.grid(row=0, column=0, sticky="ew", padx=16, pady=(10, 2))
        self.pct = ctk.CTkLabel(pr, text="0%", font=(FONT, 13, "bold"), text_color=C["text"])
        self.pct.grid(row=0, column=1, padx=16)
        self.bar = ctk.CTkProgressBar(pr, height=12, progress_color=C["cyan"], fg_color=C["panel"])
        self.bar.set(0)
        self.bar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 12))

        cards = ctk.CTkFrame(p, fg_color="transparent")
        cards.grid(row=2, column=0, sticky="ew")
        self.stat = {}
        for i, (key, icon) in enumerate([("Total", "🧮"), ("Critical", "🔥"), ("High", "🚨"),
                                         ("Medium", "⚠️"), ("Low", "🟢"), ("Informational", "ℹ️")]):
            cards.grid_columnconfigure(i, weight=1, uniform="s")
            c = self._card(cards)
            c.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 6, 0))
            col = C["cyan"] if key == "Total" else SEV[key]
            ctk.CTkLabel(c, text=f"{icon} {key}", font=(FONT, 12, "bold"), text_color=C["muted"]
                         ).pack(anchor="w", padx=14, pady=(10, 0))
            v = ctk.CTkLabel(c, text="0", font=(FONT, 34, "bold"), text_color=col)
            v.pack(anchor="w", padx=14, pady=(0, 8))
            self.stat[key] = v

        bottom = ctk.CTkFrame(p, fg_color="transparent")
        bottom.grid(row=3, column=0, sticky="nsew", pady=(10, 0))
        bottom.grid_columnconfigure((0, 1), weight=1, uniform="b")
        bottom.grid_rowconfigure(0, weight=1)
        for col, title, attr in [(0, "🖼️ Image information", "img_box"), (1, "📚 Layer information", "layer_box")]:
            c = self._card(bottom)
            c.grid(row=0, column=col, sticky="nsew", padx=(0, 6) if col == 0 else (6, 0))
            ctk.CTkLabel(c, text=title, font=(FONT, 14, "bold"), text_color=C["cyan"]).pack(anchor="w", padx=14, pady=(10, 4))
            box = self._textbox(c)
            box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
            setattr(self, attr, box)
            self._set(box, "Run a scan to see details here.")

    # --- findings
    def _build_findings(self):
        p = self._page("Findings")
        p.grid_columnconfigure(0, weight=1)
        p.grid_rowconfigure(1, weight=3)
        p.grid_rowconfigure(2, weight=2)
        bar = self._card(p)
        bar.grid(row=0, column=0, sticky="ew")
        bar.grid_columnconfigure(0, weight=1)
        self.search = ctk.CTkEntry(bar, placeholder_text="🔎 Search findings (title, file, category, description)...",
                                   height=38, fg_color=C["panel"], border_color=C["border"], font=(FONT, 13))
        self.search.grid(row=0, column=0, sticky="ew", padx=14, pady=12)
        self.search.bind("<KeyRelease>", lambda e: self.refresh_findings())
        self.sev_filter = ctk.CTkOptionMenu(bar, values=["All severities"] + SEVERITY_ORDER + ["Suppressed (allowlist)"], width=200, height=38,
                                            fg_color=C["card2"], button_color=C["purple"], font=(FONT, 13),
                                            command=lambda v: self.refresh_findings())
        self.sev_filter.grid(row=0, column=1, padx=6)
        self.count_lbl = ctk.CTkLabel(bar, text="0 shown", font=(FONT, 12, "bold"), text_color=C["cyan"])
        self.count_lbl.grid(row=0, column=2, padx=14)

        wrap, self.ftree = self._tree(p, [("id", "ID", 80), ("sev", "Severity", 120), ("cat", "Category", 120),
                                          ("title", "Title", 420), ("loc", "Affected file / layer", 360)])
        wrap.grid(row=1, column=0, sticky="nsew", pady=10)
        self.ftree.bind("<<TreeviewSelect>>", self._on_finding)

        d = self._card(p)
        d.grid(row=2, column=0, sticky="nsew")
        d.grid_columnconfigure(0, weight=1)
        d.grid_rowconfigure(1, weight=1)
        top = ctk.CTkFrame(d, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 4))
        self.d_sev = ctk.CTkLabel(top, text="  —  ", corner_radius=8, fg_color=C["card2"], font=(FONT, 12, "bold"))
        self.d_sev.pack(side="left")
        self.d_title = ctk.CTkLabel(top, text="Select a finding to see details", font=(FONT, 15, "bold"),
                                    text_color=C["text"], anchor="w")
        self.d_title.pack(side="left", padx=12)
        self.d_body = self._textbox(d, wrap="word")
        self.d_body.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.d_body.tag_config("h", foreground=C["cyan"])

    # --- packages / layers / history
    def _build_tables(self):
        p = self._page("Packages")
        p.grid_columnconfigure(0, weight=1)
        p.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(p, text="🧩 Installed packages", font=(FONT, 20, "bold"), text_color=C["cyan"]
                     ).grid(row=0, column=0, sticky="w", pady=(0, 8))
        w, self.ptree = self._tree(p, [("n", "Package", 260), ("v", "Version", 220), ("s", "Source", 80),
                                       ("l", "Layer", 70), ("x", "Known vulnerabilities", 260)], 20)
        w.grid(row=1, column=0, sticky="nsew")

        p = self._page("Layers")
        p.grid_columnconfigure(0, weight=1)
        p.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(p, text="📚 Image layers", font=(FONT, 20, "bold"), text_color=C["cyan"]
                     ).grid(row=0, column=0, sticky="w", pady=(0, 8))
        w, self.ltree = self._tree(p, [("i", "#", 50), ("id", "Layer ID", 220), ("f", "Files", 90),
                                       ("s", "Size", 100), ("c", "Created by (build command)", 600)], 20)
        w.grid(row=1, column=0, sticky="nsew")

        p = self._page("History")
        p.grid_columnconfigure(0, weight=1)
        p.grid_rowconfigure(2, weight=1)
        ctk.CTkLabel(p, text="🕘 Scans in this session", font=(FONT, 20, "bold"), text_color=C["cyan"]
                     ).grid(row=0, column=0, sticky="w", pady=(0, 8))
        row = ctk.CTkFrame(p, fg_color="transparent")
        row.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self._btn(row, "📂 Load selected scan", self.load_history).pack(side="left")
        ctk.CTkLabel(row, text="  History is kept until you close the app.", text_color=C["muted"],
                     font=(FONT, 12)).pack(side="left")
        w, self.htree = self._tree(p, [("t", "Time", 160), ("im", "Image", 360), ("tot", "Total", 70),
                                       ("c", "Critical", 70), ("h", "High", 70), ("m", "Medium", 70)], 20)
        w.grid(row=2, column=0, sticky="nsew")
        self.htree.bind("<Double-1>", lambda e: self.load_history())

    def _build_diff(self):
        p = self._page("Diff")
        p.grid_columnconfigure(0, weight=1)
        p.grid_rowconfigure(3, weight=1)
        ctk.CTkLabel(p, text="🔀 Compare two scans of the same image", font=(FONT, 20, "bold"),
                     text_color=C["cyan"]).grid(row=0, column=0, sticky="w", pady=(0, 8))
        card = self._card(p)
        card.grid(row=1, column=0, sticky="ew")
        self._btn(card, "📄 Old report (JSON)", lambda: self.diff_pick("old")).grid(row=0, column=0, padx=(14, 6), pady=(14, 4))
        self._btn(card, "📄 New report (JSON)", lambda: self.diff_pick("new")).grid(row=0, column=1, padx=6, pady=(14, 4))
        self._btn(card, "📌 Use current scan as New", self.diff_use_current, C["purple"]).grid(row=0, column=2, padx=6, pady=(14, 4))
        self._btn(card, "🔀 Compare", self.diff_compare, "#12b886").grid(row=0, column=3, padx=6, pady=(14, 4))
        self.diff_old_lbl = ctk.CTkLabel(card, text="Old: (none)", font=(FONT, 12), text_color=C["muted"], anchor="w")
        self.diff_old_lbl.grid(row=1, column=0, columnspan=4, sticky="ew", padx=16)
        self.diff_new_lbl = ctk.CTkLabel(card, text="New: (none)", font=(FONT, 12), text_color=C["muted"], anchor="w")
        self.diff_new_lbl.grid(row=2, column=0, columnspan=4, sticky="ew", padx=16, pady=(0, 10))
        self.diff_sum = ctk.CTkLabel(p, text="Pick two JSON reports (exported from DockerScan) and press Compare. "
                                     "Only NEW and FIXED findings are shown.", font=(FONT, 13, "bold"),
                                     text_color=C["text"], anchor="w")
        self.diff_sum.grid(row=2, column=0, sticky="ew", pady=8)
        w, self.dtree = self._tree(p, [("c", "Change", 100), ("sev", "Severity", 120), ("t", "Title", 430),
                                       ("l", "Location", 380)], 18)
        w.grid(row=3, column=0, sticky="nsew")

    def _build_about(self):
        p = self._page("About")
        c = self._card(p)
        c.pack(fill="both", expand=True)
        ctk.CTkLabel(c, text="🏏 DockerScan", font=(FONT, 40, "bold"), text_color=C["cyan"]).pack(pady=(40, 4))
        ctk.CTkLabel(c, text=f"Version {VERSION}", font=(FONT, 13), text_color=C["muted"]).pack()
        ctk.CTkLabel(c, text=f"🚀 Built by {AUTHOR}", font=(FONT, 20, "bold"), text_color=C["purple"]).pack(pady=14)
        ctk.CTkLabel(c, text="⚡ Stay Curious, Stay Secure", font=(FONT, 16, "bold"), text_color=C["text"]).pack()
        ctk.CTkLabel(c, justify="center", font=(FONT, 13), text_color=C["muted"], text=(
            "\nDockerScan inspects Docker image archives (docker save) completely offline.\n\n"
            "🔐 Hardcoded secrets (regex + entropy)     🧩 Packages (dpkg, apk, rpm, pip) + layer attribution\n"
            "🗄️ Local vulnerability database     ⚙️ Root, ports, healthcheck, setuid     🚫 Allowlist     🔀 Diff\n"
            "📁 Reads docker-save tarballs, unpacked folders and plain filesystem folders\n\n"
            "🛑 Safety: the image is only READ inside memory — it is never extracted to disk or executed.\n"
            "📴 No network connection is used.")).pack(pady=10)

    # ---------------------------------------------------------------- helpers
    def show_page(self, name):
        self.pages[name].tkraise()
        for n, b in self.nav.items():
            b.configure(fg_color=C["card2"] if n == name else "transparent",
                        text_color=C["cyan"] if n == name else C["text"])

    def _set(self, box, text):
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", text)
        box.configure(state="disabled")

    def _pulse(self, flag):
        self.tagline.configure(text_color=C["purple"] if flag else C["cyan"])
        self.after(1000, lambda: self._pulse(not flag))

    def _count_up(self, label, target, step=0):
        steps = 12
        label.configure(text=str(int(target * min(step, steps) / steps)))
        if step < steps:
            self.after(30, lambda: self._count_up(label, target, step + 1))

    # ---------------------------------------------------------------- actions
    def _refresh_labels(self):
        db = os.path.basename(self.db_path) + (" (bundled sample)" if self.db_path == vulnerability_checker.default_db_path()
                                               else " (custom)")
        al = os.path.basename(self.allowlist_path) if self.allowlist_path else "none"
        self.db_lbl.configure(text=f"🗄️ DB: {db}     🚫 Allowlist: {al}")

    def _set_input(self, path, icon):
        self.image_path, self.config_path, self.asked_config = path, "", False
        self.path_lbl.configure(text=f"{icon} {path}", text_color=C["text"])

    def select_image(self):
        path = filedialog.askopenfilename(title="Select Docker image archive", filetypes=[
            ("Docker image archives", "*.tar *.tar.gz *.tgz"), ("All files", "*.*")])
        if path:
            self._set_input(path, "📦")

    def select_folder(self):
        path = filedialog.askdirectory(title="Select an unpacked image folder or a filesystem folder")
        if path:
            self._set_input(path, "📁")

    def select_allowlist(self):
        path = filedialog.askopenfilename(title="Select allowlist (JSON)",
                                          filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            allowlist_mod.load_allowlist(path)                   # validate before accepting
        except (ValueError, OSError) as e:
            messagebox.showerror("Invalid allowlist", f"Could not use this allowlist:\n\n{e}")
            return
        self.allowlist_path = path
        self._refresh_labels()

    def select_db(self):
        path = filedialog.askopenfilename(title="Select vulnerability database (JSON)",
                                          filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            vulnerability_checker.load_db(path)              # validate before accepting
        except (ValueError, OSError) as e:
            messagebox.showerror("Invalid database", f"Could not use this database:\n\n{e}")
            return
        self.db_path = path
        self._refresh_labels()

    def start_scan(self):
        if self.scanning:
            return
        if not self.image_path:
            messagebox.showwarning("No input selected", "Click 'Select Image' (a .tar / .tar.gz) or 'Select Folder' first.")
            return
        if (os.path.isdir(self.image_path) and not os.path.isfile(os.path.join(self.image_path, "manifest.json"))
                and not self.config_path and not self.asked_config):
            self.asked_config = True                              # ask only once per selection
            if messagebox.askyesno("Image config (optional)", "This folder is a plain filesystem, so it carries no image "
                                   "configuration (user, ports, healthcheck).\n\nChoose the image config JSON now?"):
                cfg = filedialog.askopenfilename(title="Select image config JSON",
                                                 filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
                if cfg:
                    self.config_path = cfg
        self.scanning = True
        self.cancel.clear()
        self.btn_scan.configure(state="disabled")
        self.btn_cancel.configure(state="normal")
        self.bar.set(0)
        threading.Thread(target=self._worker, args=(self.image_path, self.db_path, self.allowlist_path, self.config_path),
                         daemon=True).start()

    def _worker(self, path, db, allow, cfg):
        """Runs in a background thread; results go back through the queue."""
        try:
            sc = DockerImageScanner(db, lambda pct, msg: self.q.put(("progress", pct, msg)), self.cancel,
                                    allow or None, cfg or None)
            self.q.put(("done", sc.scan(path)))
        except ScanCancelled:
            self.q.put(("cancelled",))
        except ScanError as e:
            self.q.put(("error", str(e)))
        except Exception as e:                                # never let the thread die silently
            self.q.put(("error", f"Unexpected error: {type(e).__name__}: {e}"))

    def cancel_scan(self):
        if self.scanning:
            self.cancel.set()
            self.status.configure(text="⏹ Cancelling...")

    def _poll(self):
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    self.bar.set(msg[1] / 100)
                    self.pct.configure(text=f"{msg[1]}%")
                    self._last_msg = msg[2]
                elif kind == "done":
                    self._finish()
                    self._load_result(msg[1])
                    self.history.insert(0, msg[1])
                    self._refresh_history()
                    sm = msg[1]["summary"]
                    self.status.configure(text=f"✅ Scan complete — {sm['Total']} findings "
                                               f"({sm.get('Suppressed', 0)} suppressed) in {msg[1]['duration_seconds']} s")
                elif kind == "cancelled":
                    self._finish()
                    self.bar.set(0)
                    self.pct.configure(text="0%")
                    self.status.configure(text="⏹ Scan cancelled")
                elif kind == "error":
                    self._finish()
                    self.bar.set(0)
                    self.pct.configure(text="0%")
                    self.status.configure(text="❌ Scan failed")
                    messagebox.showerror("Scan failed", msg[1])
        except queue.Empty:
            pass
        if self.scanning and not self.cancel.is_set():
            self.spin = (self.spin + 1) % 4
            self.status.configure(text=f"{'⠋⠙⠹⠸'[self.spin]} {getattr(self, '_last_msg', 'Starting...')}")
        self.after(120, self._poll)

    def _finish(self):
        self.scanning = False
        self.btn_scan.configure(state="normal")
        self.btn_cancel.configure(state="disabled")

    def _load_result(self, r):
        """Fill every page with a scan result."""
        self.result = r
        for key, lbl in self.stat.items():
            self._count_up(lbl, r["summary"][key])
        im = r["image"]
        self._set(self.img_box, "\n".join([
            f"Tags        : {', '.join(im['tags']) or 'n/a'}", f"OS          : {im['os_name']}",
            f"Platform    : {im['platform']}", f"Created     : {im['created']}",
            f"Input type  : {im.get('input_type', 'image')}",
            f"Archive size: {report_generator.format_size(im['archive_size']) if im['archive_size'] else 'n/a'}",
            f"User        : {im['user']}", f"Entrypoint  : {' '.join(im['entrypoint']) or 'n/a'}",
            f"Cmd         : {' '.join(im['cmd']) or 'n/a'}", f"ENV vars    : {im['env_count']}",
            f"Ports       : {', '.join(im['exposed_ports']) or 'none'}",
            f"Healthcheck : {'yes' if im['healthcheck'] else 'NO'}", f"Packages    : {len(r['packages'])}"]))
        self._set(self.layer_box, "\n".join(
            f"#{l['index']}  {l['id'][:12]}  {l['files']} files  {report_generator.format_size(l['size'])}\n"
            f"    {l['created_by'][:70] or '(no command info)'}" for l in r["layers"]) or "No layers (plain filesystem folder).")
        self.refresh_findings()
        for t in (self.ptree, self.ltree):
            t.delete(*t.get_children())
        for pk in sorted(r["packages"], key=lambda x: (-len(x["vulnerabilities"]), x["name"])):
            self.ptree.insert("", "end", values=(pk["name"], pk["version"], pk["source"], pk.get("layer") or "—",
                              ", ".join(pk["vulnerabilities"]) or "—"),
                              tags=("High",) if pk["vulnerabilities"] else ())
        for l in r["layers"]:
            self.ltree.insert("", "end", values=(l["index"], l["id"][:24], l["files"],
                              report_generator.format_size(l["size"]), l["created_by"]))

    def refresh_findings(self):
        self.ftree.delete(*self.ftree.get_children())
        self.filtered = []
        if not self.result:
            self.count_lbl.configure(text="0 shown")
            return
        q, sev = self.search.get().strip().lower(), self.sev_filter.get()
        shown_suppressed = sev == "Suppressed (allowlist)"
        for f in (self.result.get("suppressed", []) if shown_suppressed else self.result["findings"]):
            if sev not in ("All severities", "Suppressed (allowlist)") and f["severity"] != sev:
                continue
            if q and q not in " ".join((f["title"], f["location"], f["category"], f["description"], f["id"])).lower():
                continue
            self.filtered.append(f)
            self.ftree.insert("", "end", iid=f["id"], tags=(f["severity"],),
                              values=(f["id"], f"{SEV_ICON[f['severity']]} {f['severity']}", f["category"],
                                      f["title"], f["location"]))
        self.count_lbl.configure(text=f"{len(self.filtered)} shown")

    def _on_finding(self, _event):
        sel = self.ftree.selection()
        f = next((x for x in self.filtered if sel and x["id"] == sel[0]), None)
        if not f:
            return
        self.d_title.configure(text=f["title"])
        self.d_sev.configure(text=f"  {f['severity'].upper()}  ", fg_color=SEV[f["severity"]], text_color="#000000")
        b = self.d_body
        b.configure(state="normal")
        b.delete("1.0", "end")
        sections = [("📄 Description", f["description"]), ("📍 Affected file / layer", f["location"])]
        if f.get("layer"):
            cmd = next((l["created_by"] for l in self.result["layers"] if l["index"] == f["layer"]), "")
            sections.append(("🧬 Introduced in layer", f"#{f['layer']}  {cmd.strip()[:120]}"))
        sections += [("⚠️ Risk explanation", f["risk"]), ("🛠️ Recommended fix", f["fix"])]
        if f.get("suppressed_by"):
            sections.append(("🚫 Suppressed by allowlist", f["suppressed_by"]))
        for head, text in sections:
            b.insert("end", head + "\n", "h")
            b.insert("end", text + "\n\n")
        b.configure(state="disabled")

    def _refresh_history(self):
        self.htree.delete(*self.htree.get_children())
        for i, r in enumerate(self.history):
            s = r["summary"]
            self.htree.insert("", "end", iid=str(i), values=(
                r["scanned_at"], ", ".join(r["image"]["tags"]) or os.path.basename(r["image"]["archive"]),
                s["Total"], s["Critical"], s["High"], s["Medium"]))

    def load_history(self):
        sel = self.htree.selection()
        if not sel:
            messagebox.showinfo("History", "Select a scan in the list first.")
            return
        self._load_result(self.history[int(sel[0])])
        self.status.configure(text="📂 Loaded a previous scan from this session")
        self.show_page("Dashboard")

    def diff_pick(self, which):
        path = filedialog.askopenfilename(title=f"Select {which} report (JSON)",
                                          filetypes=[("JSON reports", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            data = report_generator.load_report(path)
        except ValueError as e:
            messagebox.showerror("Cannot use this report", str(e))
            return
        label = f"{os.path.basename(path)}  —  {report_generator.image_label(data)}  ({data['scanned_at']})"
        if which == "old":
            self.diff_old = data
            self.diff_old_lbl.configure(text=f"Old: {label}", text_color=C["text"])
        else:
            self.diff_new = data
            self.diff_new_lbl.configure(text=f"New: {label}", text_color=C["text"])

    def diff_use_current(self):
        if not self.result:
            messagebox.showinfo("Diff", "Run a scan first, or load a JSON report as 'New'.")
            return
        self.diff_new = self.result
        self.diff_new_lbl.configure(text=f"New: current scan — {report_generator.image_label(self.result)} "
                                         f"({self.result['scanned_at']})", text_color=C["text"])

    def diff_compare(self):
        if not (self.diff_old and self.diff_new):
            messagebox.showwarning("Diff", "Choose both an Old and a New report first.")
            return
        d = report_generator.diff_results(self.diff_old, self.diff_new)
        self.dtree.delete(*self.dtree.get_children())
        for tag, rows in (("🆕 NEW", d["new"]), ("✅ FIXED", d["fixed"])):
            for f in rows:
                self.dtree.insert("", "end", tags=(f["severity"],),
                                  values=(tag, f"{SEV_ICON[f['severity']]} {f['severity']}", f["title"], f["location"]))
        self.diff_sum.configure(text=f"🆕 {len(d['new'])} new   ✅ {len(d['fixed'])} fixed   "
                                     f"({d['unchanged']} unchanged findings hidden)")

    def export(self, kind):
        if not self.result:
            messagebox.showwarning("Nothing to export", "Run a scan first, then export the report.")
            return
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(title=f"Export {kind.upper()} report", defaultextension=f".{kind}",
                                            initialfile=f"DockerScan_report_{stamp}.{kind}",
                                            filetypes=[(f"{kind.upper()} file", f"*.{kind}")])
        if not path:
            return
        try:
            (report_generator.save_txt if kind == "txt" else report_generator.save_json)(self.result, path)
        except OSError as e:
            messagebox.showerror("Export failed", f"Could not write the file:\n\n{e}")
            return
        messagebox.showinfo("Report saved", f"✅ Report saved to:\n{path}")
