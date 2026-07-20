import csv
import datetime as dt
import difflib
import hashlib
import html
import os
import queue
import socket
import sqlite3
import ssl
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlparse
from urllib.request import Request, urlopen


APP_NAME = "Domain Impersonation Detection System"
DB_FILE = "dids.sqlite3"


HOMOGLYPHS = {
    "a": ["а", "ɑ", "à"],
    "c": ["с", "ċ"],
    "e": ["е", "ė", "è"],
    "i": ["і", "í", "ì"],
    "l": ["1", "і", "ł"],
    "o": ["0", "о", "ò"],
    "p": ["р"],
    "s": ["5", "ѕ"],
}


KEYBOARD_NEIGHBORS = {
    "a": "qwsz",
    "b": "vghn",
    "c": "xdfv",
    "d": "erfcxs",
    "e": "wsdr",
    "f": "rtgvcd",
    "g": "tyhbvf",
    "h": "yujnbg",
    "i": "ujko",
    "l": "kop",
    "m": "njk",
    "n": "bhjm",
    "o": "iklp",
    "p": "ol",
    "r": "edft",
    "s": "wedxza",
    "t": "rfgy",
    "u": "yhji",
    "v": "cfgb",
    "w": "qase",
    "x": "zsdc",
    "y": "tghu",
    "z": "asx",
}


class Database:
    def __init__(self, path=DB_FILE):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.init_schema()
        self.seed()

    def init_schema(self):
        self.conn.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS protected_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                brand TEXT NOT NULL,
                owner TEXT,
                priority TEXT DEFAULT 'Medium',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS detected_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protected_domain_id INTEGER,
                domain TEXT NOT NULL,
                similarity REAL NOT NULL,
                attack_type TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                status TEXT DEFAULT 'New',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                dns_summary TEXT,
                ssl_summary TEXT,
                website_summary TEXT,
                indicators TEXT,
                UNIQUE(protected_domain_id, domain),
                FOREIGN KEY(protected_domain_id) REFERENCES protected_domains(id)
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detected_domain_id INTEGER NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT DEFAULT 'Open',
                created_at TEXT NOT NULL,
                FOREIGN KEY(detected_domain_id) REFERENCES detected_domains(id)
            );

            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detected_domain_id INTEGER NOT NULL,
                assignee TEXT,
                notes TEXT,
                state TEXT DEFAULT 'Open',
                updated_at TEXT NOT NULL,
                FOREIGN KEY(detected_domain_id) REFERENCES detected_domains(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def seed(self):
        count = self.conn.execute("SELECT COUNT(*) FROM protected_domains").fetchone()[0]
        if count:
            return
        now = timestamp()
        self.conn.executemany(
            "INSERT INTO protected_domains(domain, brand, owner, priority, created_at) VALUES(?,?,?,?,?)",
            [
                ("examplebank.com", "Example Bank", "SOC Team", "High", now),
                ("contoso.com", "Contoso", "Brand Protection", "Medium", now),
            ],
        )
        self.log("system", "seed", "Created demo protected domains")
        self.conn.commit()

    def log(self, actor, action, details=""):
        self.conn.execute(
            "INSERT INTO audit_logs(actor, action, details, created_at) VALUES(?,?,?,?)",
            (actor, action, details, timestamp()),
        )
        self.conn.commit()


def timestamp():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_domain(value):
    value = value.strip().lower()
    if "://" in value:
        value = urlparse(value).netloc
    return value.split("/")[0].strip(".")


def split_domain(domain):
    parts = normalize_domain(domain).split(".")
    if len(parts) < 2:
        return domain, ""
    return ".".join(parts[:-1]), parts[-1]


def similarity(a, b):
    return round(difflib.SequenceMatcher(None, normalize_domain(a), normalize_domain(b)).ratio() * 100, 1)


def detect_attack_type(base_domain, candidate):
    base_name, base_tld = split_domain(base_domain)
    cand_name, cand_tld = split_domain(candidate)
    if any(ord(ch) > 127 for ch in candidate):
        return "Homograph"
    if base_tld != cand_tld and base_name == cand_name:
        return "TLD swap"
    if base_name in cand_name and base_name != cand_name:
        return "Brand keyword"
    if abs(len(base_name) - len(cand_name)) == 1:
        return "Missing/added character"
    if len(base_name) == len(cand_name):
        diffs = sum(1 for a, b in zip(base_name, cand_name) if a != b)
        if diffs <= 2:
            return "Keyboard substitution"
    return "Lookalike"


def generate_candidates(domain, limit=90):
    domain = normalize_domain(domain)
    name, tld = split_domain(domain)
    candidates = set()
    tlds = ["com", "net", "org", "co", "io", "biz", "info", "online", "site"]

    for i in range(len(name)):
        candidates.add(name[:i] + name[i + 1 :] + "." + tld)
        candidates.add(name[:i] + name[i] + name[i:] + "." + tld)
        if i < len(name) - 1:
            candidates.add(name[:i] + name[i + 1] + name[i] + name[i + 2 :] + "." + tld)
        for repl in KEYBOARD_NEIGHBORS.get(name[i], "")[:2]:
            candidates.add(name[:i] + repl + name[i + 1 :] + "." + tld)
        for repl in HOMOGLYPHS.get(name[i], [])[:1]:
            candidates.add(name[:i] + repl + name[i + 1 :] + "." + tld)

    for suffix in ["login", "secure", "verify", "support", "portal", "account"]:
        candidates.add(f"{name}-{suffix}.{tld}")
        candidates.add(f"{suffix}-{name}.{tld}")

    for alt_tld in tlds:
        if alt_tld != tld:
            candidates.add(f"{name}.{alt_tld}")

    candidates.discard(domain)
    ordered = sorted(candidates, key=lambda item: (-similarity(domain, item), item))
    return ordered[:limit]


def resolve_dns(domain):
    records = []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
            if family in (socket.AF_INET, socket.AF_INET6):
                records.append(sockaddr[0])
    except OSError as exc:
        return "No A/AAAA records resolved", ["DNS unresolved"]
    unique = sorted(set(records))
    return "A/AAAA: " + ", ".join(unique[:6]), []


def inspect_ssl(domain, timeout=4):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except Exception as exc:
        return f"TLS unavailable: {exc.__class__.__name__}", ["TLS unavailable"]

    issuer = "Unknown issuer"
    for rdn in cert.get("issuer", []):
        for key, value in rdn:
            if key == "organizationName":
                issuer = value
    expires = cert.get("notAfter", "Unknown expiry")
    return f"Issuer: {issuer}; expires: {expires}", []


def inspect_website(domain, timeout=5):
    url = "https://" + domain
    try:
        req = Request(url, headers={"User-Agent": "DIDS Local Analyzer/1.0"})
        with urlopen(req, timeout=timeout) as response:
            body = response.read(120000).decode("utf-8", errors="ignore")
            final_url = response.geturl()
    except Exception as exc:
        return f"Website unavailable: {exc.__class__.__name__}", ["Website unavailable"]

    text = html.unescape(body).lower()
    indicators = []
    if "<form" in text and ("password" in text or "login" in text):
        indicators.append("Login form")
    if any(term in text for term in ["verify your account", "reset password", "security check"]):
        indicators.append("Phishing phrase")
    title = ""
    marker = "<title>"
    if marker in text:
        title = text.split(marker, 1)[1].split("</title>", 1)[0][:80].strip()
    digest = hashlib.sha256(body[:5000].encode("utf-8", errors="ignore")).hexdigest()[:12]
    summary = f"Fetched {final_url}; title: {title or 'untitled'}; content hash: {digest}"
    return summary, indicators


def score_domain(base_domain, candidate, dns_summary, ssl_summary, website_summary, indicators):
    sim = similarity(base_domain, candidate)
    score = 0
    if sim >= 95:
        score += 35
    elif sim >= 88:
        score += 28
    elif sim >= 75:
        score += 18
    else:
        score += 8

    attack_type = detect_attack_type(base_domain, candidate)
    score += {
        "Homograph": 28,
        "Keyboard substitution": 22,
        "Missing/added character": 18,
        "TLD swap": 15,
        "Brand keyword": 20,
        "Lookalike": 12,
    }.get(attack_type, 10)

    if "A/AAAA:" in dns_summary:
        score += 12
    if "Issuer:" in ssl_summary:
        score += 10
    if "Login form" in indicators:
        score += 20
    if "Phishing phrase" in indicators:
        score += 15
    if "Website unavailable" in indicators:
        score -= 5

    return max(1, min(100, score)), attack_type, sim


def severity(score):
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


class DidsApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1220x780")
        self.minsize(1040, 680)
        self.db = Database()
        self.work_queue = queue.Queue()
        self.editing_domain_id = None
        self.configure_style()
        self.build_ui()
        self.refresh_all()
        self.after(200, self.consume_queue)

    def configure_style(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.colors = {
            "bg": "#f5f7f9",
            "panel": "#ffffff",
            "ink": "#1c2630",
            "muted": "#64717f",
            "line": "#d8dee6",
            "accent": "#0f766e",
            "danger": "#b42318",
            "warn": "#b54708",
        }
        self.configure(bg=self.colors["bg"])
        self.style.configure(".", font=("Segoe UI", 10))
        self.style.configure("TFrame", background=self.colors["bg"])
        self.style.configure("Panel.TFrame", background=self.colors["panel"], relief="solid", borderwidth=1)
        self.style.configure("Title.TLabel", background=self.colors["bg"], foreground=self.colors["ink"], font=("Segoe UI", 18, "bold"))
        self.style.configure("Subtle.TLabel", background=self.colors["bg"], foreground=self.colors["muted"])
        self.style.configure("Metric.TLabel", background=self.colors["panel"], foreground=self.colors["ink"], font=("Segoe UI", 22, "bold"))
        self.style.configure("MetricName.TLabel", background=self.colors["panel"], foreground=self.colors["muted"], font=("Segoe UI", 9))
        self.style.configure("Accent.TButton", foreground="#ffffff", background=self.colors["accent"], padding=(12, 7))
        self.style.map("Accent.TButton", background=[("active", "#115e59")])
        self.style.configure("Treeview", rowheight=28, fieldbackground="#ffffff", background="#ffffff")
        self.style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def build_ui(self):
        header = ttk.Frame(self)
        header.pack(fill="x", padx=18, pady=(16, 10))
        ttk.Label(header, text=APP_NAME, style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="Local SOC console", style="Subtle.TLabel").pack(side="left", padx=(14, 0), pady=(7, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=18, pady=(0, 18))

        self.tabs = {}
        for name in ["Dashboard", "Protected Domains", "Scan", "Alerts", "Investigations", "Reports", "Audit Logs"]:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=name)
            self.tabs[name] = frame

        self.build_dashboard()
        self.build_protected_domains()
        self.build_scan()
        self.build_alerts()
        self.build_investigations()
        self.build_reports()
        self.build_audit()

    def panel(self, parent, **pack):
        frame = ttk.Frame(parent, style="Panel.TFrame", padding=12)
        frame.pack(**pack)
        return frame

    def build_dashboard(self):
        tab = self.tabs["Dashboard"]
        metrics = ttk.Frame(tab)
        metrics.pack(fill="x", pady=(8, 12))
        self.metric_labels = {}
        for title in ["Protected", "Detected", "Open Alerts", "Critical Risk"]:
            box = self.panel(metrics, side="left", fill="x", expand=True, padx=5)
            label = ttk.Label(box, text="0", style="Metric.TLabel")
            label.pack(anchor="w")
            ttk.Label(box, text=title.upper(), style="MetricName.TLabel").pack(anchor="w")
            self.metric_labels[title] = label

        content = ttk.Frame(tab)
        content.pack(fill="both", expand=True)
        left = self.panel(content, side="left", fill="both", expand=True, padx=(5, 8))
        right = self.panel(content, side="right", fill="both", expand=True, padx=(8, 5))
        ttk.Label(left, text="Highest Risk Detections", background="#ffffff", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.dashboard_tree = self.make_tree(left, ("Domain", "Brand", "Risk", "Type", "Status"), (220, 130, 70, 150, 90))
        ttk.Label(right, text="Recent Alerts", background="#ffffff", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.recent_alerts_tree = self.make_tree(right, ("Severity", "Title", "Status", "Created"), (90, 260, 90, 150))

    def build_protected_domains(self):
        tab = self.tabs["Protected Domains"]
        form = self.panel(tab, fill="x", pady=(8, 12), padx=5)
        self.domain_var = tk.StringVar()
        self.brand_var = tk.StringVar()
        self.owner_var = tk.StringVar()
        self.priority_var = tk.StringVar(value="High")
        for i, (label, var, width) in enumerate([
            ("Domain", self.domain_var, 24),
            ("Brand", self.brand_var, 24),
            ("Owner", self.owner_var, 20),
        ]):
            ttk.Label(form, text=label, background="#ffffff").grid(row=0, column=i * 2, sticky="w", padx=(0, 5))
            ttk.Entry(form, textvariable=var, width=width).grid(row=0, column=i * 2 + 1, sticky="ew", padx=(0, 12))
        ttk.Label(form, text="Priority", background="#ffffff").grid(row=0, column=6, sticky="w", padx=(0, 5))
        ttk.Combobox(form, textvariable=self.priority_var, values=["High", "Medium", "Low"], width=10, state="readonly").grid(row=0, column=7, padx=(0, 12))
        self.add_domain_button = ttk.Button(form, text="Add Domain", style="Accent.TButton", command=self.add_protected_domain)
        self.add_domain_button.grid(row=0, column=8)
        ttk.Button(form, text="Cancel", command=self.cancel_protected_domain_edit).grid(row=0, column=9, padx=(8, 0))
        self.protected_status_label = ttk.Label(form, text="", style="Subtle.TLabel")
        self.protected_status_label.grid(row=1, column=0, columnspan=10, sticky="w", pady=(8, 0))
        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)

        list_panel = self.panel(tab, fill="both", expand=True, padx=5)
        self.protected_tree = self.make_tree(list_panel, ("ID", "Domain", "Brand", "Owner", "Priority", "Created"), (50, 220, 180, 180, 90, 160))
        self.protected_tree.bind("<<TreeviewSelect>>", self.load_selected_protected_domain)
        buttons = ttk.Frame(list_panel, style="Panel.TFrame")
        buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(buttons, text="Delete Selected", command=self.delete_protected_domain).pack(side="left")

    def build_scan(self):
        tab = self.tabs["Scan"]
        top = self.panel(tab, fill="x", pady=(8, 12), padx=5)
        ttk.Label(top, text="Protected domain", background="#ffffff").grid(row=0, column=0, sticky="w")
        self.scan_domain_var = tk.StringVar()
        self.scan_domain_combo = ttk.Combobox(top, textvariable=self.scan_domain_var, width=36, state="readonly")
        self.scan_domain_combo.grid(row=0, column=1, sticky="ew", padx=(8, 14))
        ttk.Label(top, text="Candidate domains", background="#ffffff").grid(row=1, column=0, sticky="nw", pady=(10, 0))
        self.candidate_text = tk.Text(top, height=5, width=70, wrap="word")
        self.candidate_text.grid(row=1, column=1, sticky="ew", padx=(8, 14), pady=(10, 0))
        button_bar = ttk.Frame(top, style="Panel.TFrame")
        button_bar.grid(row=0, column=2, rowspan=2, sticky="nsew")
        ttk.Button(button_bar, text="Generate Typos", command=self.generate_for_scan).pack(fill="x", pady=(0, 8))
        ttk.Button(button_bar, text="Run Scan", style="Accent.TButton", command=self.run_scan).pack(fill="x", pady=(0, 8))
        ttk.Button(button_bar, text="Import CSV", command=self.import_candidates).pack(fill="x")
        top.columnconfigure(1, weight=1)

        self.scan_status = ttk.Label(tab, text="Ready", style="Subtle.TLabel")
        self.scan_status.pack(anchor="w", padx=8)
        results = self.panel(tab, fill="both", expand=True, padx=5, pady=(8, 0))
        self.scan_tree = self.make_tree(results, ("Domain", "Risk", "Severity", "Type", "Similarity", "Indicators"), (240, 70, 90, 150, 90, 330))

    def build_alerts(self):
        tab = self.tabs["Alerts"]
        panel = self.panel(tab, fill="both", expand=True, padx=5, pady=(8, 0))
        self.alerts_tree = self.make_tree(panel, ("ID", "Severity", "Title", "Status", "Created"), (50, 90, 420, 90, 160))
        bar = ttk.Frame(panel, style="Panel.TFrame")
        bar.pack(fill="x", pady=(8, 0))
        ttk.Button(bar, text="Acknowledge", command=lambda: self.update_alert_status("Acknowledged")).pack(side="left", padx=(0, 8))
        ttk.Button(bar, text="Close", command=lambda: self.update_alert_status("Closed")).pack(side="left")

    def build_investigations(self):
        tab = self.tabs["Investigations"]
        split = ttk.Frame(tab)
        split.pack(fill="both", expand=True, padx=5, pady=(8, 0))
        left = self.panel(split, side="left", fill="both", expand=True, padx=(0, 8))
        right = self.panel(split, side="right", fill="both", expand=True, padx=(8, 0))
        self.investigation_tree = self.make_tree(left, ("ID", "Domain", "Assignee", "State", "Updated"), (50, 220, 140, 100, 160))
        ttk.Label(right, text="Investigation Notes", background="#ffffff", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.assignee_var = tk.StringVar()
        self.state_var = tk.StringVar(value="Open")
        ttk.Entry(right, textvariable=self.assignee_var).pack(fill="x", pady=(8, 6))
        ttk.Combobox(right, textvariable=self.state_var, values=["Open", "In Review", "Escalated", "Closed"], state="readonly").pack(fill="x", pady=(0, 8))
        self.notes_text = tk.Text(right, height=14, wrap="word")
        self.notes_text.pack(fill="both", expand=True)
        ttk.Button(right, text="Save Investigation", style="Accent.TButton", command=self.save_investigation).pack(anchor="e", pady=(8, 0))
        self.investigation_tree.bind("<<TreeviewSelect>>", self.load_investigation)

    def build_reports(self):
        tab = self.tabs["Reports"]
        panel = self.panel(tab, fill="both", expand=True, padx=5, pady=(8, 0))
        ttk.Button(panel, text="Generate Executive Summary", style="Accent.TButton", command=self.generate_report).pack(anchor="w")
        ttk.Button(panel, text="Export Detections CSV", command=self.export_detections).pack(anchor="w", pady=(8, 10))
        self.report_text = tk.Text(panel, wrap="word", height=28)
        self.report_text.pack(fill="both", expand=True)

    def build_audit(self):
        tab = self.tabs["Audit Logs"]
        panel = self.panel(tab, fill="both", expand=True, padx=5, pady=(8, 0))
        self.audit_tree = self.make_tree(panel, ("Actor", "Action", "Details", "Created"), (100, 140, 520, 160))

    def make_tree(self, parent, columns, widths):
        holder = ttk.Frame(parent, style="Panel.TFrame")
        holder.pack(fill="both", expand=True, pady=(8, 0))
        tree = ttk.Treeview(holder, columns=columns, show="headings")
        yscroll = ttk.Scrollbar(holder, orient="vertical", command=tree.yview)
        xscroll = ttk.Scrollbar(holder, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        for col, width in zip(columns, widths):
            tree.heading(col, text=col)
            tree.column(col, width=width, minwidth=50)
        tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        holder.columnconfigure(0, weight=1)
        holder.rowconfigure(0, weight=1)
        return tree

    def refresh_all(self):
        self.refresh_protected_domains()
        self.refresh_dashboard()
        self.refresh_alerts()
        self.refresh_investigations()
        self.refresh_audit()

    def refresh_protected_domains(self):
        rows = self.db.conn.execute("SELECT * FROM protected_domains ORDER BY priority, domain").fetchall()
        self.fill_tree(self.protected_tree, [(r["id"], r["domain"], r["brand"], r["owner"], r["priority"], r["created_at"]) for r in rows])
        values = [r["domain"] for r in rows]
        self.scan_domain_combo["values"] = values
        if values and not self.scan_domain_var.get():
            self.scan_domain_var.set(values[0])

    def refresh_dashboard(self):
        protected = self.db.conn.execute("SELECT COUNT(*) FROM protected_domains").fetchone()[0]
        detected = self.db.conn.execute("SELECT COUNT(*) FROM detected_domains").fetchone()[0]
        open_alerts = self.db.conn.execute("SELECT COUNT(*) FROM alerts WHERE status != 'Closed'").fetchone()[0]
        critical = self.db.conn.execute("SELECT COUNT(*) FROM detected_domains WHERE risk_score >= 80").fetchone()[0]
        for key, value in [("Protected", protected), ("Detected", detected), ("Open Alerts", open_alerts), ("Critical Risk", critical)]:
            self.metric_labels[key].configure(text=str(value))

        rows = self.db.conn.execute(
            """
            SELECT dd.domain, pd.brand, dd.risk_score, dd.attack_type, dd.status
            FROM detected_domains dd
            JOIN protected_domains pd ON pd.id = dd.protected_domain_id
            ORDER BY dd.risk_score DESC, dd.last_seen DESC LIMIT 15
            """
        ).fetchall()
        self.fill_tree(self.dashboard_tree, [(r["domain"], r["brand"], r["risk_score"], r["attack_type"], r["status"]) for r in rows])

        alerts = self.db.conn.execute("SELECT severity, title, status, created_at FROM alerts ORDER BY id DESC LIMIT 15").fetchall()
        self.fill_tree(self.recent_alerts_tree, [(r["severity"], r["title"], r["status"], r["created_at"]) for r in alerts])

    def refresh_alerts(self):
        rows = self.db.conn.execute("SELECT id, severity, title, status, created_at FROM alerts ORDER BY id DESC").fetchall()
        self.fill_tree(self.alerts_tree, [(r["id"], r["severity"], r["title"], r["status"], r["created_at"]) for r in rows])

    def refresh_investigations(self):
        rows = self.db.conn.execute(
            """
            SELECT i.id, dd.domain, i.assignee, i.state, i.updated_at
            FROM investigations i
            JOIN detected_domains dd ON dd.id = i.detected_domain_id
            ORDER BY i.updated_at DESC
            """
        ).fetchall()
        self.fill_tree(self.investigation_tree, [(r["id"], r["domain"], r["assignee"], r["state"], r["updated_at"]) for r in rows])

    def refresh_audit(self):
        rows = self.db.conn.execute("SELECT actor, action, details, created_at FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall()
        self.fill_tree(self.audit_tree, [(r["actor"], r["action"], r["details"], r["created_at"]) for r in rows])

    def fill_tree(self, tree, rows):
        tree.delete(*tree.get_children())
        for row in rows:
            tree.insert("", "end", values=row)

    def load_protected_domain(self, domain_id):
        row = self.db.conn.execute("SELECT * FROM protected_domains WHERE id=?", (domain_id,)).fetchone()
        if not row:
            self.cancel_protected_domain_edit()
            return
        self.editing_domain_id = domain_id
        for item in self.protected_tree.get_children():
            if self.protected_tree.item(item)["values"][0] == domain_id:
                self.protected_tree.selection_set(item)
                self.protected_tree.see(item)
                break
        self.domain_var.set(row["domain"])
        self.brand_var.set(row["brand"])
        self.owner_var.set(row["owner"] or "")
        self.priority_var.set(row["priority"] or "Medium")
        self.add_domain_button.configure(text="Update Domain")
        self.protected_status_label.configure(text=f"Editing protected domain {row['domain']}")

    def load_selected_protected_domain(self, _event=None):
        selected = self.protected_tree.selection()
        if not selected:
            self.cancel_protected_domain_edit()
            return
        domain_id = self.protected_tree.item(selected[0])["values"][0]
        self.load_protected_domain(domain_id)

    def cancel_protected_domain_edit(self):
        self.editing_domain_id = None
        self.domain_var.set("")
        self.brand_var.set("")
        self.owner_var.set("")
        self.priority_var.set("High")
        self.add_domain_button.configure(text="Add Domain")
        self.protected_status_label.configure(text="")
        self.protected_tree.selection_remove(self.protected_tree.selection())

    def add_protected_domain(self):
        domain = normalize_domain(self.domain_var.get())
        brand = self.brand_var.get().strip()
        if not domain or "." not in domain or not brand:
            messagebox.showerror("Missing data", "Enter a valid domain and brand.")
            return
        if self.editing_domain_id is not None:
            existing = self.db.conn.execute("SELECT id FROM protected_domains WHERE domain=?", (domain,)).fetchone()
            if existing and existing["id"] != self.editing_domain_id:
                messagebox.showwarning("Already exists", f"{domain} is already protected.")
                return
            self.db.conn.execute(
                "UPDATE protected_domains SET domain=?, brand=?, owner=?, priority=? WHERE id=?",
                (domain, brand, self.owner_var.get().strip(), self.priority_var.get(), self.editing_domain_id),
            )
            self.db.log("analyst", "update protected domain", domain)
            messagebox.showinfo("Updated", f"Protected domain {domain} updated.")
            self.cancel_protected_domain_edit()
        else:
            try:
                self.db.conn.execute(
                    "INSERT INTO protected_domains(domain, brand, owner, priority, created_at) VALUES(?,?,?,?,?)",
                    (domain, brand, self.owner_var.get().strip(), self.priority_var.get(), timestamp()),
                )
                self.db.log("analyst", "add protected domain", domain)
            except sqlite3.IntegrityError:
                duplicate = self.db.conn.execute("SELECT id FROM protected_domains WHERE domain=?", (domain,)).fetchone()
                if duplicate:
                    self.load_protected_domain(duplicate["id"])
                    messagebox.showwarning("Already exists", f"{domain} already exists and has been loaded for editing.")
                else:
                    messagebox.showwarning("Already exists", f"{domain} is already protected.")
                return
            messagebox.showinfo("Added", f"Protected domain {domain} added.")
            self.cancel_protected_domain_edit()
        self.refresh_all()

    def delete_protected_domain(self):
        selected = self.protected_tree.selection()
        if not selected:
            return
        domain_id = self.protected_tree.item(selected[0])["values"][0]
        if not messagebox.askyesno("Delete domain", "Delete this protected domain and related detections?"):
            return
        self.cancel_protected_domain_edit()
        detected_ids = [
            row["id"]
            for row in self.db.conn.execute(
                "SELECT id FROM detected_domains WHERE protected_domain_id=?",
                (domain_id,),
            ).fetchall()
        ]
        for detected_id in detected_ids:
            self.db.conn.execute("DELETE FROM alerts WHERE detected_domain_id=?", (detected_id,))
            self.db.conn.execute("DELETE FROM investigations WHERE detected_domain_id=?", (detected_id,))
        self.db.conn.execute("DELETE FROM detected_domains WHERE protected_domain_id=?", (domain_id,))
        self.db.conn.execute("DELETE FROM protected_domains WHERE id=?", (domain_id,))
        self.db.log("analyst", "delete protected domain", str(domain_id))
        self.refresh_all()

    def generate_for_scan(self):
        domain = self.scan_domain_var.get()
        if not domain:
            messagebox.showinfo("No domain", "Add or select a protected domain first.")
            return
        candidates = generate_candidates(domain)
        self.candidate_text.delete("1.0", "end")
        self.candidate_text.insert("1.0", "\n".join(candidates))

    def import_candidates(self):
        path = filedialog.askopenfilename(filetypes=[("CSV/Text", "*.csv *.txt"), ("All files", "*.*")])
        if not path:
            return
        with open(path, newline="", encoding="utf-8", errors="ignore") as handle:
            sample = handle.read()
        self.candidate_text.delete("1.0", "end")
        self.candidate_text.insert("1.0", sample.replace(",", "\n"))

    def run_scan(self):
        protected = self.scan_domain_var.get()
        candidates = [normalize_domain(line) for line in self.candidate_text.get("1.0", "end").splitlines() if normalize_domain(line)]
        if not protected or not candidates:
            messagebox.showinfo("Nothing to scan", "Select a protected domain and add candidate domains.")
            return
        row = self.db.conn.execute("SELECT id FROM protected_domains WHERE domain=?", (protected,)).fetchone()
        if not row:
            messagebox.showerror("Unknown domain", "Selected protected domain is not in the database.")
            return
        self.scan_status.configure(text=f"Scanning {len(candidates)} domains...")
        self.scan_tree.delete(*self.scan_tree.get_children())
        threading.Thread(target=self.scan_worker, args=(row["id"], protected, candidates), daemon=True).start()

    def scan_worker(self, protected_id, protected_domain, candidates):
        results = []
        for idx, candidate in enumerate(candidates, 1):
            dns_summary, dns_indicators = resolve_dns(candidate)
            ssl_summary, ssl_indicators = inspect_ssl(candidate)
            website_summary, web_indicators = inspect_website(candidate)
            indicators = dns_indicators + ssl_indicators + web_indicators
            risk, attack_type, sim = score_domain(protected_domain, candidate, dns_summary, ssl_summary, website_summary, indicators)
            results.append((candidate, risk, severity(risk), attack_type, sim, ", ".join(indicators) or "None"))
            self.persist_detection(protected_id, candidate, sim, attack_type, risk, dns_summary, ssl_summary, website_summary, indicators)
            self.work_queue.put(("progress", f"Scanned {idx}/{len(candidates)}: {candidate}"))
        self.work_queue.put(("scan_done", results))

    def persist_detection(self, protected_id, candidate, sim, attack_type, risk, dns_summary, ssl_summary, website_summary, indicators):
        now = timestamp()
        indicator_text = ", ".join(indicators)
        self.db.conn.execute(
            """
            INSERT INTO detected_domains(protected_domain_id, domain, similarity, attack_type, risk_score, first_seen, last_seen, dns_summary, ssl_summary, website_summary, indicators)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(protected_domain_id, domain) DO UPDATE SET
                similarity=excluded.similarity,
                attack_type=excluded.attack_type,
                risk_score=excluded.risk_score,
                last_seen=excluded.last_seen,
                dns_summary=excluded.dns_summary,
                ssl_summary=excluded.ssl_summary,
                website_summary=excluded.website_summary,
                indicators=excluded.indicators
            """,
            (protected_id, candidate, sim, attack_type, risk, now, now, dns_summary, ssl_summary, website_summary, indicator_text),
        )
        detected_id = self.db.conn.execute(
            "SELECT id FROM detected_domains WHERE protected_domain_id=? AND domain=?",
            (protected_id, candidate),
        ).fetchone()["id"]
        if risk >= 60:
            sev = severity(risk)
            title = f"{sev} impersonation risk: {candidate}"
            existing = self.db.conn.execute(
                "SELECT id FROM alerts WHERE detected_domain_id=? AND status != 'Closed'",
                (detected_id,),
            ).fetchone()
            if not existing:
                self.db.conn.execute(
                    "INSERT INTO alerts(detected_domain_id, severity, title, message, created_at) VALUES(?,?,?,?,?)",
                    (detected_id, sev, title, f"{candidate} scored {risk}/100 as {attack_type}.", now),
                )
                self.db.conn.execute(
                    "INSERT INTO investigations(detected_domain_id, assignee, notes, state, updated_at) VALUES(?,?,?,?,?)",
                    (detected_id, "", "Auto-created from high-risk detection.", "Open", now),
                )
        self.db.conn.commit()

    def consume_queue(self):
        try:
            while True:
                event, payload = self.work_queue.get_nowait()
                if event == "progress":
                    self.scan_status.configure(text=payload)
                elif event == "scan_done":
                    self.fill_tree(self.scan_tree, payload)
                    self.scan_status.configure(text=f"Scan complete: {len(payload)} domains analyzed")
                    self.db.log("analyst", "scan complete", f"{len(payload)} candidate domains analyzed")
                    self.refresh_all()
        except queue.Empty:
            pass
        self.after(200, self.consume_queue)

    def update_alert_status(self, status):
        selected = self.alerts_tree.selection()
        if not selected:
            return
        alert_id = self.alerts_tree.item(selected[0])["values"][0]
        self.db.conn.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
        self.db.log("analyst", "update alert", f"{alert_id} -> {status}")
        self.refresh_all()

    def load_investigation(self, _event=None):
        selected = self.investigation_tree.selection()
        if not selected:
            return
        investigation_id = self.investigation_tree.item(selected[0])["values"][0]
        row = self.db.conn.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not row:
            return
        self.assignee_var.set(row["assignee"] or "")
        self.state_var.set(row["state"] or "Open")
        self.notes_text.delete("1.0", "end")
        self.notes_text.insert("1.0", row["notes"] or "")

    def save_investigation(self):
        selected = self.investigation_tree.selection()
        if not selected:
            messagebox.showinfo("No investigation", "Select an investigation first.")
            return
        investigation_id = self.investigation_tree.item(selected[0])["values"][0]
        self.db.conn.execute(
            "UPDATE investigations SET assignee=?, state=?, notes=?, updated_at=? WHERE id=?",
            (self.assignee_var.get().strip(), self.state_var.get(), self.notes_text.get("1.0", "end").strip(), timestamp(), investigation_id),
        )
        self.db.log("analyst", "save investigation", str(investigation_id))
        self.refresh_all()

    def generate_report(self):
        rows = self.db.conn.execute(
            """
            SELECT pd.brand, pd.domain AS protected, dd.domain, dd.risk_score, dd.attack_type, dd.status, dd.indicators
            FROM detected_domains dd
            JOIN protected_domains pd ON pd.id = dd.protected_domain_id
            ORDER BY dd.risk_score DESC
            """
        ).fetchall()
        open_alerts = self.db.conn.execute("SELECT COUNT(*) FROM alerts WHERE status != 'Closed'").fetchone()[0]
        critical = [r for r in rows if r["risk_score"] >= 80]
        high = [r for r in rows if 60 <= r["risk_score"] < 80]
        lines = [
            f"Executive Summary - {timestamp()}",
            "",
            f"Total detections: {len(rows)}",
            f"Open alerts: {open_alerts}",
            f"Critical risk detections: {len(critical)}",
            f"High risk detections: {len(high)}",
            "",
            "Top findings:",
        ]
        for r in rows[:10]:
            lines.append(
                f"- {r['domain']} impersonates {r['protected']} ({r['brand']}): "
                f"{r['risk_score']}/100, {r['attack_type']}, indicators: {r['indicators'] or 'None'}"
            )
        if not rows:
            lines.append("- No detections have been recorded yet.")
        lines.extend(
            [
                "",
                "Recommended SOC actions:",
                "- Review critical and high alerts.",
                "- Validate live website content and login forms.",
                "- Escalate confirmed phishing infrastructure for takedown.",
                "- Add confirmed false positives to operational notes.",
            ]
        )
        self.report_text.delete("1.0", "end")
        self.report_text.insert("1.0", "\n".join(lines))
        self.db.log("analyst", "generate report", "Executive summary generated")
        self.refresh_audit()

    def export_detections(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        rows = self.db.conn.execute(
            """
            SELECT pd.domain AS protected_domain, dd.domain, dd.similarity, dd.attack_type, dd.risk_score,
                   dd.status, dd.dns_summary, dd.ssl_summary, dd.website_summary, dd.indicators, dd.last_seen
            FROM detected_domains dd
            JOIN protected_domains pd ON pd.id = dd.protected_domain_id
            ORDER BY dd.risk_score DESC
            """
        ).fetchall()
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(rows[0].keys() if rows else ["protected_domain", "domain", "similarity", "attack_type", "risk_score", "status", "dns_summary", "ssl_summary", "website_summary", "indicators", "last_seen"])
            for row in rows:
                writer.writerow([row[key] for key in row.keys()])
        self.db.log("analyst", "export detections", os.path.basename(path))
        messagebox.showinfo("Export complete", f"Saved {len(rows)} detections.")
        self.refresh_audit()


if __name__ == "__main__":
    app = DidsApp()
    app.mainloop()
