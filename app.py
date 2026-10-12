import csv
import io
import os
import re
import secrets
import sqlite3  # used only for the IntegrityError compatibility alias below
import hashlib
import json
import hmac
import tempfile
from io import BytesIO
from flask import jsonify, send_file
from dotenv import load_dotenv
load_dotenv()
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, redirect, render_template, request, send_from_directory,
    session, url_for, Response
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

ROOT = Path(__file__).resolve().parent
INSTANCE = ROOT / "instance"
UPLOADS = ROOT / "uploads"
INSTANCE.mkdir(exist_ok=True)
UPLOADS.mkdir(exist_ok=True)
DB_PATH = INSTANCE / "procuretrack.db"
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "png", "jpg", "jpeg", "txt"}

app = Flask(__name__)
APP_ENV = os.environ.get("APP_ENV", "production").lower()
SESSION_SECRET = os.environ.get("PROCURETRACK_SECRET", "").strip()
if APP_ENV == "production" and not SESSION_SECRET:
    raise RuntimeError("PROCURETRACK_SECRET is required in production. Configure it as a private environment secret.")
app.secret_key = SESSION_SECRET or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = str(UPLOADS)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = APP_ENV == "production"
app.config["PREFERRED_URL_SCHEME"] = "https"


# Cloud Edition database adapter. Uses managed PostgreSQL; never falls back to local SQLite.
import psycopg
from psycopg import rows as pg_rows

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
if not DATABASE_URL:
    # Allow import for syntax checks, but refuse to initialize or run without a database URL.
    DATABASE_URL = None

# Preserve existing route exception handling while mapping it to PostgreSQL integrity errors.
sqlite3.IntegrityError = psycopg.IntegrityError

class HybridRow(dict):
    """Mapping row compatible with existing templates and row[0] access."""
    def __init__(self, names, values):
        super().__init__(zip(names, values))
        self._values = tuple(values)
    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)

class CloudCursor:
    def __init__(self, raw, lastrowid=None):
        self.raw = raw
        self.lastrowid = lastrowid
    def _row(self, values):
        if values is None:
            return None
        names = [d.name if hasattr(d, 'name') else d[0] for d in self.raw.description]
        return HybridRow(names, values)
    def fetchone(self):
        return self._row(self.raw.fetchone())
    def fetchall(self):
        return [self._row(v) for v in self.raw.fetchall()]

class CloudConnection:
    def __init__(self):
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL is not configured. See CLOUD_SETUP.md.")
        self.conn = psycopg.connect(DATABASE_URL, row_factory=pg_rows.tuple_row, connect_timeout=15)
    def __enter__(self):
        return self
    def __exit__(self, typ, val, tb):
        try:
            if typ:
                self.conn.rollback()
            else:
                self.conn.commit()
        finally:
            self.conn.close()
        return False
    def execute(self, sql, params=()):
        sql = sql.replace("?", "%s")
        insert_match = re.match(r"\s*INSERT\s+INTO\s+([A-Za-z_][A-Za-z0-9_]*)", sql, flags=re.I)
        # app_settings uses setting_key as its primary key and has no numeric id.
        is_insert = bool(insert_match) and insert_match.group(1).lower() != "app_settings" and not re.search(r"\bRETURNING\b", sql, flags=re.I)
        if is_insert:
            sql = sql.rstrip().rstrip(';') + " RETURNING id"
        cur = self.conn.cursor()
        cur.execute(sql, params or ())
        lastrowid = None
        if is_insert:
            row = cur.fetchone()
            if row:
                lastrowid = row[0]
        return CloudCursor(cur, lastrowid)
    def executescript(self, script):
        # Schema scripts contain plain CREATE TABLE statements only.
        for statement in script.split(';'):
            statement = statement.strip()
            if not statement:
                continue
            statement = statement.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
            statement = re.sub(r"\bINTEGER\b", "BIGINT", statement, flags=re.I)
            statement = re.sub(r"\bREAL\b", "DOUBLE PRECISION", statement, flags=re.I)
            self.execute(statement)

def db():
    return CloudConnection()


def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'staff',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS suppliers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            contact_person TEXT DEFAULT '', email TEXT DEFAULT '', phone TEXT DEFAULT '',
            address TEXT DEFAULT '', philgeps_no TEXT DEFAULT '', notes TEXT DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS procurements (
            id INTEGER PRIMARY KEY AUTOINCREMENT, pr_number TEXT NOT NULL UNIQUE, title TEXT NOT NULL,
            end_user TEXT DEFAULT '', procurement_method TEXT DEFAULT '', abc REAL NOT NULL DEFAULT 0,
            funding_source TEXT DEFAULT '', ppmp_app_ref TEXT DEFAULT '', pr_date TEXT DEFAULT '', target_date TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Received', assigned_to TEXT DEFAULT '', supplier_id INTEGER,
            po_number TEXT DEFAULT '', remarks TEXT DEFAULT '', created_by INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            FOREIGN KEY(supplier_id) REFERENCES suppliers(id) ON DELETE SET NULL,
            FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT, procurement_id INTEGER NOT NULL, original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL, category TEXT DEFAULT '', uploaded_by INTEGER, uploaded_at TEXT NOT NULL,
            drive_file_id TEXT DEFAULT '', sha256 TEXT DEFAULT '', sync_status TEXT NOT NULL DEFAULT 'pending',
            FOREIGN KEY(procurement_id) REFERENCES procurements(id) ON DELETE CASCADE,
            FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL, entity TEXT NOT NULL,
            entity_id INTEGER, detail TEXT DEFAULT '', created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, plan_type TEXT NOT NULL, reference_no TEXT NOT NULL,
            fiscal_year INTEGER NOT NULL, office TEXT DEFAULT '', title TEXT NOT NULL, category TEXT DEFAULT '',
            estimated_cost REAL NOT NULL DEFAULT 0, funding_source TEXT DEFAULT '', procurement_method TEXT DEFAULT '',
            target_quarter TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Draft', remarks TEXT DEFAULT '', created_by INTEGER,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(plan_type, reference_no),
            FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS quotations (
            id INTEGER PRIMARY KEY AUTOINCREMENT, procurement_id INTEGER NOT NULL, supplier_id INTEGER,
            quotation_ref TEXT DEFAULT '', quotation_date TEXT DEFAULT '', amount REAL NOT NULL DEFAULT 0,
            responsive TEXT NOT NULL DEFAULT 'Pending', notes TEXT DEFAULT '', created_at TEXT NOT NULL,
            FOREIGN KEY(procurement_id) REFERENCES procurements(id) ON DELETE CASCADE,
            FOREIGN KEY(supplier_id) REFERENCES suppliers(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS milestones (
            id INTEGER PRIMARY KEY AUTOINCREMENT, procurement_id INTEGER NOT NULL, stage TEXT NOT NULL,
            action_date TEXT DEFAULT '', reference_no TEXT DEFAULT '', responsible_person TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Pending', notes TEXT DEFAULT '', created_by INTEGER, created_at TEXT NOT NULL,
            FOREIGN KEY(procurement_id) REFERENCES procurements(id) ON DELETE CASCADE,
            FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS checklist_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT, procurement_id INTEGER NOT NULL, item_name TEXT NOT NULL,
            required_for TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Pending', document_ref TEXT DEFAULT '',
            notes TEXT DEFAULT '', updated_at TEXT NOT NULL,
            FOREIGN KEY(procurement_id) REFERENCES procurements(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT, procurement_id INTEGER NOT NULL, delivery_date TEXT DEFAULT '',
            inspection_date TEXT DEFAULT '', acceptance_date TEXT DEFAULT '', delivery_receipt_no TEXT DEFAULT '',
            inspection_report_no TEXT DEFAULT '', acceptance_report_no TEXT DEFAULT '', payment_status TEXT NOT NULL DEFAULT 'Not Started',
            payment_reference TEXT DEFAULT '', notes TEXT DEFAULT '', updated_at TEXT NOT NULL,
            FOREIGN KEY(procurement_id) REFERENCES procurements(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS plan_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT, plan_id INTEGER NOT NULL, original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL, category TEXT DEFAULT '', uploaded_by INTEGER, uploaded_at TEXT NOT NULL,
            drive_file_id TEXT DEFAULT '', sha256 TEXT DEFAULT '', sync_status TEXT NOT NULL DEFAULT 'pending',
            FOREIGN KEY(plan_id) REFERENCES plans(id) ON DELETE CASCADE,
            FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS app_settings (
            setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        """)
        # Add cloud metadata safely if upgrading a cloud database created by an earlier test build.
        for table in ("documents", "plan_documents"):
            con.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS drive_file_id TEXT DEFAULT ''")
            con.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS sha256 TEXT DEFAULT ''")
            con.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS sync_status TEXT NOT NULL DEFAULT 'pending'")


# Google Drive OAuth credentials are encrypted at rest in PostgreSQL. The encryption key
# and OAuth client secret must be configured as hosting-provider secrets, never in source.
def setting_get(key):
    with db() as con:
        row = con.execute("SELECT setting_value FROM app_settings WHERE setting_key=?", (key,)).fetchone()
    return row["setting_value"] if row else None

def setting_set(key, value):
    with db() as con:
        existing = con.execute("SELECT setting_key FROM app_settings WHERE setting_key=?", (key,)).fetchone()
        if existing:
            con.execute("UPDATE app_settings SET setting_value=?, updated_at=? WHERE setting_key=?", (value, now(), key))
        else:
            con.execute("INSERT INTO app_settings(setting_key, setting_value, updated_at) VALUES(?,?,?)", (key, value, now()))

def get_fernet():
    key = os.environ.get("NEXORA_TOKEN_ENCRYPTION_KEY", "").strip()
    if not key:
        raise RuntimeError("NEXORA_TOKEN_ENCRYPTION_KEY is missing; configure it in the hosting secrets.")
    from cryptography.fernet import Fernet
    return Fernet(key.encode())

def drive_client_configured():
    return bool(os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"))

def get_drive_credentials():
    if not drive_client_configured():
        raise RuntimeError("Google OAuth client is not configured. See CLOUD_SETUP.md.")
    encrypted = setting_get("google_oauth_credentials")
    if not encrypted:
        raise RuntimeError("Google Drive is not connected yet. Open Drive Settings and connect it first.")
    token_data = json.loads(get_fernet().decrypt(encrypted.encode()).decode())
    from google.oauth2.credentials import Credentials
    creds = Credentials.from_authorized_user_info(token_data, scopes=["https://www.googleapis.com/auth/drive.file"])
    if creds.expired and creds.refresh_token:
        from google.auth.transport.requests import Request
        creds.refresh(Request())
        setting_set("google_oauth_credentials", get_fernet().encrypt(creds.to_json().encode()).decode())
    return creds

def get_drive_service():
    from googleapiclient.discovery import build
    return build("drive", "v3", credentials=get_drive_credentials(), cache_discovery=False)

def ensure_drive_folder():
    folder_id = setting_get("google_drive_folder_id")
    if folder_id:
        return folder_id
    service = get_drive_service()
    result = service.files().create(body={"name": "NEXORA PH Procurement", "mimeType": "application/vnd.google-apps.folder"}, fields="id,name").execute()
    setting_set("google_drive_folder_id", result["id"])
    return result["id"]

def upload_to_drive(local_path, stored_name, mime_type="application/octet-stream"):
    from googleapiclient.http import MediaFileUpload
    service = get_drive_service()
    folder_id = ensure_drive_folder()
    result = service.files().create(
        body={"name": stored_name, "parents": [folder_id], "description": "NEXORA PH procurement attachment"},
        media_body=MediaFileUpload(str(local_path), mimetype=mime_type, resumable=True),
        fields="id,name,mimeType,size,md5Checksum"
    ).execute()
    return result["id"]

def drive_file_bytes(file_id):
    from googleapiclient.http import MediaIoBaseDownload
    service = get_drive_service()
    request_obj = service.files().get_media(fileId=file_id)
    target = BytesIO()
    downloader = MediaIoBaseDownload(target, request_obj)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    return target.getvalue()

def require_sync_token():
    supplied = request.headers.get("Authorization", "")
    expected = os.environ.get("NEXORA_SYNC_TOKEN", "")
    if not expected or not supplied.startswith("Bearer ") or not hmac.compare_digest(supplied[7:], expected):
        abort(401)


def now():
    return datetime.now().isoformat(timespec="seconds")


def audit(action, entity, entity_id=None, detail=""):
    with db() as con:
        con.execute(
            "INSERT INTO audit_log(user_id, action, entity, entity_id, detail, created_at) VALUES(?,?,?,?,?,?)",
            (session.get("user_id"), action, entity, entity_id, detail[:500], now())
        )


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def write_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if session.get("role") == "viewer":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


@app.context_processor
def inject_user():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"current_user": session.get("username"), "current_role": session.get("role"), "csrf_token": session["csrf_token"]}

@app.before_request
def protect_post_requests():
    if request.method == "POST":
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            abort(400, "CSRF token missing or invalid. Refresh the page and try again.")


@app.route("/setup", methods=["GET", "POST"])
def setup():
    with db() as con:
        count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count:
        return redirect(url_for("login"))
    setup_key = os.environ.get("NEXORA_SETUP_KEY", "").strip()
    if APP_ENV == "production" and not setup_key:
        return "Initial setup is locked. Configure NEXORA_SETUP_KEY in the server's private environment settings, then restart.", 503
    if request.method == "POST":
        if setup_key and not secrets.compare_digest(request.form.get("setup_key", ""), setup_key):
            flash("Invalid initial setup key.", "error")
            return render_template("setup.html", setup_key_required=bool(setup_key)), 403
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(password) < 12:
            flash("Use a username of at least 3 characters and a password of at least 12 characters.", "error")
        else:
            with db() as con:
                cur = con.execute(
                    "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                    (username, generate_password_hash(password), "admin", now())
                )
                user_id = cur.lastrowid
            session.update(user_id=user_id, username=username, role="admin")
            audit("CREATE", "user", user_id, "Initial administrator created")
            flash("Administrator account created. Keep the password private.", "success")
            return redirect(url_for("dashboard"))
    return render_template("setup.html", setup_key_required=bool(setup_key))


@app.route("/login", methods=["GET", "POST"])
def login():
    with db() as con:
        count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if not count:
        return redirect(url_for("setup"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.update(user_id=user["id"], username=user["username"], role=user["role"])
            audit("LOGIN", "user", user["id"], "Successful login")
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    if session.get("user_id"):
        audit("LOGOUT", "user", session.get("user_id"), "User logged out")
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    with db() as con:
        total = con.execute("SELECT COUNT(*) FROM procurements").fetchone()[0]
        active = con.execute("SELECT COUNT(*) FROM procurements WHERE status NOT IN ('Completed','Cancelled')").fetchone()[0]
        completed = con.execute("SELECT COUNT(*) FROM procurements WHERE status='Completed'").fetchone()[0]
        abc = con.execute("SELECT COALESCE(SUM(abc),0) FROM procurements").fetchone()[0]
        suppliers = con.execute("SELECT COUNT(*) FROM suppliers").fetchone()[0]
        recent = con.execute("""SELECT p.*, s.name supplier_name FROM procurements p
                              LEFT JOIN suppliers s ON s.id=p.supplier_id
                              ORDER BY p.updated_at DESC LIMIT 8""").fetchall()
    return render_template("dashboard.html", total=total, active=active, completed=completed,
                           abc=abc, suppliers=suppliers, recent=recent)


STATUSES = ["Received", "For Review", "For Procurement Processing", "For Award/PO",
            "For Delivery", "For Inspection/Acceptance", "For Payment Documents", "Completed", "On Hold", "Cancelled"]
METHODS = ["", "Competitive Bidding", "Small Value Procurement", "Direct Contracting",
           "Negotiated Procurement", "Shopping", "Other / To Be Confirmed"]


@app.route("/procurements")
@login_required
def procurements():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    sql = """SELECT p.*, s.name supplier_name FROM procurements p
             LEFT JOIN suppliers s ON s.id=p.supplier_id WHERE 1=1"""
    args = []
    if q:
        like = f"%{q}%"
        sql += " AND (p.pr_number LIKE ? OR p.title LIKE ? OR p.end_user LIKE ? OR p.po_number LIKE ?)"
        args.extend([like, like, like, like])
    if status:
        sql += " AND p.status=?"
        args.append(status)
    sql += " ORDER BY p.updated_at DESC"
    with db() as con:
        rows = con.execute(sql, args).fetchall()
    return render_template("procurements.html", rows=rows, statuses=STATUSES, q=q, selected_status=status)


def form_values():
    return {
        "pr_number": request.form.get("pr_number", "").strip(),
        "title": request.form.get("title", "").strip(),
        "end_user": request.form.get("end_user", "").strip(),
        "procurement_method": request.form.get("procurement_method", "").strip(),
        "abc": request.form.get("abc", "0").strip() or "0",
        "funding_source": request.form.get("funding_source", "").strip(),
        "ppmp_app_ref": request.form.get("ppmp_app_ref", "").strip(),
        "pr_date": request.form.get("pr_date", "").strip(),
        "target_date": request.form.get("target_date", "").strip(),
        "status": request.form.get("status", "Received").strip(),
        "assigned_to": request.form.get("assigned_to", "").strip(),
        "supplier_id": request.form.get("supplier_id", "").strip() or None,
        "po_number": request.form.get("po_number", "").strip(),
        "remarks": request.form.get("remarks", "").strip(),
    }


@app.route("/procurements/new", methods=["GET", "POST"])
@write_required
def new_procurement():
    if not can_edit(): abort(403)
    with db() as con:
        suppliers = con.execute("SELECT id,name FROM suppliers ORDER BY name").fetchall()
    if request.method == "POST":
        v = form_values()
        try:
            abc = float(v["abc"])
            if not v["pr_number"] or not v["title"] or abc < 0:
                raise ValueError()
            with db() as con:
                cur = con.execute("""INSERT INTO procurements
                (pr_number,title,end_user,procurement_method,abc,funding_source,ppmp_app_ref,pr_date,target_date,status,assigned_to,supplier_id,po_number,remarks,created_by,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (v["pr_number"],v["title"],v["end_user"],v["procurement_method"],abc,v["funding_source"],
                 v["ppmp_app_ref"],v["pr_date"],v["target_date"],v["status"],v["assigned_to"],v["supplier_id"],
                 v["po_number"],v["remarks"],session["user_id"],now(),now()))
                rid = cur.lastrowid
            audit("CREATE", "procurement", rid, f"PR {v['pr_number']} created")
            flash("Procurement record added.", "success")
            return redirect(url_for("procurement_detail", pid=rid))
        except ValueError:
            flash("Enter a PR number, title, and valid non-negative ABC amount.", "error")
        except sqlite3.IntegrityError:
            flash("That PR number already exists. Use a unique PR number.", "error")
    return render_template("procurement_form.html", row=None, suppliers=suppliers, statuses=STATUSES, methods=METHODS)


@app.route("/procurements/<int:pid>")
@login_required
def procurement_detail(pid):
    with db() as con:
        row = con.execute("""SELECT p.*, s.name supplier_name FROM procurements p
                           LEFT JOIN suppliers s ON s.id=p.supplier_id WHERE p.id=?""", (pid,)).fetchone()
        docs = con.execute("SELECT * FROM documents WHERE procurement_id=? ORDER BY uploaded_at DESC", (pid,)).fetchall()
    if not row:
        abort(404)
    return render_template("procurement_detail.html", row=row, docs=docs)


@app.route("/procurements/<int:pid>/edit", methods=["GET", "POST"])
@write_required
def edit_procurement(pid):
    if not can_edit(): abort(403)
    with db() as con:
        row = con.execute("SELECT * FROM procurements WHERE id=?", (pid,)).fetchone()
        suppliers = con.execute("SELECT id,name FROM suppliers ORDER BY name").fetchall()
    if not row:
        abort(404)
    if request.method == "POST":
        v = form_values()
        try:
            abc = float(v["abc"])
            if not v["pr_number"] or not v["title"] or abc < 0:
                raise ValueError()
            with db() as con:
                con.execute("""UPDATE procurements SET pr_number=?,title=?,end_user=?,procurement_method=?,abc=?,
                funding_source=?,ppmp_app_ref=?,pr_date=?,target_date=?,status=?,assigned_to=?,supplier_id=?,
                po_number=?,remarks=?,updated_at=? WHERE id=?""",
                (v["pr_number"],v["title"],v["end_user"],v["procurement_method"],abc,v["funding_source"],
                 v["ppmp_app_ref"],v["pr_date"],v["target_date"],v["status"],v["assigned_to"],v["supplier_id"],
                 v["po_number"],v["remarks"],now(),pid))
            audit("UPDATE", "procurement", pid, f"PR {v['pr_number']} updated; status={v['status']}")
            flash("Procurement record updated.", "success")
            return redirect(url_for("procurement_detail", pid=pid))
        except ValueError:
            flash("Enter a PR number, title, and valid non-negative ABC amount.", "error")
        except sqlite3.IntegrityError:
            flash("That PR number is already used by another record.", "error")
    return render_template("procurement_form.html", row=row, suppliers=suppliers, statuses=STATUSES, methods=METHODS)


@app.route("/suppliers", methods=["GET", "POST"])
@write_required
def suppliers():
    if request.method == "POST" and not can_edit():
        abort(403)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Supplier name is required.", "error")
        else:
            with db() as con:
                cur = con.execute("""INSERT INTO suppliers(name,contact_person,email,phone,address,philgeps_no,notes,created_at)
                VALUES(?,?,?,?,?,?,?,?)""",
                (name,request.form.get("contact_person","").strip(),request.form.get("email","").strip(),
                 request.form.get("phone","").strip(),request.form.get("address","").strip(),
                 request.form.get("philgeps_no","").strip(),request.form.get("notes","").strip(),now()))
                sid = cur.lastrowid
            audit("CREATE", "supplier", sid, f"Supplier added: {name}")
            flash("Supplier added.", "success")
            return redirect(url_for("suppliers"))
    q = request.args.get("q", "").strip()
    with db() as con:
        if q:
            rows = con.execute("SELECT * FROM suppliers WHERE name LIKE ? OR philgeps_no LIKE ? ORDER BY name",
                               (f"%{q}%", f"%{q}%")).fetchall()
        else:
            rows = con.execute("SELECT * FROM suppliers ORDER BY name").fetchall()
    return render_template("suppliers.html", rows=rows, q=q)


@app.route("/procurements/<int:pid>/upload", methods=["POST"])
@write_required
def upload_document(pid):
    if not can_edit(): abort(403)
    with db() as con:
        exists = con.execute("SELECT id FROM procurements WHERE id=?", (pid,)).fetchone()
    if not exists:
        abort(404)
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Choose a file first.", "error")
        return redirect(url_for("procurement_detail", pid=pid))
    original = file.filename
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    if ext not in ALLOWED_EXTENSIONS:
        flash("File type not allowed. Allowed: PDF, Word, Excel, PNG, JPG, TXT.", "error")
        return redirect(url_for("procurement_detail", pid=pid))
    stored = secrets.token_hex(16) + "_" + secure_filename(original)
    local_path = UPLOADS / stored
    file.save(local_path)
    sha256 = hashlib.sha256(local_path.read_bytes()).hexdigest()
    try:
        drive_id = upload_to_drive(local_path, stored, file.mimetype or "application/octet-stream")
    except Exception as exc:
        local_path.unlink(missing_ok=True)
        app.logger.exception("Google Drive upload failed")
        flash("Upload was not completed because Google Drive could not confirm the file. Check Drive Settings and retry.", "error")
        return redirect(url_for("procurement_detail", pid=pid))
    with db() as con:
        con.execute("""INSERT INTO documents(procurement_id,original_name,stored_name,category,uploaded_by,uploaded_at,drive_file_id,sha256,sync_status)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (pid, original, stored, request.form.get("category","").strip(), session["user_id"], now(), drive_id, sha256, "complete"))
    audit("UPLOAD", "document", pid, f"Uploaded attachment: {original}")
    flash("Document uploaded to Google Drive and mirrored on the app server. Office-PC sync will copy it when configured.", "success")
    return redirect(url_for("procurement_detail", pid=pid))


@app.route("/documents/<int:doc_id>")
@login_required
def download_document(doc_id):
    with db() as con:
        doc = con.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        abort(404)
    local_path = UPLOADS / doc["stored_name"]
    if local_path.exists():
        return send_from_directory(UPLOADS, doc["stored_name"], as_attachment=True, download_name=doc["original_name"])
    if not doc.get("drive_file_id"):
        abort(404)
    try:
        data = drive_file_bytes(doc["drive_file_id"])
    except Exception:
        app.logger.exception("Drive download failed")
        abort(503)
    return send_file(BytesIO(data), as_attachment=True, download_name=doc["original_name"])


@app.route("/export/procurements.csv")
@login_required
def export_csv():
    with db() as con:
        rows = con.execute("""SELECT p.pr_number,p.title,p.end_user,p.procurement_method,p.abc,p.funding_source,
            p.ppmp_app_ref,p.pr_date,p.target_date,p.status,p.assigned_to,s.name AS supplier,p.po_number,p.remarks
            FROM procurements p LEFT JOIN suppliers s ON s.id=p.supplier_id ORDER BY p.pr_number""").fetchall()
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["PR Number","Title","End User","Procurement Method","ABC","Funding Source","PPMP/APP Ref",
                     "PR Date","Target Date","Status","Assigned To","Supplier","PO Number","Remarks"])
    writer.writerows([tuple(r) for r in rows])
    audit("EXPORT", "procurements", None, "Exported procurement CSV")
    return Response("\ufeff" + out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":"attachment; filename=procurement_records.csv"})


@app.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "staff")
        if len(username) < 3 or len(password) < 12 or role not in ("admin", "staff", "viewer"):
            flash("Username must be at least 3 characters, password at least 12 characters, and role valid.", "error")
        else:
            try:
                with db() as con:
                    cur = con.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                                      (username, generate_password_hash(password), role, now()))
                audit("CREATE", "user", cur.lastrowid, f"Created user {username} with role {role}")
                flash("User created.", "success")
                return redirect(url_for("users"))
            except sqlite3.IntegrityError:
                flash("That username already exists.", "error")
    with db() as con:
        rows = con.execute("SELECT id,username,role,active,created_at FROM users ORDER BY username").fetchall()
    return render_template("users.html", rows=rows)


@app.route("/users/<int:uid>/toggle", methods=["POST"])
@admin_required
def toggle_user(uid):
    if uid == session.get("user_id"):
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("users"))
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not user:
            abort(404)
        con.execute("UPDATE users SET active=? WHERE id=?", (0 if user["active"] else 1, uid))
    audit("UPDATE", "user", uid, f"Set active={0 if user['active'] else 1}")
    flash("User status updated.", "success")
    return redirect(url_for("users"))


@app.route("/audit")
@login_required
def audit_page():
    if session.get("role") != "admin":
        abort(403)
    with db() as con:
        rows = con.execute("""SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON u.id=a.user_id
                           ORDER BY a.id DESC LIMIT 300""").fetchall()
    return render_template("audit.html", rows=rows)



# ---- Extended modules: plans, quotations, milestones, checklist, delivery/payment, reports, imports ----
def can_edit():
    return session.get("role") in ("admin", "staff")

def edit_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if not can_edit():
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

PLAN_TYPES = ["PPMP", "APP"]
PLAN_STATUSES = ["Draft", "For Review", "Approved", "Included", "Deferred", "Cancelled"]
MILESTONE_STAGES = [
    "PR Received", "Specifications Reviewed", "Market Scoping", "RFQ/Bidding Documents",
    "Invitation/Posting", "Pre-Procurement Conference", "Pre-Bid Conference",
    "Submission/Opening", "Evaluation", "Post-Qualification", "BAC Resolution/Recommendation",
    "Approval of Award", "Notice of Award", "Contract/PO Preparation", "Notice to Proceed",
    "Delivery", "Inspection", "Acceptance", "Payment Documents", "Archived"
]
CHECKLIST_SUGGESTIONS = [
    "Approved Purchase Request", "Approved specifications / Terms of Reference",
    "PPMP / APP reference verified", "Budget / funding confirmation",
    "Market scoping / price research record (if applicable)", "Procurement method justification",
    "RFQ / bidding document or applicable solicitation", "Supplier quotations / bids (as applicable)",
    "Abstract / evaluation record (as applicable)", "BAC minutes / resolution (as applicable)",
    "Approval / award documentation (as applicable)", "Purchase Order / contract (as applicable)",
    "Delivery receipt / proof of delivery", "Inspection and acceptance documentation",
    "Invoice / billing documents", "Payment processing reference", "PhilGEPS posting reference (if applicable)"
]

@app.route("/plans", methods=["GET", "POST"])
@login_required
def plans():
    if request.method == "POST":
        if not can_edit():
            abort(403)
        v = {k: request.form.get(k, "").strip() for k in
             ["plan_type","reference_no","fiscal_year","office","title","category","funding_source",
              "procurement_method","target_quarter","status","remarks"]}
        try:
            cost = float(request.form.get("estimated_cost", "0") or 0)
            year = int(v["fiscal_year"])
            if v["plan_type"] not in PLAN_TYPES or not v["reference_no"] or not v["title"] or year < 2000 or cost < 0:
                raise ValueError()
            with db() as con:
                cur = con.execute("""INSERT INTO plans(plan_type,reference_no,fiscal_year,office,title,category,
                    estimated_cost,funding_source,procurement_method,target_quarter,status,remarks,created_by,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (v["plan_type"],v["reference_no"],year,v["office"],v["title"],v["category"],cost,
                     v["funding_source"],v["procurement_method"],v["target_quarter"],v["status"],v["remarks"],
                     session["user_id"],now(),now()))
            audit("CREATE","plan",cur.lastrowid,f"{v['plan_type']} {v['reference_no']} added")
            flash("Planning record added.", "success")
            return redirect(url_for("plans"))
        except (ValueError, sqlite3.IntegrityError):
            flash("Check the year, cost, required fields, and ensure the plan reference is unique within its type.", "error")
    q = request.args.get("q","").strip()
    typ = request.args.get("type","").strip()
    sql = "SELECT * FROM plans WHERE 1=1"
    args = []
    if q:
        like=f"%{q}%"; sql += " AND (reference_no LIKE ? OR title LIKE ? OR office LIKE ?)"; args += [like,like,like]
    if typ in PLAN_TYPES:
        sql += " AND plan_type=?"; args.append(typ)
    sql += " ORDER BY fiscal_year DESC, plan_type, reference_no"
    with db() as con:
        rows = con.execute(sql,args).fetchall()
        doc_rows = con.execute("SELECT * FROM plan_documents ORDER BY uploaded_at DESC").fetchall()
    docs_by_plan = {}
    for doc in doc_rows:
        docs_by_plan.setdefault(doc["plan_id"], []).append(doc)
    return render_template("plans.html", rows=rows, docs_by_plan=docs_by_plan, q=q, typ=typ, plan_types=PLAN_TYPES, statuses=PLAN_STATUSES)


@app.route("/plans/<int:plan_id>/upload", methods=["POST"])
@write_required
def upload_plan_document(plan_id):
    if not can_edit():
        abort(403)
    with db() as con:
        plan = con.execute("SELECT id, plan_type, reference_no FROM plans WHERE id=?", (plan_id,)).fetchone()
    if not plan:
        abort(404)
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Choose a planning document first.", "error")
        return redirect(url_for("plans"))
    original = file.filename
    ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
    if ext not in ALLOWED_EXTENSIONS:
        flash("File type not allowed. Use PDF, Word, Excel, PNG, JPG, or TXT.", "error")
        return redirect(url_for("plans"))
    stored = secrets.token_hex(16) + "_" + secure_filename(original)
    local_path = UPLOADS / stored
    file.save(local_path)
    sha256 = hashlib.sha256(local_path.read_bytes()).hexdigest()
    try:
        drive_id = upload_to_drive(local_path, stored, file.mimetype or "application/octet-stream")
    except Exception:
        local_path.unlink(missing_ok=True)
        app.logger.exception("Google Drive upload failed")
        flash("Upload was not completed because Google Drive could not confirm the file. Check Drive Settings and retry.", "error")
        return redirect(url_for("plans"))
    with db() as con:
        cur = con.execute("INSERT INTO plan_documents(plan_id,original_name,stored_name,category,uploaded_by,uploaded_at,drive_file_id,sha256,sync_status) VALUES(?,?,?,?,?,?,?,?,?)",
                           (plan_id, original, stored, request.form.get("category", "").strip(), session["user_id"], now(), drive_id, sha256, "complete"))
    audit("UPLOAD", "plan_document", cur.lastrowid, f"{plan['plan_type']} {plan['reference_no']}: {original}")
    flash("Planning document uploaded to Google Drive and mirrored on the app server. Office-PC sync will copy it when configured.", "success")
    return redirect(url_for("plans", q=plan["reference_no"], type=plan["plan_type"]))


@app.route("/plan-documents/<int:doc_id>")
@login_required
def download_plan_document(doc_id):
    with db() as con:
        doc = con.execute("SELECT * FROM plan_documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        abort(404)
    local_path = UPLOADS / doc["stored_name"]
    if local_path.exists():
        return send_from_directory(UPLOADS, doc["stored_name"], as_attachment=True, download_name=doc["original_name"])
    if not doc.get("drive_file_id"):
        abort(404)
    try:
        data = drive_file_bytes(doc["drive_file_id"])
    except Exception:
        app.logger.exception("Drive download failed")
        abort(503)
    return send_file(BytesIO(data), as_attachment=True, download_name=doc["original_name"])


@app.route("/procurements/<int:pid>/quotations", methods=["GET","POST"])
@login_required
def quotation_page(pid):
    with db() as con:
        p = con.execute("SELECT * FROM procurements WHERE id=?",(pid,)).fetchone()
        suppliers = con.execute("SELECT * FROM suppliers ORDER BY name").fetchall()
    if not p: abort(404)
    if request.method=="POST":
        if not can_edit(): abort(403)
        try:
            amount=float(request.form.get("amount","0") or 0)
            sid=request.form.get("supplier_id") or None
            if amount < 0: raise ValueError()
            with db() as con:
                cur=con.execute("""INSERT INTO quotations(procurement_id,supplier_id,quotation_ref,quotation_date,amount,responsive,notes,created_at)
                    VALUES(?,?,?,?,?,?,?,?)""",
                    (pid,sid,request.form.get("quotation_ref","").strip(),request.form.get("quotation_date","").strip(),
                     amount,request.form.get("responsive","Pending"),request.form.get("notes","").strip(),now()))
            audit("CREATE","quotation",cur.lastrowid,f"Quotation added to PR {p['pr_number']}")
            flash("Quotation recorded.","success")
            return redirect(url_for("quotation_page",pid=pid))
        except ValueError:
            flash("Enter a valid non-negative quotation amount.","error")
    with db() as con:
        rows=con.execute("""SELECT q.*,s.name supplier_name FROM quotations q LEFT JOIN suppliers s ON s.id=q.supplier_id
                           WHERE q.procurement_id=? ORDER BY q.amount""",(pid,)).fetchall()
    return render_template("quotations.html", p=p, suppliers=suppliers, rows=rows)


@app.route("/procurements/<int:pid>/quotations/<int:qid>/status", methods=["POST"])
@write_required
def update_quotation_status(pid, qid):
    if not can_edit():
        abort(403)
    valid_statuses = ["Pending", "For Evaluation", "Responsive", "Non-Responsive", "Withdrawn"]
    new_status = request.form.get("responsive", "").strip()
    if new_status not in valid_statuses:
        flash("Choose a valid quotation evaluation status.", "error")
        return redirect(url_for("quotation_page", pid=pid))
    with db() as con:
        quotation = con.execute("SELECT id, responsive FROM quotations WHERE id=? AND procurement_id=?", (qid, pid)).fetchone()
        procurement = con.execute("SELECT pr_number FROM procurements WHERE id=?", (pid,)).fetchone()
        if not quotation or not procurement:
            abort(404)
        old_status = quotation["responsive"]
        con.execute("UPDATE quotations SET responsive=? WHERE id=? AND procurement_id=?", (new_status, qid, pid))
    audit("UPDATE", "quotation", qid, f"PR {procurement['pr_number']}: status changed from {old_status} to {new_status}")
    flash("Quotation status updated.", "success")
    return redirect(url_for("quotation_page", pid=pid))


@app.route("/procurements/<int:pid>/milestones", methods=["GET","POST"])
@login_required
def milestone_page(pid):
    with db() as con:
        p=con.execute("SELECT * FROM procurements WHERE id=?",(pid,)).fetchone()
    if not p: abort(404)
    if request.method=="POST":
        if not can_edit(): abort(403)
        stage=request.form.get("stage","").strip()
        if stage not in MILESTONE_STAGES:
            flash("Choose a valid milestone.","error")
        else:
            with db() as con:
                cur=con.execute("""INSERT INTO milestones(procurement_id,stage,action_date,reference_no,responsible_person,status,notes,created_by,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?)""",
                    (pid,stage,request.form.get("action_date","").strip(),request.form.get("reference_no","").strip(),
                     request.form.get("responsible_person","").strip(),request.form.get("status","Pending"),
                     request.form.get("notes","").strip(),session["user_id"],now()))
            audit("CREATE","milestone",cur.lastrowid,f"Milestone recorded for PR {p['pr_number']}: {stage}")
            flash("Milestone recorded.","success")
            return redirect(url_for("milestone_page",pid=pid))
    with db() as con:
        rows=con.execute("SELECT * FROM milestones WHERE procurement_id=? ORDER BY COALESCE(action_date,''),id",(pid,)).fetchall()
    return render_template("milestones.html",p=p,rows=rows,stages=MILESTONE_STAGES)


@app.route("/procurements/<int:pid>/checklist", methods=["GET","POST"])
@login_required
def checklist_page(pid):
    with db() as con:
        p=con.execute("SELECT * FROM procurements WHERE id=?",(pid,)).fetchone()
    if not p: abort(404)
    if request.method=="POST":
        if not can_edit(): abort(403)
        action=request.form.get("action","")
        if action=="seed":
            with db() as con:
                existing={r["item_name"] for r in con.execute("SELECT item_name FROM checklist_items WHERE procurement_id=?",(pid,)).fetchall()}
                for item in CHECKLIST_SUGGESTIONS:
                    if item not in existing:
                        con.execute("INSERT INTO checklist_items(procurement_id,item_name,updated_at) VALUES(?,?,?)",(pid,item,now()))
            audit("SEED","checklist",pid,"Default checklist added; confirm applicability")
            flash("Starter checklist added. Review applicability for the chosen procurement method.","success")
        elif action=="add":
            name=request.form.get("item_name","").strip()
            if name:
                with db() as con:
                    con.execute("INSERT INTO checklist_items(procurement_id,item_name,required_for,status,document_ref,notes,updated_at) VALUES(?,?,?,?,?,?,?)",
                        (pid,name,request.form.get("required_for","").strip(),request.form.get("status","Pending"),
                         request.form.get("document_ref","").strip(),request.form.get("notes","").strip(),now()))
                audit("CREATE","checklist",pid,f"Checklist item added: {name}")
                flash("Checklist item added.","success")
        elif action=="update":
            for key,val in request.form.items():
                if key.startswith("status_"):
                    item_id=key.split("_",1)[1]
                    with db() as con:
                        con.execute("UPDATE checklist_items SET status=?,updated_at=? WHERE id=? AND procurement_id=?",
                                    (val,now(),item_id,pid))
            audit("UPDATE","checklist",pid,"Checklist statuses updated")
            flash("Checklist statuses saved.","success")
        return redirect(url_for("checklist_page",pid=pid))
    with db() as con:
        rows=con.execute("SELECT * FROM checklist_items WHERE procurement_id=? ORDER BY id",(pid,)).fetchall()
    return render_template("checklist.html",p=p,rows=rows)


@app.route("/procurements/<int:pid>/delivery-payment", methods=["GET","POST"])
@login_required
def delivery_payment(pid):
    with db() as con:
        p=con.execute("SELECT * FROM procurements WHERE id=?",(pid,)).fetchone()
        row=con.execute("SELECT * FROM deliveries WHERE procurement_id=? ORDER BY id DESC LIMIT 1",(pid,)).fetchone()
    if not p: abort(404)
    if request.method=="POST":
        if not can_edit(): abort(403)
        fields=["delivery_date","inspection_date","acceptance_date","delivery_receipt_no","inspection_report_no",
                "acceptance_report_no","payment_status","payment_reference","notes"]
        vals=[request.form.get(k,"").strip() for k in fields]
        with db() as con:
            if row:
                con.execute("""UPDATE deliveries SET delivery_date=?,inspection_date=?,acceptance_date=?,delivery_receipt_no=?,
                    inspection_report_no=?,acceptance_report_no=?,payment_status=?,payment_reference=?,notes=?,updated_at=? WHERE id=?""",
                    (*vals,now(),row["id"]))
                did=row["id"]
            else:
                cur=con.execute("""INSERT INTO deliveries(delivery_date,inspection_date,acceptance_date,delivery_receipt_no,
                    inspection_report_no,acceptance_report_no,payment_status,payment_reference,notes,updated_at,procurement_id)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)""",(*vals,now(),pid))
                did=cur.lastrowid
        audit("UPDATE","delivery_payment",did,f"Delivery/payment tracking updated for PR {p['pr_number']}")
        flash("Delivery, inspection, acceptance and payment tracking saved.","success")
        return redirect(url_for("delivery_payment",pid=pid))
    return render_template("delivery_payment.html",p=p,row=row)


@app.route("/reports")
@login_required
def reports():
    start=request.args.get("start","").strip()
    end=request.args.get("end","").strip()
    status=request.args.get("status","").strip()
    method=request.args.get("method","").strip()
    sql="""SELECT p.*,s.name supplier_name FROM procurements p LEFT JOIN suppliers s ON s.id=p.supplier_id WHERE 1=1"""
    args=[]
    if start: sql+=" AND (p.pr_date='' OR p.pr_date>=?)"; args.append(start)
    if end: sql+=" AND (p.pr_date='' OR p.pr_date<=?)"; args.append(end)
    if status in STATUSES: sql+=" AND p.status=?"; args.append(status)
    if method: sql+=" AND p.procurement_method=?"; args.append(method)
    sql+=" ORDER BY p.pr_date DESC,p.pr_number"
    with db() as con:
        rows=con.execute(sql,args).fetchall()
    total_abc=sum(r["abc"] or 0 for r in rows)
    return render_template("reports.html",rows=rows,total_abc=total_abc,start=start,end=end,status=status,method=method,statuses=STATUSES,methods=METHODS)


@app.route("/import/csv", methods=["GET","POST"])
@login_required
def import_csv():
    if request.method=="POST":
        if not can_edit(): abort(403)
        f=request.files.get("file")
        if not f or not f.filename.lower().endswith(".csv"):
            flash("Upload a CSV file.","error"); return redirect(url_for("import_csv"))
        try:
            content=f.stream.read().decode("utf-8-sig")
            reader=csv.DictReader(io.StringIO(content))
            required={"pr_number","title"}
            if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
                flash("CSV must include at least these exact column headers: pr_number,title. Optional headers are listed below.","error")
                return redirect(url_for("import_csv"))
            added=0; skipped=0
            with db() as con:
                for item in reader:
                    pr=(item.get("pr_number") or "").strip()
                    title=(item.get("title") or "").strip()
                    if not pr or not title:
                        skipped+=1; continue
                    try:
                        abc=float((item.get("abc") or "0").replace(",","") or 0)
                        if abc<0: raise ValueError()
                        con.execute("""INSERT INTO procurements(pr_number,title,end_user,procurement_method,abc,funding_source,
                            ppmp_app_ref,pr_date,target_date,status,assigned_to,po_number,remarks,created_by,created_at,updated_at)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (pr,title,(item.get("end_user") or "").strip(),(item.get("procurement_method") or "").strip(),
                             abc,(item.get("funding_source") or "").strip(),(item.get("ppmp_app_ref") or "").strip(),
                             (item.get("pr_date") or "").strip(),(item.get("target_date") or "").strip(),
                             (item.get("status") or "Received").strip(),(item.get("assigned_to") or "").strip(),
                             (item.get("po_number") or "").strip(),(item.get("remarks") or "").strip(),
                             session["user_id"],now(),now()))
                        added+=1
                    except (sqlite3.IntegrityError,ValueError):
                        skipped+=1
            audit("IMPORT","procurement",None,f"CSV import: {added} added, {skipped} skipped")
            flash(f"Import finished: {added} added, {skipped} skipped (duplicates/invalid rows). Review records carefully.","success")
            return redirect(url_for("procurements"))
        except UnicodeDecodeError:
            flash("Could not read CSV as UTF-8. Save it as CSV UTF-8 and try again.","error")
    return render_template("import_csv.html")


@app.route("/reports/export.csv")
@login_required
def export_report_csv():
    start=request.args.get("start","").strip(); end=request.args.get("end","").strip()
    status=request.args.get("status","").strip(); method=request.args.get("method","").strip()
    sql="SELECT pr_number,title,end_user,procurement_method,abc,funding_source,ppmp_app_ref,pr_date,target_date,status,assigned_to,po_number,remarks FROM procurements WHERE 1=1"
    args=[]
    if start: sql+=" AND (pr_date='' OR pr_date>=?)"; args.append(start)
    if end: sql+=" AND (pr_date='' OR pr_date<=?)"; args.append(end)
    if status in STATUSES: sql+=" AND status=?"; args.append(status)
    if method: sql+=" AND procurement_method=?"; args.append(method)
    with db() as con: rows=con.execute(sql,args).fetchall()
    out=io.StringIO(); writer=csv.writer(out)
    writer.writerow(["PR Number","Title","End User","Procurement Method","ABC","Funding Source","PPMP/APP Ref","PR Date","Target Date","Status","Assigned To","PO Number","Remarks"])
    writer.writerows([tuple(r) for r in rows])
    audit("EXPORT","report",None,"Filtered report exported to CSV")
    return Response("\ufeff"+out.getvalue(),mimetype="text/csv",headers={"Content-Disposition":"attachment; filename=procurement_report.csv"})



@app.route("/drive")
@admin_required
def drive_settings():
    connected = bool(setting_get("google_oauth_credentials"))
    folder_id = setting_get("google_drive_folder_id") or ""
    return render_template("drive_settings.html", connected=connected, folder_id=folder_id, configured=drive_client_configured())

@app.route("/drive/connect")
@admin_required
def drive_connect():
    if not drive_client_configured():
        flash("Google OAuth client ID and secret are not configured on the hosting service.", "error")
        return redirect(url_for("drive_settings"))
    from google_auth_oauthlib.flow import Flow
    client_config = {"web": {"client_id": os.environ["GOOGLE_CLIENT_ID"], "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
        "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [os.environ.get("GOOGLE_REDIRECT_URI") or url_for("drive_callback", _external=True)]}}
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI") or url_for("drive_callback", _external=True)
    flow = Flow.from_client_config(client_config, scopes=["https://www.googleapis.com/auth/drive.file"], redirect_uri=redirect_uri)
    authorization_url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true", prompt="consent")
    session["google_oauth_state"] = state
    return redirect(authorization_url)

@app.route("/drive/callback")
@admin_required
def drive_callback():
    if not session.get("google_oauth_state") or request.args.get("state") != session.get("google_oauth_state"):
        abort(400, "OAuth state verification failed. Please restart Drive connection.")
    if request.args.get("error"):
        flash("Google Drive authorization was cancelled or denied.", "error")
        return redirect(url_for("drive_settings"))
    from google_auth_oauthlib.flow import Flow
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI") or url_for("drive_callback", _external=True)
    client_config = {"web": {"client_id": os.environ["GOOGLE_CLIENT_ID"], "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
        "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [redirect_uri]}}
    flow = Flow.from_client_config(client_config, scopes=["https://www.googleapis.com/auth/drive.file"], state=session.pop("google_oauth_state"), redirect_uri=redirect_uri)
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials
    encrypted = get_fernet().encrypt(creds.to_json().encode()).decode()
    setting_set("google_oauth_credentials", encrypted)
    try:
        folder_id = ensure_drive_folder()
        flash("Google Drive connected. The private NEXORA PH Procurement folder is ready.", "success")
    except Exception:
        app.logger.exception("Drive folder creation failed after OAuth")
        flash("Google authorization was saved, but the Drive folder could not be created. Check permissions and retry.", "error")
    return redirect(url_for("drive_settings"))

@app.route("/api/sync/manifest")
def sync_manifest():
    require_sync_token()
    entries = []
    with db() as con:
        for table, kind, parent_col in (("documents", "procurement", "procurement_id"), ("plan_documents", "plan", "plan_id")):
            rows = con.execute(f"SELECT id, original_name, stored_name, drive_file_id, sha256, uploaded_at FROM {table} WHERE COALESCE(drive_file_id,'') <> '' ORDER BY id").fetchall()
            for r in rows:
                entries.append({"kind": kind, "id": r["id"], "original_name": r["original_name"], "stored_name": r["stored_name"], "drive_file_id": r["drive_file_id"], "sha256": r["sha256"], "uploaded_at": r["uploaded_at"]})
    return jsonify({"files": entries})

@app.route("/api/sync/file/<kind>/<int:doc_id>")
def sync_file(kind, doc_id):
    require_sync_token()
    table = {"procurement": "documents", "plan": "plan_documents"}.get(kind)
    if not table:
        abort(404)
    with db() as con:
        doc = con.execute(f"SELECT original_name, stored_name, drive_file_id, sha256 FROM {table} WHERE id=?", (doc_id,)).fetchone()
    if not doc or not doc["drive_file_id"]:
        abort(404)
    try:
        data = drive_file_bytes(doc["drive_file_id"])
    except Exception:
        app.logger.exception("Sync download from Drive failed")
        abort(503)
    response = send_file(BytesIO(data), as_attachment=True, download_name=doc["stored_name"])
    response.headers["X-Nexora-SHA256"] = hashlib.sha256(data).hexdigest()
    return response

@app.errorhandler(403)
def forbidden(_):
    return render_template("message.html", title="Access denied", message="Your account does not have permission to view this page."), 403


@app.errorhandler(413)
def too_large(_):
    return render_template("message.html", title="File too large", message="The maximum upload size is 20 MB."), 413


@app.errorhandler(500)
def server_error(_):
    return render_template("message.html", title="Application error", message="The app encountered an error. Check the server console; do not retry sensitive actions until the issue is understood."), 500


init_db()

if __name__ == "__main__":
    host = os.environ.get("PROCURETRACK_HOST", "127.0.0.1")
    port = int(os.environ.get("PROCURETRACK_PORT", "5000"))
    print("\nNEXORA PH — Procurement Command Center is starting.")
    print("Open this computer: http://127.0.0.1:5000")
    if host == "0.0.0.0":
        print("LAN mode enabled. Find this computer's LAN IPv4 address with ipconfig.")
        print("Pilot use only: restrict firewall access to the private office network.")
    print("Stop the server with CTRL+C.\n")
    app.run(host=host, port=port, debug=False)
