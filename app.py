"""یابنده: سامانهٔ فارسی ثبت و جست‌وجوی اشیای گم‌شده و پیدا‌شده."""

from __future__ import annotations

import io
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import unicodedata
import uuid
from datetime import datetime, timezone
from difflib import SequenceMatcher
from email.message import EmailMessage
from email.utils import parseaddr
from functools import wraps
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFError, CSRFProtect
from PIL import Image, ImageOps, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


csrf = CSRFProtect()
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 25_000_000
ALLOWED_IMAGE_FORMATS = {"JPEG", "PNG", "WEBP", "GIF"}
ITEM_TYPES = ("موبایل", "زیورآلات", "کارت", "کتاب", "کیف", "کلید", "هدفون", "سایر")
STATUSES = ("lost", "found")
SAMPLE_SEED_KEY = "persian-samples-v1"
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

SAMPLE_ITEMS = (
    ("گوشی اندرویدی", "موبایل", "found", "کتابخانه مرکزی", "مشکی", "گوشی مشکی کنار میز مطالعه پیدا شده است."),
    ("دسته‌کلید با جاکلیدی آبی", "کلید", "found", "سلف دانشگاه", "نقره‌ای و آبی", "سه کلید با جاکلیدی آبی نزدیک ورودی جا مانده بود."),
    ("کیف پارچه‌ای", "کیف", "found", "ساختمان کلاس‌ها، طبقه دوم", "سرمه‌ای", "یک کیف پارچه‌ای سرمه‌ای در راهرو پیدا شد."),
    ("کتاب برنامه‌نویسی", "کتاب", "found", "آزمایشگاه رایانه", "سفید و آبی", "کتابی روی میز انتهایی جا مانده است."),
    ("کارت دانشجویی", "کارت", "found", "ورودی دانشکده", "سفید", "یک کارت پیدا شده؛ مالک باید برای تحویل مشخصات آن را اعلام کند."),
    ("هدفون بی‌سیم", "هدفون", "lost", "سالن مطالعه", "سفید", "هدفون سفید در محدودهٔ سالن مطالعه گم شده است."),
    ("انگشتر ساده", "زیورآلات", "lost", "طبقه اول", "نقره‌ای", "یک انگشتر ساده با رنگ نقره‌ای گم شده است."),
    ("کیف پول کوچک", "کیف", "lost", "محوطه حیاط", "قهوه‌ای", "کیف پول کوچک قهوه‌ای در محوطه گم شده است."),
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _environment_name() -> str:
    return (
        os.environ.get("APP_ENV")
        or os.environ.get("FLASK_ENV")
        or os.environ.get("ENVIRONMENT")
        or "development"
    ).strip().lower()


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app_env = _environment_name()
    secret_key = os.environ.get("SECRET_KEY", "").strip()
    if app_env in {"production", "prod"} and (
        len(secret_key) < 32 or secret_key.startswith("replace-with-")
    ):
        raise RuntimeError(
            "در محیط تولید باید SECRET_KEY تصادفی و دست‌کم ۳۲ نویسه‌ای تنظیم کنید."
        )
    if not secret_key:
        secret_key = secrets.token_urlsafe(48)
        app.logger.warning(
            "SECRET_KEY تنظیم نشده است؛ کلید موقت فقط برای اجرای توسعه ساخته شد."
        )

    default_db = Path(app.instance_path) / "yabande.sqlite3"
    default_uploads = Path(app.root_path) / "static" / "uploads"
    app.config.from_mapping(
        SECRET_KEY=secret_key,
        APP_ENV=app_env,
        DATABASE_PATH=os.environ.get("DATABASE_PATH", str(default_db)),
        UPLOAD_DIR=os.environ.get("UPLOAD_DIR", str(default_uploads)),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES + 256 * 1024,
        WTF_CSRF_ENABLED=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=app_env in {"production", "prod"},
        PERMANENT_SESSION_LIFETIME=60 * 60 * 12,
        SMTP_HOST=os.environ.get("SMTP_HOST", ""),
        SMTP_PORT=os.environ.get("SMTP_PORT", "587"),
        SMTP_USER=os.environ.get("SMTP_USER", ""),
        SMTP_PASSWORD=os.environ.get("SMTP_PASSWORD", ""),
        MAIL_FROM=os.environ.get("MAIL_FROM", ""),
        PUBLIC_BASE_URL=os.environ.get("PUBLIC_BASE_URL", "").rstrip("/"),
    )
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    upload_directory = Path(app.config["UPLOAD_DIR"]).expanduser()
    if not upload_directory.is_absolute():
        upload_directory = Path(app.root_path) / upload_directory
    app.config["UPLOAD_DIR"] = str(upload_directory.resolve())
    upload_directory.mkdir(parents=True, exist_ok=True)
    csrf.init_app(app)
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        return (
            render_template("error.html", message="درخواست منقضی یا نامعتبر است؛ صفحه را تازه کنید."),
            400,
        )

    @app.errorhandler(413)
    def handle_too_large(_error):
        flash("حجم عکس یا درخواست بیش از حد مجاز است؛ عکس باید حداکثر ۵ مگابایت باشد.", "error")
        return redirect(url_for("new_item")), 303

    @app.errorhandler(404)
    def handle_not_found(_error):
        return render_template("error.html", message="صفحه یا آگهی موردنظر پیدا نشد."), 404

    @app.cli.command("init-db")
    def init_db_command():
        """ساخت یا به‌روزرسانی جدول‌ها و افزودن نمونه‌ها در پایگاه خالی."""
        init_db()
        print("پایگاه داده آماده است.")

    @app.template_filter("item_image")
    def item_image(value: str | None) -> str:
        if not value:
            return ""
        value = str(value)
        if value.startswith("/static/uploads/") or value.startswith("https://"):
            return value
        if value.startswith("uploads/"):
            value = value.removeprefix("uploads/")
        if "/" in value or value in {".", ".."}:
            return ""
        return url_for("uploaded_file", filename=value)

    @app.route("/")
    def home():
        if not current_user():
            return redirect(url_for("login"))
        return redirect(url_for("browse"))

    @app.route("/health")
    def health():
        return jsonify(status="ok"), 200

    @app.route("/browse")
    def browse():
        status = request.args.get("status", "found").strip()
        if status not in {"found", "lost", "all"}:
            status = "found"
        query = request.args.get("q", "").strip()[:100]
        kind = request.args.get("kind", "").strip()
        sql = (
            "SELECT items.*, users.username FROM items "
            "JOIN users ON users.id=items.user_id WHERE 1=1"
        )
        args: list[str] = []
        if status != "all":
            sql += " AND items.status=?"
            args.append(status)
        if query:
            normalized_query = _normalize_text(query)
            if normalized_query:
                sql += (
                    " AND (normalize_text(items.item_name) LIKE ? "
                    "OR normalize_text(items.location) LIKE ? "
                    "OR normalize_text(items.color) LIKE ? "
                    "OR normalize_text(items.description) LIKE ?)"
                )
                args.extend([f"%{normalized_query}%"] * 4)
        if kind in ITEM_TYPES:
            sql += " AND items.item_type=?"
            args.append(kind)
        sql += " ORDER BY items.id DESC"
        items = get_db().execute(sql, args).fetchall()
        types = [
            row["item_type"]
            for row in get_db().execute(
                "SELECT DISTINCT item_type FROM items ORDER BY item_type"
            ).fetchall()
        ]
        return render_template(
            "home.html",
            items=items,
            status=status,
            q=query,
            kind=kind,
            types=types,
            user=current_user(),
        )

    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if not username or len(username) > 60 or not is_valid_email(email):
                flash("نام کاربری و یک ایمیل معتبر وارد کنید.", "error")
            elif len(password) < 8 or len(password) > 256:
                flash("رمز عبور باید دست‌کم ۸ و حداکثر ۲۵۶ نویسه باشد.", "error")
            else:
                try:
                    cursor = get_db().execute(
                        "INSERT INTO users(username,email,password_hash,created_at) "
                        "VALUES(?,?,?,?)",
                        (username, email, generate_password_hash(password), _utc_now()),
                    )
                    get_db().commit()
                    session.clear()
                    session["user_id"] = cursor.lastrowid
                    session.permanent = True
                    flash("حساب کاربری ساخته شد. خوش آمدید!", "success")
                    return redirect(url_for("home"))
                except sqlite3.IntegrityError:
                    get_db().rollback()
                    flash("این ایمیل قبلاً ثبت شده است.", "error")
        return render_template("signup.html", user=current_user())

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = get_db().execute(
                "SELECT id, password_hash FROM users WHERE email=? COLLATE NOCASE",
                (email,),
            ).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session.permanent = True
                return redirect(url_for("home"))
            flash("ایمیل یا رمز عبور درست نیست.", "error")
        return render_template("login.html", user=current_user())

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        flash("از حساب کاربری خارج شدید.", "success")
        return redirect(url_for("login"))

    @app.route("/item/new", methods=["GET", "POST"])
    @login_required
    def new_item():
        user = current_user()
        if request.method == "POST":
            form = request.form
            name = form.get("item_name", "").strip()
            item_type = form.get("item_type", "").strip()
            status = form.get("status", "").strip()
            location = form.get("location", "").strip()
            color = form.get("color", "").strip()
            contact_email = form.get("contact_email", "").strip().lower()
            description = form.get("description", "").strip()
            upload = request.files.get("image_file")

            if (
                not name
                or len(name) > 80
                or item_type not in ITEM_TYPES
                or status not in STATUSES
                or not location
                or len(location) > 120
                or not color
                or len(color) > 60
                or not is_valid_email(contact_email)
                or len(contact_email) > 254
                or not description
                or len(description) > 180
            ):
                flash("اطلاعات را بررسی کنید؛ فیلدها باید معتبر و توضیحات حداکثر ۱۸۰ نویسه باشد.", "error")
            else:
                image_name = None
                try:
                    if upload and upload.filename:
                        image_name = save_uploaded_image(upload)
                except ValueError as error:
                    flash(str(error), "error")
                    return render_template("new_item.html", user=user), 400
                cursor = get_db().execute(
                    "INSERT INTO items(user_id,item_name,item_type,status,location,color,"
                    "contact_email,description,image_url,created_at,is_demo) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,0)",
                    (
                        user["id"],
                        name,
                        item_type,
                        status,
                        location,
                        color,
                        contact_email,
                        description,
                        image_name,
                        _utc_now(),
                    ),
                )
                get_db().commit()
                match_items(cursor.lastrowid)
                flash("آگهی ثبت شد و موارد مشابه بررسی شدند.", "success")
                return redirect(url_for("detail", item_id=cursor.lastrowid))
        return render_template("new_item.html", user=user)

    @app.route("/item/<int:item_id>")
    def detail(item_id: int):
        item = get_db().execute(
            "SELECT items.*, users.username FROM items "
            "JOIN users ON users.id=items.user_id WHERE items.id=?",
            (item_id,),
        ).fetchone()
        if not item:
            abort(404)
        user = current_user()
        return render_template(
            "detail.html",
            item=item,
            user=user,
            show_contact=bool(user),
        )

    @app.route("/my-items")
    @login_required
    def my_items():
        items = get_db().execute(
            "SELECT * FROM items WHERE user_id=? ORDER BY id DESC",
            (session["user_id"],),
        ).fetchall()
        return render_template("my_items.html", items=items, user=current_user())

    @app.route("/item/<int:item_id>/delete", methods=["POST"])
    @login_required
    def delete_item(item_id: int):
        item = get_db().execute(
            "SELECT user_id, image_url FROM items WHERE id=?", (item_id,)
        ).fetchone()
        if not item or item["user_id"] != session["user_id"]:
            flash("اجازهٔ حذف این آگهی را ندارید.", "error")
            return redirect(url_for("my_items"))
        get_db().execute("DELETE FROM items WHERE id=?", (item_id,))
        get_db().commit()
        delete_uploaded_file(item["image_url"])
        flash("آگهی حذف شد.", "success")
        return redirect(url_for("my_items"))

    @app.route("/uploads/<path:filename>")
    def uploaded_file(filename: str):
        if "/" in filename or "\\" in filename or filename in {".", ".."}:
            abort(404)
        return send_from_directory(current_app.config["UPLOAD_DIR"], filename)

    return app


def _resolved_database_path() -> str:
    path = os.path.expanduser(str(current_app.config["DATABASE_PATH"]))
    if path == ":memory:":
        return path
    database = Path(path)
    if not database.is_absolute():
        database = Path(current_app.root_path) / database
    database.parent.mkdir(parents=True, exist_ok=True)
    return str(database)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        connection = sqlite3.connect(
            _resolved_database_path(),
            timeout=30,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.create_function(
            "normalize_text", 1, _normalize_text, deterministic=True
        )
        g.db = connection
    return g.db


def close_db(_error: BaseException | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db() -> None:
    """Create schema, migrate the supplied older schema, and seed a blank DB once."""
    connection = get_db()
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            item_name TEXT NOT NULL,
            item_type TEXT NOT NULL,
            status TEXT NOT NULL,
            location TEXT NOT NULL,
            color TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            description TEXT NOT NULL,
            image_url TEXT,
            created_at TEXT NOT NULL,
            is_demo INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS matches (
            id INTEGER PRIMARY KEY,
            lost_item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
            found_item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            notified INTEGER NOT NULL DEFAULT 0,
            UNIQUE(lost_item_id, found_item_id)
        );
        CREATE TABLE IF NOT EXISTS app_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )
    connection.execute("BEGIN IMMEDIATE")
    item_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(items)").fetchall()
    }
    added_demo_column = "is_demo" not in item_columns
    if added_demo_column:
        connection.execute(
            "ALTER TABLE items ADD COLUMN is_demo INTEGER NOT NULL DEFAULT 0"
        )
        legacy_sample = connection.execute(
            "SELECT id FROM users WHERE email=? COLLATE NOCASE",
            ("demo@yabande.local",),
        ).fetchone()
        if legacy_sample:
            # The supplied older release published a known demo password and fake
            # contact address. Retire that synthetic account and label its records.
            connection.execute(
                "UPDATE items SET is_demo=1, contact_email='' WHERE user_id=?",
                (legacy_sample["id"],),
            )
            connection.execute(
                "UPDATE users SET password_hash=? WHERE id=?",
                (
                    generate_password_hash(secrets.token_urlsafe(48)),
                    legacy_sample["id"],
                ),
            )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_items_status_created ON items(status, id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_items_user_created ON items(user_id, id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_matches_lost_found "
        "ON matches(lost_item_id, found_item_id)"
    )

    seeded = connection.execute(
        "SELECT 1 FROM app_metadata WHERE key=?", (SAMPLE_SEED_KEY,)
    ).fetchone()
    if not seeded:
        existing_items = connection.execute("SELECT COUNT(*) FROM items").fetchone()[0]
        if existing_items == 0:
            sample_user = connection.execute(
                "SELECT id FROM users WHERE email=?",
                ("sample-data@invalid.example",),
            ).fetchone()
            if sample_user:
                sample_user_id = sample_user["id"]
            else:
                cursor = connection.execute(
                    "INSERT INTO users(username,email,password_hash,created_at) "
                    "VALUES(?,?,?,?)",
                    (
                        "آگهی نمونه",
                        "sample-data@invalid.example",
                        generate_password_hash(secrets.token_urlsafe(48)),
                        _utc_now(),
                    ),
                )
                sample_user_id = cursor.lastrowid
            now = _utc_now()
            connection.executemany(
                "INSERT INTO items(user_id,item_name,item_type,status,location,color,"
                "contact_email,description,image_url,created_at,is_demo) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,1)",
                [
                    (
                        sample_user_id,
                        name,
                        item_type,
                        status,
                        location,
                        color,
                        "",
                        description,
                        None,
                        now,
                    )
                    for name, item_type, status, location, color, description in SAMPLE_ITEMS
                ],
            )
        # Mark the seed attempt even if an existing, non-empty database was supplied:
        # existing user data must never be changed by later restarts.
        connection.execute(
            "INSERT OR IGNORE INTO app_metadata(key,value) VALUES(?,?)",
            (SAMPLE_SEED_KEY, "done"),
        )
    connection.commit()


def is_valid_email(value: str) -> bool:
    if not value or len(value) > 254:
        return False
    _, parsed = parseaddr(value)
    return parsed == value and bool(EMAIL_RE.fullmatch(value))


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_db().execute(
        "SELECT id,username,email FROM users WHERE id=?", (user_id,)
    ).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("برای انجام این کار ابتدا وارد حساب کاربری شوید.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def _normalize_text(value: str | None) -> str:
    value = unicodedata.normalize("NFKC", value or "").translate(
        str.maketrans({"ي": "ی", "ى": "ی", "ك": "ک", "ۀ": "ه", "ة": "ه"})
    )
    value = value.replace("\u200c", " ").replace("\u200f", "").replace("\u200e", "")
    value = "".join(
        character
        for character in value
        if unicodedata.category(character) not in {"Mn", "Me", "Cf"}
    )
    value = re.sub(r"[^\w\s]", " ", value, flags=re.UNICODE)
    return " ".join(value.casefold().split())


def _text_similarity(left: str | None, right: str | None) -> float:
    first, second = _normalize_text(left), _normalize_text(right)
    if not first or not second:
        return 0.0
    if first == second:
        return 1.0
    first_words, second_words = set(first.split()), set(second.split())
    dice = (
        2 * len(first_words & second_words) / (len(first_words) + len(second_words))
        if first_words or second_words
        else 0.0
    )
    sequence = SequenceMatcher(None, first, second).ratio()
    return max(dice, sequence)


def score_match(lost_item, found_item) -> dict[str, Any]:
    """Return a transparent weighted score and plausible-match decision."""
    type_score = _text_similarity(lost_item["item_type"], found_item["item_type"])
    name_score = _text_similarity(lost_item["item_name"], found_item["item_name"])
    color_score = _text_similarity(lost_item["color"], found_item["color"])
    location_score = _text_similarity(lost_item["location"], found_item["location"])
    description_score = _text_similarity(
        lost_item["description"], found_item["description"]
    )
    score = (
        0.40 * name_score
        + 0.20 * color_score
        + 0.20 * location_score
        + 0.20 * description_score
    )
    same_category = type_score >= 0.75
    evidence = name_score >= 0.50 or (
        color_score >= 0.80 and location_score >= 0.60
    )
    return {
        "score": round(score, 4),
        "plausible": same_category and score >= 0.50 and evidence,
        "type": round(type_score, 4),
        "name": round(name_score, 4),
        "color": round(color_score, 4),
        "location": round(location_score, 4),
        "description": round(description_score, 4),
    }


def match_items(new_item_id: int) -> list[dict[str, Any]]:
    """Create unique lost/found matches and try one notification per new match."""
    connection = get_db()
    new_item = connection.execute(
        "SELECT * FROM items WHERE id=?", (new_item_id,)
    ).fetchone()
    if not new_item or new_item["is_demo"]:
        return []
    opposite_status = "lost" if new_item["status"] == "found" else "found"
    others = connection.execute(
        "SELECT * FROM items WHERE status=? AND id<>? AND is_demo=0",
        (opposite_status, new_item_id),
    ).fetchall()
    created_matches = []
    for other in others:
        lost_item = new_item if new_item["status"] == "lost" else other
        found_item = new_item if new_item["status"] == "found" else other
        score = score_match(lost_item, found_item)
        if not score["plausible"]:
            continue
        cursor = connection.execute(
            "INSERT OR IGNORE INTO matches(lost_item_id,found_item_id,created_at,notified) "
            "VALUES(?,?,?,0)",
            (lost_item["id"], found_item["id"], _utc_now()),
        )
        connection.commit()
        if cursor.rowcount != 1:
            continue

        result = {
            "lost_item_id": lost_item["id"],
            "found_item_id": found_item["id"],
            **score,
        }
        created_matches.append(result)
        if not lost_item["contact_email"]:
            current_app.logger.warning(
                "تطبیق %s/%s ثبت شد؛ ایمیل گزارش‌دهندهٔ آگهی گم‌شده در دسترس نیست.",
                lost_item["id"],
                found_item["id"],
            )
            continue
        listing_url = _listing_url(found_item["id"])
        body = (
            "سلام،\n\n"
            "یک آگهی پیدا‌شده با آگهی گم‌شدهٔ شما شباهت دارد. این فقط یک پیشنهاد است؛ "
            "پیش از تحویل، مالکیت وسیله را بررسی کنید.\n\n"
            f"وسیله: {found_item['item_name']}\n"
            f"نوع: {found_item['item_type']}\n"
            f"رنگ: {found_item['color']}\n"
            f"محل: {found_item['location']}\n"
            f"توضیحات: {found_item['description']}\n"
            f"مشاهدهٔ آگهی: {listing_url}\n"
        )
        if send_email(
            lost_item["contact_email"],
            "احتمال پیدا شدن وسیلهٔ شما - یابنده",
            body,
        ):
            connection.execute(
                "UPDATE matches SET notified=1 WHERE lost_item_id=? AND found_item_id=?",
                (lost_item["id"], found_item["id"]),
            )
            connection.commit()
    return created_matches


def _listing_url(item_id: int) -> str:
    path = url_for("detail", item_id=item_id)
    base_url = current_app.config.get("PUBLIC_BASE_URL")
    if base_url:
        return f"{base_url}{path}"
    return url_for("detail", item_id=item_id, _external=True)


def send_email(to: str, subject: str, body: str) -> bool:
    host = str(current_app.config.get("SMTP_HOST", "")).strip()
    user = str(current_app.config.get("SMTP_USER", "")).strip()
    password = str(current_app.config.get("SMTP_PASSWORD", ""))
    mail_from = str(current_app.config.get("MAIL_FROM", "")).strip() or user
    try:
        port = int(current_app.config.get("SMTP_PORT", 587))
    except (TypeError, ValueError):
        current_app.logger.warning("SMTP_PORT نامعتبر است؛ ایمیل ارسال نشد.")
        return False
    if not (host and user and password and mail_from):
        current_app.logger.warning(
            "تنظیمات SMTP کامل نیست؛ آگهی ثبت شد اما ایمیل تطبیق ارسال نشد."
        )
        return False
    if not is_valid_email(to) or not is_valid_email(user) or not is_valid_email(mail_from):
        current_app.logger.warning("نشانی ایمیل SMTP یا گیرنده معتبر نیست؛ ایمیل ارسال نشد.")
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = mail_from
    message["To"] = to
    message.set_content(body)
    try:
        if port == 465:
            with smtplib.SMTP_SSL(
                host, port, timeout=15, context=ssl.create_default_context()
            ) as server:
                server.login(user, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=15) as server:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
                server.login(user, password)
                server.send_message(message)
        return True
    except (OSError, smtplib.SMTPException, ssl.SSLError) as error:
        # Avoid printing server responses or configuration values into shared logs.
        current_app.logger.warning(
            "ارسال ایمیل انجام نشد (نوع خطا: %s).", type(error).__name__
        )
        return False


def save_uploaded_image(upload) -> str:
    if not upload or not upload.filename:
        raise ValueError("فایلی برای بارگذاری انتخاب نشده است.")
    # The name is not used as a filesystem path; it is only checked for a plausible extension.
    original_name = secure_filename(upload.filename)
    extension = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
    if extension not in {"png", "jpg", "jpeg", "webp", "gif"}:
        raise ValueError("فرمت عکس باید PNG، JPG، JPEG، WEBP یا GIF باشد.")
    data = upload.stream.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("حجم عکس باید حداکثر ۵ مگابایت باشد.")
    if not data:
        raise ValueError("فایل عکس خالی است.")
    try:
        with Image.open(io.BytesIO(data)) as source:
            image_format = source.format
            if image_format not in ALLOWED_IMAGE_FORMATS:
                raise ValueError("محتوای فایل عکس پشتیبانی نمی‌شود.")
            if source.width * source.height > MAX_IMAGE_PIXELS:
                raise ValueError("ابعاد عکس بیش از حد مجاز است.")
            source.seek(0)
            clean_image = ImageOps.exif_transpose(source).copy()
            if image_format == "JPEG":
                clean_image = clean_image.convert("RGB")
            elif image_format in {"PNG", "WEBP"} and clean_image.mode not in {
                "RGB",
                "RGBA",
            }:
                clean_image = clean_image.convert("RGBA")
            elif image_format == "GIF":
                clean_image.seek(0)
                clean_image = clean_image.convert("RGBA")
                image_format = "PNG"
            output = io.BytesIO()
            clean_image.save(output, format=image_format, optimize=True)
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        raise ValueError("فایل انتخاب‌شده یک عکس معتبر نیست.") from None

    safe_extension = {"JPEG": "jpg", "PNG": "png", "WEBP": "webp"}[image_format]
    filename = f"{uuid.uuid4().hex}.{safe_extension}"
    upload_dir = Path(current_app.config["UPLOAD_DIR"]).expanduser()
    upload_dir.mkdir(parents=True, exist_ok=True)
    (upload_dir / filename).write_bytes(output.getvalue())
    return filename


def delete_uploaded_file(filename: str | None) -> None:
    if not filename:
        return
    filename = str(filename)
    if filename.startswith("uploads/"):
        filename = filename.removeprefix("uploads/")
    if "/" in filename or "\\" in filename or filename in {".", ".."}:
        return
    try:
        (Path(current_app.config["UPLOAD_DIR"]).expanduser() / filename).unlink(
            missing_ok=True
        )
    except OSError:
        current_app.logger.warning("حذف فایل عکس آگهی انجام نشد.")


app = create_app()


if __name__ == "__main__":
    debug = app.config["APP_ENV"] not in {"production", "prod"} and (
        os.environ.get("FLASK_DEBUG", "0") == "1"
    )
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=debug,
    )
