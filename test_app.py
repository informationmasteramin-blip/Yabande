import io
import os
import re
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image
from werkzeug.security import check_password_hash, generate_password_hash

os.environ.setdefault("SECRET_KEY", "unit-test-key-that-is-not-used-for-deployment")

from app import create_app, get_db, match_items, score_match  # noqa: E402


class MockSMTPServer:
    """SMTP server stand-in: records accepted messages without network access."""

    sent_messages = []
    logins = []

    def __init__(self, *args, **kwargs):
        self.connection = (args, kwargs)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def ehlo(self):
        return 250, b"ok"

    def starttls(self, **kwargs):
        return 220, b"ready"

    def login(self, user, password):
        self.logins.append((user, password))

    def send_message(self, message):
        self.sent_messages.append(message)


class YabandeTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = os.path.join(self.temp_dir.name, "data", "test.sqlite3")
        self.upload_dir = os.path.join(self.temp_dir.name, "uploads")
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-only-secret-key",
                "DATABASE_PATH": self.database,
                "UPLOAD_DIR": self.upload_dir,
                "SMTP_HOST": "",
                "SMTP_PORT": "587",
                "SMTP_USER": "",
                "SMTP_PASSWORD": "",
                "MAIL_FROM": "",
                "WTF_CSRF_ENABLED": True,
            }
        )
        self.client = self.app.test_client()
        MockSMTPServer.sent_messages.clear()
        MockSMTPServer.logins.clear()

    def tearDown(self):
        self.temp_dir.cleanup()

    def csrf_token(self, path):
        response = self.client.get(path)
        if response.status_code == 405:
            response = self.client.get("/browse")
        self.assertEqual(response.status_code, 200)
        match = re.search(
            rb'name="csrf_token"[^>]*value="([^"]+)"|'
            rb'name="csrf_token" value="([^"]+)"',
            response.data,
        )
        self.assertIsNotNone(match, f"CSRF token missing from {path}")
        return next(group for group in match.groups() if group).decode()

    def post_form(self, path, data, **kwargs):
        data = dict(data)
        data["csrf_token"] = self.csrf_token(path)
        return self.client.post(path, data=data, **kwargs)

    def logout(self):
        token = self.csrf_token("/browse")
        return self.client.post("/logout", data={"csrf_token": token})

    def signup(self, email="owner@example.com", username="کاربر"):
        return self.post_form(
            "/signup",
            {
                "username": username,
                "email": email,
                "password": "safe-test-password",
            },
        )

    @staticmethod
    def listing_data(**overrides):
        values = {
            "item_name": "گوشی سامسونگ مشکی",
            "item_type": "موبایل",
            "status": "lost",
            "location": "کتابخانه مرکزی",
            "color": "مشکی",
            "contact_email": "owner@example.com",
            "description": "گوشی مشکی کنار میز مطالعه گم شده است.",
        }
        values.update(overrides)
        return values

    def create_listing(self, **overrides):
        return self.post_form("/item/new", self.listing_data(**overrides))

    def test_root_redirect_health_and_public_browse(self):
        root = self.client.get("/")
        self.assertEqual(root.status_code, 302)
        self.assertEqual(root.headers["Location"], "/login")
        self.assertEqual(self.client.get("/health").json, {"status": "ok"})
        browse = self.client.get("/browse?status=all")
        self.assertEqual(browse.status_code, 200)
        self.assertEqual(browse.data.count("نمونه نمایشی".encode()), 8)
        self.assertIn("گوشی اندرویدی".encode(), browse.data)
        self.assertEqual(self.client.get("/item/99999").status_code, 404)

    def test_signup_login_hash_and_csrf(self):
        rejected = self.client.post(
            "/signup",
            data={
                "username": "مینا",
                "email": "mina@example.com",
                "password": "safe-test-password",
            },
        )
        self.assertEqual(rejected.status_code, 400)

        response = self.signup("mina@example.com", "مینا")
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            user = get_db().execute(
                "SELECT password_hash FROM users WHERE email=?",
                ("mina@example.com",),
            ).fetchone()
            self.assertTrue(check_password_hash(user["password_hash"], "safe-test-password"))
            self.assertNotEqual(user["password_hash"], "safe-test-password")

        self.logout()
        login = self.post_form(
            "/login",
            {"email": "mina@example.com", "password": "safe-test-password"},
        )
        self.assertEqual(login.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 302)
        wrong = self.post_form(
            "/login",
            {"email": "mina@example.com", "password": "wrong-password"},
        )
        self.assertEqual(wrong.status_code, 200)
        self.assertIn("ایمیل یا رمز عبور درست نیست".encode(), wrong.data)

    def test_access_listing_creation_search_detail_and_owner_delete(self):
        self.assertEqual(self.client.get("/item/new").status_code, 302)
        self.assertEqual(self.client.get("/my-items").status_code, 302)
        self.signup()
        response = self.create_listing()
        self.assertEqual(response.status_code, 302)
        detail = self.client.get(response.headers["Location"])
        self.assertEqual(detail.status_code, 200)
        self.assertIn("گوشی سامسونگ مشکی".encode(), detail.data)
        self.assertIn("کتابخانه مرکزی".encode(), detail.data)
        self.assertIn("تاریخ ثبت".encode(), detail.data)
        self.assertIn(
            "گوشی سامسونگ".encode(),
            self.client.get("/browse?status=lost&q=گوشى").data,
        )
        self.assertIn(
            "گوشی سامسونگ".encode(),
            self.client.get("/browse?status=lost&kind=موبایل").data,
        )
        self.assertNotIn(
            "گوشی سامسونگ".encode(),
            self.client.get("/browse?status=found&q=سامسونگ").data,
        )
        mine = self.client.get("/my-items")
        self.assertIn("گوشی سامسونگ مشکی".encode(), mine.data)

        item_id = int(response.headers["Location"].rsplit("/", 1)[1])
        delete = self.post_form(f"/item/{item_id}/delete", {})
        self.assertEqual(delete.status_code, 302)
        with self.app.app_context():
            self.assertIsNone(
                get_db().execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
            )

    def test_users_cannot_delete_another_users_item(self):
        self.signup("first@example.com", "اول")
        response = self.create_listing(item_name="کیف خودم")
        item_id = int(response.headers["Location"].rsplit("/", 1)[1])
        self.logout()
        self.signup("second@example.com", "دوم")
        denied = self.post_form(f"/item/{item_id}/delete", {})
        self.assertEqual(denied.status_code, 302)
        with self.app.app_context():
            self.assertIsNotNone(
                get_db().execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
            )

    def test_private_contact_and_invalid_form_values(self):
        self.signup()
        response = self.create_listing(contact_email="person.private@example.com")
        item_url = response.headers["Location"]
        signed_in_detail = self.client.get(item_url)
        self.assertIn("person.private@example.com".encode(), signed_in_detail.data)
        self.logout()
        public_detail = self.client.get(item_url)
        self.assertNotIn("person.private@example.com".encode(), public_detail.data)
        self.post_form(
            "/login",
            {"email": "owner@example.com", "password": "safe-test-password"},
        )
        bad = self.post_form(
            "/item/new",
            self.listing_data(description="الف" * 181),
        )
        self.assertEqual(bad.status_code, 200)
        self.assertIn("حداکثر ۱۸۰".encode(), bad.data)

    def test_valid_image_is_stored_safely_and_non_image_is_rejected(self):
        self.signup()
        image = Image.new("RGB", (16, 12), "purple")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        buffer.seek(0)
        form = self.listing_data()
        form["image_file"] = (buffer, "test.png")
        response = self.post_form(
            "/item/new",
            form,
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            stored = get_db().execute(
                "SELECT image_url FROM items WHERE is_demo=0 ORDER BY id DESC LIMIT 1"
            ).fetchone()["image_url"]
        self.assertRegex(stored, r"^[a-f0-9]{32}\.png$")
        image_response = self.client.get(f"/uploads/{stored}")
        self.assertEqual(image_response.status_code, 200)
        self.assertEqual(image_response.mimetype, "image/png")
        image_response.close()

        form = self.listing_data(item_name="فایل جعلی")
        form["image_file"] = (io.BytesIO(b"not an image"), "fake.png")
        invalid = self.post_form(
            "/item/new",
            form,
            content_type="multipart/form-data",
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertIn("عکس معتبر نیست".encode(), invalid.data)

        too_large = self.listing_data(item_name="عکس حجیم")
        too_large["image_file"] = (
            io.BytesIO(b"x" * (5 * 1024 * 1024 + 1)),
            "large.jpg",
        )
        oversized = self.post_form(
            "/item/new",
            too_large,
            content_type="multipart/form-data",
        )
        self.assertEqual(oversized.status_code, 400)
        self.assertIn("حجم عکس باید حداکثر ۵ مگابایت".encode(), oversized.data)

    def test_seed_is_once_only_and_existing_user_data_survives_restart(self):
        with self.app.app_context():
            db = get_db()
            self.assertEqual(db.execute("SELECT COUNT(*) FROM items").fetchone()[0], 8)
            db.execute(
                "INSERT INTO users(username,email,password_hash,created_at) "
                "VALUES(?,?,?,?)",
                ("مالک", "persistent@example.com", "hash-placeholder", "2026-01-01"),
            )
            user_id = db.execute(
                "SELECT id FROM users WHERE email=?", ("persistent@example.com",)
            ).fetchone()["id"]
            db.execute(
                "INSERT INTO items(user_id,item_name,item_type,status,location,color,"
                "contact_email,description,created_at,is_demo) "
                "VALUES(?,?,?,?,?,?,?,?,?,0)",
                (
                    user_id,
                    "دادهٔ قبلی",
                    "کیف",
                    "lost",
                    "محل",
                    "آبی",
                    "persistent@example.com",
                    "شرح",
                    "2026-01-01",
                ),
            )
            db.commit()

        second_app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "another-test-key",
                "DATABASE_PATH": self.database,
                "UPLOAD_DIR": self.upload_dir,
                "WTF_CSRF_ENABLED": True,
            }
        )
        with second_app.app_context():
            db = get_db()
            self.assertEqual(db.execute("SELECT COUNT(*) FROM items").fetchone()[0], 9)
            self.assertIsNotNone(
                db.execute(
                    "SELECT id FROM items WHERE item_name='دادهٔ قبلی'"
                ).fetchone()
            )
            self.assertEqual(
                db.execute(
                    "SELECT COUNT(*) FROM users WHERE email='persistent@example.com'"
                ).fetchone()[0],
                1,
            )

    def test_migrates_older_database_and_disables_published_demo_login(self):
        old_database = os.path.join(self.temp_dir.name, "legacy", "old.sqlite3")
        os.makedirs(os.path.dirname(old_database), exist_ok=True)
        connection = sqlite3.connect(old_database)
        connection.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE items (
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
                created_at TEXT NOT NULL
            );
            CREATE TABLE matches (
                id INTEGER PRIMARY KEY,
                lost_item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                found_item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                notified INTEGER DEFAULT 0,
                UNIQUE(lost_item_id, found_item_id)
            );
            """
        )
        connection.execute(
            "INSERT INTO users VALUES(1,?,?,?,?)",
            (
                "کاربر نمونه",
                "demo@yabande.local",
                generate_password_hash("Yabande123!"),
                "2026-01-01",
            ),
        )
        connection.execute(
            "INSERT INTO users VALUES(2,?,?,?,?)",
            (
                "کاربر واقعی",
                "real@example.com",
                generate_password_hash("private-password"),
                "2026-01-01",
            ),
        )
        connection.execute(
            "INSERT INTO items VALUES(1,1,?,?,?,?,?,?,?,?,?)",
            (
                "نمونه قدیمی",
                "کیف",
                "found",
                "محل نمونه",
                "قهوه‌ای",
                "demo@yabande.local",
                "داده نمایشی قدیمی",
                None,
                "2026-01-01",
            ),
        )
        connection.execute(
            "INSERT INTO items VALUES(2,2,?,?,?,?,?,?,?,?,?)",
            (
                "آگهی واقعی",
                "کتاب",
                "lost",
                "کتابخانه",
                "آبی",
                "real@example.com",
                "دادهٔ واقعی باید باقی بماند",
                None,
                "2026-01-01",
            ),
        )
        connection.commit()
        connection.close()

        legacy_app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "migration-test-secret-key",
                "DATABASE_PATH": old_database,
                "UPLOAD_DIR": self.upload_dir,
                "WTF_CSRF_ENABLED": True,
            }
        )
        with legacy_app.app_context():
            db = get_db()
            demo = db.execute(
                "SELECT password_hash FROM users WHERE email='demo@yabande.local'"
            ).fetchone()
            self.assertFalse(check_password_hash(demo["password_hash"], "Yabande123!"))
            demo_item = db.execute(
                "SELECT is_demo,contact_email FROM items WHERE id=1"
            ).fetchone()
            self.assertEqual(demo_item["is_demo"], 1)
            self.assertEqual(demo_item["contact_email"], "")
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM items").fetchone()[0],
                2,
            )
            self.assertEqual(
                db.execute(
                    "SELECT description FROM items WHERE item_name='آگهی واقعی'"
                ).fetchone()["description"],
                "دادهٔ واقعی باید باقی بماند",
            )

    def test_production_requires_a_strong_environment_secret(self):
        with patch.dict(os.environ, {"APP_ENV": "production", "SECRET_KEY": ""}):
            with self.assertRaisesRegex(RuntimeError, "SECRET_KEY"):
                create_app(
                    {
                        "DATABASE_PATH": os.path.join(self.temp_dir.name, "unused.sqlite3"),
                        "UPLOAD_DIR": self.upload_dir,
                    }
                )

    def test_matching_sends_one_message_to_lost_reporter_without_exposing_finder_email(self):
        self.signup("lost.owner@example.com", "گزارش‌دهنده")
        lost = self.create_listing(
            item_name="گوشی سامسونگ مشکی",
            status="lost",
            contact_email="lost.owner@example.com",
            description="گوشی مشکی کنار میز مطالعه گم شده است.",
        )
        self.assertEqual(lost.status_code, 302)
        self.logout()
        self.signup("finder@example.com", "یابنده")
        self.app.config.update(
            SMTP_HOST="smtp.example.test",
            SMTP_PORT="587",
            SMTP_USER="mailer@example.com",
            SMTP_PASSWORD="mock-password",
            MAIL_FROM="mailer@example.com",
            PUBLIC_BASE_URL="https://yabande.example.test",
        )
        with patch("app.smtplib.SMTP", MockSMTPServer):
            found = self.create_listing(
                item_name="گوشی سامسونگ مشکی",
                status="found",
                contact_email="finder@example.com",
                description="گوشی مشکی کنار میز مطالعه پیدا شده است.",
            )
            self.assertEqual(found.status_code, 302)
            self.assertEqual(len(MockSMTPServer.sent_messages), 1)
            message = MockSMTPServer.sent_messages[0]
            self.assertEqual(message["To"], "lost.owner@example.com")
            self.assertIn("https://yabande.example.test/item/", message.get_content())
            self.assertNotIn("finder@example.com", message.get_content())
            self.assertEqual(MockSMTPServer.logins, [("mailer@example.com", "mock-password")])

            with self.app.test_request_context("/"):
                with self.app.app_context():
                    new_id = int(found.headers["Location"].rsplit("/", 1)[1])
                    self.assertEqual(match_items(new_id), [])
            self.assertEqual(len(MockSMTPServer.sent_messages), 1)
        with self.app.app_context():
            match = get_db().execute("SELECT notified FROM matches").fetchone()
            self.assertEqual(match["notified"], 1)

    def test_matching_without_smtp_keeps_app_working_and_logs_safe_diagnostic(self):
        self.signup("reporter@example.com", "گزارش‌دهنده")
        self.create_listing(
            item_name="کلید آبی",
            item_type="کلید",
            status="lost",
            color="آبی",
            location="ورودی شمالی",
            contact_email="reporter@example.com",
            description="دسته‌کلید آبی نزدیک ورودی شمالی گم شده است.",
        )
        self.logout()
        self.signup("finder@example.com", "یابنده")
        with self.assertLogs("app", level="WARNING") as logged:
            result = self.create_listing(
                item_name="کلید آبی",
                item_type="کلید",
                status="found",
                color="آبی",
                location="ورودی شمالی",
                contact_email="finder@example.com",
                description="دسته‌کلید آبی نزدیک ورودی شمالی پیدا شد.",
            )
        self.assertEqual(result.status_code, 302)
        self.assertTrue(any("SMTP کامل نیست" in message for message in logged.output))
        self.assertFalse(any("reporter@example.com" in message for message in logged.output))
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM matches").fetchone()[0], 1)
            self.assertEqual(
                get_db().execute("SELECT notified FROM matches").fetchone()["notified"], 0
            )

    def test_matching_score_normalizes_persian_variants_and_rejects_wrong_category(self):
        lost = {
            "item_type": "موبایل",
            "item_name": "گوشی سامسونگ",
            "color": "مشکی",
            "location": "کتابخانه مرکزی",
            "description": "گوشی مشکی گم شده",
        }
        found = {
            "item_type": "موبایل",
            "item_name": "گوشی سامسونگ",
            "color": "مشکی",
            "location": "کتابخانه مرکزی",
            "description": "گوشی مشکی پیدا شده",
        }
        self.assertTrue(score_match(lost, found)["plausible"])
        variant = dict(found, item_name="گوشى سامسونگ", color="مشكى")
        self.assertTrue(score_match(lost, variant)["plausible"])
        self.assertFalse(score_match(lost, dict(found, item_type="کتاب"))["plausible"])


if __name__ == "__main__":
    unittest.main()
