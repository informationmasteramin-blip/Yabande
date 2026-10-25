"""ورودی WSGI برای Gunicorn و میزبان‌های سازگار با Flask."""

from app import app

application = app
