import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _environment_name():
    return (os.getenv("SENTINELX_ENV") or os.getenv("FLASK_ENV") or os.getenv("APP_ENV") or "development").strip().lower()


class Config:
    ENV = _environment_name()
    DEFAULT_DEV_SECRET = "local-development-only-change-me"
    SECRET_KEY = os.getenv("SENTINELX_SECRET_KEY") or os.getenv("SECRET_KEY") or (DEFAULT_DEV_SECRET if ENV != "production" else "")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'sentinelx.db'}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true" if ENV == "production" else "false").lower() == "true"
    JSON_SORT_KEYS = False

    @classmethod
    def is_production(cls):
        return cls.ENV == "production"

    @classmethod
    def validate(cls):
        secret = os.getenv("SENTINELX_SECRET_KEY") or os.getenv("SECRET_KEY")
        if cls.is_production():
            if not secret:
                raise RuntimeError("Production requires SENTINELX_SECRET_KEY or SECRET_KEY to be configured.")
            if len(secret) < 32:
                raise RuntimeError("Production secret key must be at least 32 characters long.")
            if secret == cls.DEFAULT_DEV_SECRET:
                raise RuntimeError("Production requires a non-default secret key.")
            if not cls.SESSION_COOKIE_SECURE:
                raise RuntimeError("Production requires Secure session cookies.")
            return

        if not secret and cls.SECRET_KEY == cls.DEFAULT_DEV_SECRET:
            return

        # Allow development to use the default fallback secret only when not in production.
        if not cls.SECRET_KEY:
            raise RuntimeError("Development secret is not configured.")


# Backward-compatible alias used by the recovered legacy Member 1 tests.
AppConfig = Config
