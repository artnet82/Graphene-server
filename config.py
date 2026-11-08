# config.py
import os
import secrets


def _must_env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f"Environment variable {name} is required in production")
    return v


class Config:
    """Базовый конфиг — используется по умолчанию. Безопасные дефолты для dev."""
    SECRET_KEY = os.environ.get("GRAPHENE_SECRET") or secrets.token_hex(32)
    SQLALCHEMY_DATABASE_URI = os.environ.get("GRAPHENE_DB_URI", "sqlite:///graphene.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 110 * 1024 * 1024

    # CSRF
    WTF_CSRF_ENABLED = os.environ.get("GRAPHENE_CSRF_ENABLED", "1") == "1"
    WTF_CSRF_TIME_LIMIT = None

    # Admin
    ADMIN_USERNAME = os.environ.get("GRAPHENE_ADMIN_USER", "admin")
    ADMIN_PASSWORD_HASH = os.environ.get("GRAPHENE_ADMIN_HASH") or ""

    # API token
    API_AUTH_ENABLED = os.environ.get("GRAPHENE_API_AUTH_ENABLED", "1") == "1"

    # Флаг, что это prod — create_app() по нему валидирует env
    IS_PRODUCTION = False


class DevConfig(Config):
    IS_PRODUCTION = False


class ProdConfig(Config):
    """
    Не переопределяет SECRET_KEY/ADMIN_PASSWORD_HASH в теле класса —
    иначе модуль падает при импорте, даже если ProdConfig не выбран.
    Значения читаются из env в create_app() через validate().
    """
    IS_PRODUCTION = True

    @classmethod
    def validate(cls) -> None:
        """Вызывается из create_app() только для prod."""
        _must_env("GRAPHENE_SECRET")
        _must_env("GRAPHENE_ADMIN_HASH")