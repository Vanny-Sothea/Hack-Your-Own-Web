import os
from pydantic_settings import BaseSettings, SettingsConfigDict

# Determine environment file based on ENV variable
ENV_FILE = os.getenv("ENV_FILE", ".env")

class Settings(BaseSettings):
    ENV: str = "development"
    DEBUG: bool = True
    DATABASE_URL: str
    CELERY_BROKER_URL: str
    CELERY_RESULT_BACKEND: str

    JWT_SECRET: str
    JWT_ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_DAYS: int

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        extra="ignore",
    )


class AppSettings(BaseSettings):
    APP_NAME: str
    DOMAIN_VERIFICATION_TOKEN_PREFIX: str

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        extra="ignore",
    )


class MailSettings(BaseSettings):
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: str
    MAIL_FROM_NAME: str
    MAIL_PORT: str
    MAIL_SERVER: str
    MAIL_STARTTLS: bool
    MAIL_SSL_TLS: bool
    MAIL_DEBUG: bool
    USE_CREDENTIALS: bool

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        extra="ignore",
    )


class CelerySettings(BaseSettings):
    CELERY_BROKER_URL: str
    CELERY_RESULT_BACKEND: str

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        extra="ignore",
    )


class ZAPSettings(BaseSettings):
    ZAP_HOST: str
    ZAP_PORT: int
    ZAP_API_KEY: str
    USE_DOCKER_ZAP: bool
    ZAP_DOCKER_IMAGE: str

    # Timeout configurations (in seconds)
    ZAP_PASSIVE_SCAN_TIMEOUT: int = 600  # 10 minutes
    ZAP_SPIDER_TIMEOUT: int = 300  # 5 minutes
    ZAP_SPIDER_MAX_DURATION: int = 5  # 5 minutes max duration
    ZAP_AJAX_SPIDER_TIMEOUT: int = 300  # 5 minutes for AJAX spider
    ZAP_ACTIVE_SCAN_TIMEOUT: int = 1800  # 30 minutes

    # Advanced scanning options
    ZAP_ENABLE_AJAX_SPIDER: bool = True  # Enable AJAX spider for JavaScript apps
    ZAP_ENABLE_ALPHA_SCANNERS: bool = False  # Enable alpha/experimental scanners (more aggressive)

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        extra="ignore",
    )


# Initialize settings with validation from environment variables
# These will raise ValidationError if required env vars are missing
Config = Settings()  # type: ignore[call-arg]
AppConfig = AppSettings()  # type: ignore[call-arg]
MailConfig = MailSettings()  # type: ignore[call-arg]
CeleryConfig = CelerySettings()  # type: ignore[call-arg]
ZAPConfig = ZAPSettings()  # type: ignore[call-arg]
