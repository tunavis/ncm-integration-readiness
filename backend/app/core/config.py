from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = BASE_DIR / ".env"


class Settings(BaseSettings):
    app_name: str = "Network Config Manager"

    secret_key: str = "CHANGE_ME"
    device_encryption_key: str = ""

    database_url: str = "sqlite:///./ncm.db"
    backup_root: str = "./backups"

    access_token_expire_minutes: int = 480

    default_admin_username: str = "admin"
    default_admin_password: str = "admin123"

    # Identity-provider tokens, accepted alongside the local login. Both the
    # issuer and the audience are required to switch this on: an issuer alone
    # would accept every token that realm ever minted, for any of its clients.
    # Leave them unset and nothing in app/core/oidc.py runs.
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_algorithm: str = "RS256"
    #: Role given to a user provisioned on first sight. Least privilege on
    #: purpose: a valid token proves identity, never entitlement.
    oidc_default_role: str = "viewer"
    oidc_request_timeout_seconds: float = 5.0

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
