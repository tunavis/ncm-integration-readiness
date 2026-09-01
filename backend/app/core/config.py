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
    #: Role for a user whose groups match nothing below. Least privilege on
    #: purpose: a valid token proves identity, never entitlement.
    oidc_default_role: str = "viewer"
    #: Claim carrying the provider's group memberships.
    oidc_groups_claim: str = "groups"
    #: Group-to-role map, ``group=role`` pairs separated by commas. The
    #: directory is authoritative for which groups someone is in; this file is
    #: authoritative for what those groups mean here. Roles are never read from
    #: the token directly -- a provider that could assert its own role in this
    #: application would be asserting entitlement, not identity.
    #:
    #: Where a user is in several mapped groups the most privileged wins, so
    #: adding a group can never quietly take access away.
    oidc_group_roles: str = ""
    oidc_request_timeout_seconds: float = 5.0

    # Browser sign-in, so a person arriving from a platform they are already
    # signed in to is not asked for a password again. Needs all four, and the
    # redirect URL must match what the provider has registered exactly.
    #: Origin this service reaches the provider on, when it differs from the
    #: public one. Only server-to-server calls are rewritten onto it; tokens are
    #: still validated against the public issuer, which is what mints them.
    oidc_internal_base_url: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_url: str = ""
    #: `Secure` on the short-lived state cookie. Only ever false for plain HTTP
    #: in local development.
    oidc_cookie_secure: bool = True

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
