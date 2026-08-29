"""Accepting identity-provider tokens alongside the local login.

This exists so a platform holding an identity provider — Company OS in front of
Keycloak — can call this API as itself, without a shared local password. It does
not replace the local login and is not required: leave `oidc_issuer` unset and
nothing here runs.

Three rules keep this from becoming a hole in the front door:

* **The two token types never meet.** The local login issues HS256 signed with
  `secret_key`; an identity provider issues RS256 signed with a key we only ever
  hold the public half of. Each is decoded with its own algorithm list, so a
  token signed with one scheme can never be validated under the other. That is
  the algorithm-confusion attack, and separating them is what closes it.
* **Issuer and audience are both required and both checked.** A signature proves
  who minted a token, not who it was minted for. Without the audience check, a
  token issued to any other client of the same realm would open this API.
* **A provisioned user gets the least privilege there is.** Somebody arriving on
  a valid token has proven who they are and nothing about what they may do, so
  they arrive as a `viewer` unless configured otherwise. Roles are granted here,
  by an administrator, not asserted by a claim in someone else's token.
"""

import json
import secrets
import time
import urllib.parse
import urllib.request

from jose import JWTError, jwt

from app.core.config import settings
from app.core.rbac import ROLE_PERMISSIONS
from app.core.security import hash_password
from app.models.user import User

#: How long the fetched key set is reused. A rotation is picked up sooner than
#: this: a token naming a key we do not hold forces one refresh (see `_decode`).
JWKS_TTL_SECONDS = 3600

_cache: dict[str, tuple[float, dict]] = {}


def enabled() -> bool:
    """Whether identity-provider tokens are accepted at all.

    Both settings are required, and deliberately: an issuer without an audience
    would accept any token that realm ever minted, for any client.
    """
    return bool(settings.oidc_issuer and settings.oidc_audience)


def internal(url: str) -> str:
    """Rewrite a provider URL onto the origin this server reaches it on.

    In a container deployment the browser reaches the identity provider through
    a proxy and this service reaches it directly, so the two cannot use the same
    origin — but tokens are minted with the *public* issuer, so that is what we
    keep validating against. Only server-to-server calls are rewritten; anything
    the browser is sent to stays public.

    Unset, this changes nothing.
    """
    if not settings.oidc_internal_base_url:
        return url
    parts = urllib.parse.urlsplit(url)
    internal_parts = urllib.parse.urlsplit(settings.oidc_internal_base_url.rstrip("/"))
    return urllib.parse.urlunsplit(
        (internal_parts.scheme, internal_parts.netloc, parts.path, parts.query, parts.fragment)
    )


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(
        internal(url), timeout=settings.oidc_request_timeout_seconds
    ) as response:
        return json.loads(response.read())


def discovery(refresh: bool = False) -> dict:
    """The provider's own description of itself, cached.

    Discovered from the issuer rather than assembled from it, so this works
    against any OpenID provider instead of only Keycloak's URL layout. The
    browser sign-in flow needs the authorization and token endpoints from here;
    token validation needs the key set.
    """
    cached = _cache.get("discovery")
    if cached and not refresh and cached[0] > time.time():
        return cached[1]

    document = _get_json(settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration")
    _cache["discovery"] = (time.time() + JWKS_TTL_SECONDS, document)
    return document


def _jwks(refresh: bool = False) -> dict:
    """The realm's public keys, cached."""
    cached = _cache.get("jwks")
    if cached and not refresh and cached[0] > time.time():
        return cached[1]

    keys = _get_json(discovery(refresh=refresh)["jwks_uri"])
    _cache["jwks"] = (time.time() + JWKS_TTL_SECONDS, keys)
    return keys


def claims_for(token: str) -> dict | None:
    """Validate an identity-provider token, or return None.

    None means "not ours to judge" — the token is a local one, the feature is
    off, or the provider would not vouch for it. The caller falls back to the
    local path, so a bad identity-provider token fails as an ordinary 401 rather
    than as an error that names our identity provider to an anonymous caller.
    """
    if not enabled():
        return None

    try:
        algorithm = jwt.get_unverified_header(token).get("alg", "")
    except JWTError:
        return None
    if not algorithm.startswith("RS"):
        # HS256 is the local login's own scheme. Never validated here, and never
        # validated against a public key.
        return None

    return verify(token, audience=settings.oidc_audience)


def verify(token: str, *, audience: str, nonce: str | None = None) -> dict | None:
    """Validate a provider-issued token against the realm's keys.

    Used for two different tokens with two different audiences: an access token
    presented to this API, and an ID token returned by the browser sign-in flow.
    The audience is therefore a parameter and never a default -- getting it wrong
    is what makes a token minted for another client work here.
    """
    claims = _decode(token, audience)
    if claims is None:
        # A key rotation invalidates the cache before its TTL expires. One
        # refresh and one retry, rather than an hour of failures.
        claims = _decode(token, audience, refresh=True)
    if claims is None:
        return None
    if nonce is not None and claims.get("nonce") != nonce:
        # Binds the ID token to the sign-in this browser actually started.
        return None
    return claims


def _decode(token: str, audience: str, refresh: bool = False) -> dict | None:
    try:
        return jwt.decode(
            token,
            _jwks(refresh=refresh),
            algorithms=[settings.oidc_algorithm],
            audience=audience,
            issuer=settings.oidc_issuer.rstrip("/"),
        )
    except (JWTError, OSError, KeyError, ValueError):
        return None


def resolve_user(db, claims: dict) -> User | None:
    """Find the NCM user a validated token refers to, creating one on first sight.

    Returns None when the account exists but is disabled, so disabling a user
    here stops them regardless of which door they came through.
    """
    username = claims.get("preferred_username") or claims.get("email") or claims.get("sub")
    if not username:
        return None

    user = db.query(User).filter(User.username == username).first()
    if user:
        return user if user.is_active else None

    # An unusable but well-formed hash: nobody knows this password, and
    # `verify_password` returns False rather than raising on a malformed value.
    # This account can only ever be reached through the identity provider.
    role = settings.oidc_default_role
    if role not in ROLE_PERMISSIONS:
        # A misconfigured role becomes the least-privileged one. The safe
        # direction to fail, and `viewer` is the documented default.
        role = "viewer"

    user = User(
        username=username,
        display_name=claims.get("name") or username,
        email=claims.get("email"),
        password_hash=hash_password(secrets.token_urlsafe(32)),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
