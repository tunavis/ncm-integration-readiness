"""Signing in through the identity provider, in a browser.

This is the half that `app/core/oidc.py` does not do. That module lets a *machine*
present a token this API already trusts. This one lets a *person* arrive from a
platform they are already signed in to and not be asked for a password again.

The flow is the ordinary authorization-code one, and it ends somewhere specific:
the callback mints **this application's own** access token and hands it to the
existing page. Nothing downstream changes — every route, every permission check
and the frontend's own session handling carry on exactly as they did for a local
login. That is what keeps this small.

What it refuses to do without:

* **`state`**, held in a signed cookie and compared on return. Without it, anyone
  can hand your browser a callback URL and log you in as someone else.
* **PKCE**, so an intercepted code cannot be exchanged by whoever intercepted it.
* **A `nonce`**, bound into the ID token, so a token minted for some other
  sign-in cannot be replayed into this one.
* **An exact audience.** The ID token is validated against this client's id, not
  against whatever the realm happens to have issued.

Off unless configured. Every setting it needs is required rather than defaulted,
so a half-configured deployment does not present a sign-in button that fails.
"""

import base64
import hashlib
import json
import secrets
import urllib.parse
import urllib.request

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core import oidc
from app.core.config import settings
from app.core.database import get_db
from app.core.security import ALGORITHM, create_access_token
from app.services.audit import record_audit

router = APIRouter(tags=["Authentication"])

#: Carries `state`, the PKCE verifier and the nonce between the two requests.
#: Signed with this application's own secret and short-lived, so there is no
#: server-side session to store and nothing to clean up.
STATE_COOKIE = "ncm_sso_state"
STATE_TTL_SECONDS = 600

#: Why a sign-in did not complete, as a short code the page turns into a
#: sentence. Deliberately not the provider's own error text: that names the
#: client and is of no use to whoever is looking at the screen.
ERROR_STATE = "state"
ERROR_PROVIDER = "provider"
ERROR_VERIFY = "verify"
ERROR_INACTIVE = "inactive"


def _failed(reason: str) -> RedirectResponse:
    """Send the browser back to the page with something it can explain.

    A failed sign-in must land on the login page, not on a JSON error: the page
    then shows the reason *and* stops redirecting, which is what keeps a broken
    provider from becoming a loop nobody can escape.
    """
    response = RedirectResponse(f"/?sso_error={reason}", status_code=303)
    response.delete_cookie(STATE_COOKIE, path="/auth/sso")
    return response


def enabled() -> bool:
    """Whether browser sign-in is configured. All of it, or none of it."""
    return bool(
        settings.oidc_issuer
        and settings.oidc_client_id
        and settings.oidc_client_secret
        and settings.oidc_redirect_url
    )


def _require_enabled() -> None:
    if not enabled():
        # 404 rather than 500: this deployment does not have the feature, which
        # is a normal state and not an error.
        raise HTTPException(404, "Single sign-on is not configured")


@router.get("/auth/sso/enabled")
def sso_enabled():
    """So the page can show a sign-in button only when it would work."""
    return {"enabled": enabled()}


@router.get("/auth/sso/login")
def sso_login():
    """Start the flow: send the browser to the identity provider."""
    _require_enabled()

    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    try:
        # Left public deliberately: this is where the browser is sent.
        authorization_endpoint = oidc.discovery()["authorization_endpoint"]
    except (OSError, KeyError, ValueError) as error:
        raise HTTPException(502, "The identity provider could not be reached") from error

    query = urllib.parse.urlencode(
        {
            "client_id": settings.oidc_client_id,
            "redirect_uri": settings.oidc_redirect_url,
            "response_type": "code",
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )

    response = RedirectResponse(f"{authorization_endpoint}?{query}", status_code=303)
    response.set_cookie(
        STATE_COOKIE,
        jwt.encode(
            {"state": state, "verifier": verifier, "nonce": nonce},
            settings.secret_key,
            algorithm=ALGORITHM,
        ),
        max_age=STATE_TTL_SECONDS,
        httponly=True,
        samesite="lax",  # the provider redirects back with a GET; strict would drop it
        secure=settings.oidc_cookie_secure,
        path="/auth/sso",
    )
    return response


@router.get("/auth/sso/callback")
def sso_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    db: Session = Depends(get_db),
):
    """Finish the flow: verify, provision, and hand the page a session."""
    _require_enabled()

    started = _started_flow(request)
    if started is None or not code or not state or state != started["state"]:
        # Either the provider sent us nothing usable, or this callback did not
        # come from a sign-in this browser started.
        return _failed(ERROR_STATE)

    tokens = _exchange(code, started["verifier"])
    if tokens is None:
        return _failed(ERROR_PROVIDER)

    identity = tokens.get("id_token")
    if not identity:
        return _failed(ERROR_PROVIDER)

    claims = oidc.verify(identity, audience=settings.oidc_client_id, nonce=started["nonce"])
    if claims is None:
        return _failed(ERROR_VERIFY)

    user = oidc.resolve_user(db, claims)
    if not user:
        return _failed(ERROR_INACTIVE)

    record_audit(
        db, user, "LOGIN", "auth", user.username, "SUCCESS", "single sign-on",
        request.client.host if request.client else None,
    )

    # This application's own token, exactly as a local login would produce. The
    # page, every route and every permission check carry on unchanged.
    token = create_access_token(user.username)

    # Handed over in the fragment: it is never sent to a server, never lands in
    # an access log and never appears in a Referer header. The page reads it
    # once and clears it from the address bar.
    response = RedirectResponse(f"/#ncm_token={urllib.parse.quote(token)}", status_code=303)
    response.delete_cookie(STATE_COOKIE, path="/auth/sso")
    return response


def _started_flow(request: Request) -> dict | None:
    """Recover what this browser started. ``None`` means it did not start here."""
    cookie = request.cookies.get(STATE_COOKIE)
    if not cookie:
        return None
    try:
        return jwt.decode(cookie, settings.secret_key, algorithms=[ALGORITHM])
    except JWTError:
        return None


def _exchange(code: str, verifier: str) -> dict | None:
    """Trade the authorization code for tokens, as a confidential client."""
    try:
        # Server-to-server, so it goes to the origin this service can reach.
        token_endpoint = oidc.internal(oidc.discovery()["token_endpoint"])
        body = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.oidc_redirect_url,
                "client_id": settings.oidc_client_id,
                "client_secret": settings.oidc_client_secret,
                "code_verifier": verifier,
            }
        ).encode()
        request = urllib.request.Request(
            token_endpoint,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(
            request, timeout=settings.oidc_request_timeout_seconds
        ) as response:
            return json.loads(response.read())
    except (OSError, KeyError, ValueError):
        # Deliberately silent to the caller: the provider's own error text can
        # name the client and is of no use to whoever is looking at the page.
        return None
