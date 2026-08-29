"""Browser sign-in through the identity provider.

No test reaches a provider: discovery, the code exchange and token verification
are all replaced. What is being tested is this application's half of the flow —
which is the half that can be got wrong in a way nobody notices until someone
signs in as somebody else.

The three tests worth reading are the ones that assert a *refusal*: a callback
whose `state` does not match the cookie, a callback with no cookie at all, and an
ID token minted for a different sign-in. Each corresponds to a real attack, and
each is only actually prevented if removing the check breaks the test.

A refusal is a redirect back to the login page carrying a reason, not a JSON
error. That is deliberate: the page shows the reason *and* stops redirecting, so
a broken provider cannot become a loop nobody can escape.
"""

import urllib.parse

import pytest
from fastapi import HTTPException
from jose import jwt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import sso
from app.core import oidc
from app.core.config import settings
from app.core.database import Base
from app.core.security import ALGORITHM
from app.models.audit import AuditLog
from app.models.user import User

ISSUER = "https://auth.example/realms/company"
CLIENT_ID = "ncm"
REDIRECT = "https://ncm.example/auth/sso/callback"
AUTHORIZE = f"{ISSUER}/protocol/openid-connect/auth"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine, tables=[User.__table__, AuditLog.__table__])
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(settings, "oidc_issuer", ISSUER)
    monkeypatch.setattr(settings, "oidc_audience", CLIENT_ID)
    monkeypatch.setattr(settings, "oidc_client_id", CLIENT_ID)
    monkeypatch.setattr(settings, "oidc_client_secret", "a-client-secret")
    monkeypatch.setattr(settings, "oidc_redirect_url", REDIRECT)
    monkeypatch.setattr(settings, "oidc_default_role", "viewer")
    monkeypatch.setattr(
        oidc,
        "discovery",
        lambda refresh=False: {
            "authorization_endpoint": AUTHORIZE,
            "token_endpoint": TOKEN_ENDPOINT,
            "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
        },
    )
    return settings


def failed_with(response) -> str:
    """The reason a callback redirected back to the page with."""
    assert response.status_code == 303, response
    location = response.headers["location"]
    assert location.startswith("/?sso_error="), location
    return location.split("=", 1)[1]


class FakeRequest:
    """Only what the endpoint actually reads."""

    def __init__(self, cookies=None):
        self.cookies = cookies or {}
        self.client = None


def start() -> tuple[dict, str]:
    """Run the first leg and return its query parameters and state cookie."""
    response = sso.sso_login()
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(response.headers["location"]).query))
    cookie = next(
        value.decode().split(";")[0].split("=", 1)[1]
        for key, value in response.raw_headers
        if key == b"set-cookie"
    )
    return query, cookie


class TestItIsOffUnlessConfigured:
    def test_reports_disabled(self, monkeypatch):
        monkeypatch.setattr(settings, "oidc_client_id", "")

        assert sso.enabled() is False
        assert sso.sso_enabled() == {"enabled": False}

    def test_starting_a_flow_is_a_404_not_a_500(self, monkeypatch):
        """A deployment without the feature is a normal state, not an error."""
        monkeypatch.setattr(settings, "oidc_client_id", "")

        with pytest.raises(HTTPException) as refusal:
            sso.sso_login()

        assert refusal.value.status_code == 404


class TestStartingTheFlow:
    def test_the_browser_is_sent_to_the_provider_with_what_it_needs(self, configured):
        query, _ = start()

        assert query["client_id"] == CLIENT_ID
        assert query["redirect_uri"] == REDIRECT
        assert query["response_type"] == "code"
        assert "openid" in query["scope"]
        assert query["state"] and query["nonce"]

    def test_pkce_is_used_and_the_verifier_never_leaves_this_server(self, configured):
        query, cookie = start()

        assert query["code_challenge_method"] == "S256"
        assert query["code_challenge"]
        held = jwt.decode(cookie, settings.secret_key, algorithms=[ALGORITHM])
        # The challenge goes to the provider; the verifier stays with us.
        assert held["verifier"] not in str(query)

    def test_the_state_cookie_is_signed_and_not_readable_by_script(self, configured):
        response = sso.sso_login()
        header = next(
            value.decode() for key, value in response.raw_headers if key == b"set-cookie"
        )

        assert "httponly" in header.lower()
        assert "samesite=lax" in header.lower()

    def test_every_sign_in_gets_fresh_values(self, configured):
        first, _ = start()
        second, _ = start()

        assert first["state"] != second["state"]
        assert first["nonce"] != second["nonce"]
        assert first["code_challenge"] != second["code_challenge"]


class TestTheCallbackRefuses:
    def test_a_callback_this_browser_did_not_start(self, configured, db):
        """No cookie: someone handed this URL to the browser."""
        assert failed_with(sso.sso_callback(FakeRequest(), code="c", state="x", db=db)) == (
            sso.ERROR_STATE
        )

    def test_a_state_that_does_not_match_the_cookie(self, configured, db):
        _, cookie = start()

        response = sso.sso_callback(
            FakeRequest({sso.STATE_COOKIE: cookie}), code="c", state="not-it", db=db
        )

        assert failed_with(response) == sso.ERROR_STATE

    def test_a_forged_state_cookie(self, configured, db):
        forged = jwt.encode(
            {"state": "mine", "verifier": "v", "nonce": "n"}, "not-the-secret", algorithm=ALGORITHM
        )

        response = sso.sso_callback(
            FakeRequest({sso.STATE_COOKIE: forged}), code="c", state="mine", db=db
        )

        assert failed_with(response) == sso.ERROR_STATE

    def test_an_identity_token_that_does_not_verify(self, configured, db, monkeypatch):
        """Covers a wrong signature, a wrong issuer, a wrong audience, and a
        nonce belonging to a different sign-in -- `oidc.verify` returns None for
        all of them, and none of them may produce a session."""
        query, cookie = start()
        monkeypatch.setattr(sso, "_exchange", lambda code, verifier: {"id_token": "rubbish"})
        monkeypatch.setattr(oidc, "verify", lambda token, audience, nonce=None: None)

        response = sso.sso_callback(
            FakeRequest({sso.STATE_COOKIE: cookie}), code="c", state=query["state"], db=db
        )

        assert failed_with(response) == sso.ERROR_VERIFY

    def test_a_provider_that_returns_no_identity_token(self, configured, db, monkeypatch):
        query, cookie = start()
        monkeypatch.setattr(sso, "_exchange", lambda code, verifier: {"access_token": "only"})

        response = sso.sso_callback(
            FakeRequest({sso.STATE_COOKIE: cookie}), code="c", state=query["state"], db=db
        )

        assert failed_with(response) == sso.ERROR_PROVIDER


    def test_a_disabled_account(self, configured, db, monkeypatch):
        """Disabling a user must stop them whichever door they came through."""
        db.add(User(username="gone", password_hash="x", role="viewer", is_active=False))
        db.commit()
        query, cookie = start()
        monkeypatch.setattr(sso, "_exchange", lambda code, verifier: {"id_token": "t"})
        monkeypatch.setattr(
            oidc, "verify", lambda token, audience, nonce=None: {"preferred_username": "gone"}
        )

        response = sso.sso_callback(
            FakeRequest({sso.STATE_COOKIE: cookie}), code="c", state=query["state"], db=db
        )

        assert failed_with(response) == sso.ERROR_INACTIVE

    def test_a_refusal_clears_the_state_cookie(self, configured, db):
        """So a stale cookie cannot be replayed into a later attempt."""
        response = sso.sso_callback(FakeRequest(), code="c", state="x", db=db)
        cleared = [v.decode() for k, v in response.raw_headers if k == b"set-cookie"]

        assert any(sso.STATE_COOKIE in header for header in cleared)


class TestASuccessfulSignIn:
    @pytest.fixture
    def completed(self, configured, db, monkeypatch):
        query, cookie = start()
        seen = {}

        def exchange(code, verifier):
            seen["code"] = code
            seen["verifier"] = verifier
            return {"id_token": "an-id-token"}

        monkeypatch.setattr(sso, "_exchange", exchange)
        monkeypatch.setattr(
            oidc,
            "verify",
            lambda token, audience, nonce=None: {
                "preferred_username": "mark",
                "name": "Mark",
                "email": "mark@example",
                "nonce": nonce,
            },
        )
        response = sso.sso_callback(
            FakeRequest({sso.STATE_COOKIE: cookie}), code="the-code", state=query["state"], db=db
        )
        return response, seen, jwt.decode(cookie, settings.secret_key, algorithms=[ALGORITHM])

    def test_the_code_is_exchanged_with_the_matching_verifier(self, completed):
        _, seen, held = completed

        assert seen["code"] == "the-code"
        assert seen["verifier"] == held["verifier"]

    def test_the_page_is_handed_this_applications_own_token(self, completed):
        """Not the provider's token: everything downstream -- routes, permission
        checks, the frontend's session handling -- carries on unchanged."""
        response, _, _ = completed
        location = response.headers["location"]

        assert location.startswith("/#ncm_token=")
        minted = urllib.parse.unquote(location.split("=", 1)[1])
        assert jwt.decode(minted, settings.secret_key, algorithms=[ALGORITHM])["sub"] == "mark"

    def test_the_token_is_in_the_fragment_not_the_query(self, completed):
        """A fragment is never sent to a server, never logged and never lands in
        a Referer header."""
        response, _, _ = completed

        assert "?" not in response.headers["location"]

    def test_the_user_is_provisioned_with_least_privilege(self, completed, db):
        user = db.query(User).filter(User.username == "mark").one()

        assert user.role == "viewer"

    def test_the_sign_in_is_audited(self, completed, db):
        entry = db.query(AuditLog).filter(AuditLog.action == "LOGIN").one()

        assert entry.username == "mark"
        assert "single sign-on" in (entry.details or "")

    def test_the_state_cookie_is_cleared(self, completed):
        response, _, _ = completed
        cleared = [
            value.decode() for key, value in response.raw_headers if key == b"set-cookie"
        ]

        assert any(sso.STATE_COOKIE in header for header in cleared)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
