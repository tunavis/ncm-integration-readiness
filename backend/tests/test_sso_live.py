"""The whole sign-in, against a real identity provider. Excluded by default.

Every other test in `test_sso.py` stubs `oidc.verify`, which is exactly how the
first real sign-in failed: nothing ever exercised the real decoder, and Keycloak's
ID token carries an `at_hash` that the decoder refused to accept unverified. A
suite that mocks the thing under test cannot catch that. This is the answer —
it drives the actual flow, form post and all, and fails if any leg of it breaks.

    SSO_PROBE_BASE_URL=http://localhost:8100 \\
    SSO_PROBE_USERNAME=... SSO_PROBE_PASSWORD=... \\
    pytest backend/tests/test_sso_live.py

The account needs to exist in the realm and nowhere else; it is signed in as an
ordinary user and provisioned into this application on first sight. Without the
variables the suite skips, because "not configured for this" is not "broken".
"""

import http.cookiejar
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

import pytest

BASE_URL = os.environ.get("SSO_PROBE_BASE_URL", "")
USERNAME = os.environ.get("SSO_PROBE_USERNAME", "")
PASSWORD = os.environ.get("SSO_PROBE_PASSWORD", "")
#: The provider may serve a certificate this host does not trust, which is
#: normal for a local bring-up and not what this test is about.
VERIFY_TLS = os.environ.get("SSO_PROBE_VERIFY_TLS", "false").lower() == "true"


@pytest.fixture
def browser():
    if not (BASE_URL and USERNAME and PASSWORD):
        pytest.skip("set SSO_PROBE_BASE_URL, SSO_PROBE_USERNAME and SSO_PROBE_PASSWORD")

    context = ssl.create_default_context()
    if not VERIFY_TLS:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.HTTPSHandler(context=context),
    )

    def open_url(url, data=None):
        try:
            with opener.open(url, data=data, timeout=30) as response:
                return response.status, response.read().decode("utf-8", "replace"), response.url
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode("utf-8", "replace"), error.url

    return open_url


def sign_in(browser, username=USERNAME, password=PASSWORD):
    """Start at this application and come back however it ends."""
    _, page, _ = browser(f"{BASE_URL.rstrip('/')}/auth/sso/login")
    form = re.search(r'action="([^"]+)"', page)
    assert form, "the provider did not serve a login form"

    return browser(
        form.group(1).replace("&amp;", "&"),
        urllib.parse.urlencode(
            {"username": username, "password": password, "credentialId": ""}
        ).encode(),
    )


def test_a_real_sign_in_ends_with_a_session(browser):
    """The one that matters: no password box, and a token at the end of it."""
    _, _, final = sign_in(browser)

    assert "sso_error" not in final, f"sign-in failed: {final}"
    assert "ncm_token=" in final, f"no session was issued: {final}"


def test_the_token_is_in_the_fragment(browser):
    """Never sent to a server, never logged, never in a Referer header."""
    _, _, final = sign_in(browser)

    assert "#ncm_token=" in final
    assert "?ncm_token=" not in final


def test_wrong_credentials_do_not_produce_a_session(browser):
    _, _, final = sign_in(browser, password="definitely-not-the-password")

    assert "ncm_token=" not in final


def test_the_application_is_reachable_unauthenticated_for_liveness(browser):
    status, _, _ = browser(f"{BASE_URL.rstrip('/')}/health")

    assert status == 200


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "-p", "no:cacheprovider"]))
