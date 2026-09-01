"""Identity-provider token acceptance.

No test here reaches an identity provider: the network call is replaced, so the
suite says what the code does rather than what a realm happened to answer.

The test that matters most is `test_a_local_token_is_never_validated_as_an_idp_one`.
Two token types sharing one door is where algorithm-confusion bugs live, and the
separation is only real if something fails when it is removed.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core import oidc
from app.core.config import settings
from app.core.database import Base
from app.core.security import create_access_token, verify_password
from app.models.user import User

ISSUER = "https://auth.example/realms/company"
AUDIENCE = "ncm"


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine, tables=[User.__table__])
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(settings, "oidc_issuer", ISSUER)
    monkeypatch.setattr(settings, "oidc_audience", AUDIENCE)
    monkeypatch.setattr(settings, "oidc_default_role", "viewer")
    # Any network call from here is a defect: nothing in these tests should
    # reach a realm.
    monkeypatch.setattr(
        oidc, "_get_json", lambda url: pytest.fail(f"unexpected network call to {url}")
    )
    oidc._cache.clear()
    return settings


class TestItIsOffUnlessConfigured:
    def test_disabled_when_nothing_is_set(self, monkeypatch):
        monkeypatch.setattr(settings, "oidc_issuer", "")
        monkeypatch.setattr(settings, "oidc_audience", "")

        assert oidc.enabled() is False
        assert oidc.claims_for("anything") is None

    def test_an_issuer_without_an_audience_is_not_enough(self, monkeypatch):
        """An issuer alone would accept every token that realm ever minted, for
        any of its clients."""
        monkeypatch.setattr(settings, "oidc_issuer", ISSUER)
        monkeypatch.setattr(settings, "oidc_audience", "")

        assert oidc.enabled() is False


class TestTheTwoTokenTypesNeverMeet:
    def test_a_local_token_is_never_validated_as_an_idp_one(self, configured):
        """The local login's HS256 token must not reach the public-key path.

        If it ever does, a token signed with the realm's *public* key as an HMAC
        secret becomes accepted — the algorithm-confusion attack. The `_get_json`
        stub fails the test if validation is so much as attempted.
        """
        local_token = create_access_token("admin")

        assert oidc.claims_for(local_token) is None

    def test_a_malformed_token_is_not_ours_to_judge(self, configured):
        assert oidc.claims_for("not-a-token") is None


class TestTheInternalOrigin:
    """A container deployment reaches the provider on a different origin than the
    browser does, but tokens are minted with the public issuer either way."""

    def test_nothing_is_rewritten_when_it_is_unset(self, monkeypatch):
        monkeypatch.setattr(settings, "oidc_internal_base_url", "")

        assert oidc.internal(f"{ISSUER}/protocol/openid-connect/token") == (
            f"{ISSUER}/protocol/openid-connect/token"
        )

    def test_only_the_origin_is_replaced(self, monkeypatch):
        monkeypatch.setattr(settings, "oidc_internal_base_url", "http://keycloak:8080")

        rewritten = oidc.internal(f"{ISSUER}/protocol/openid-connect/token")

        assert rewritten == "http://keycloak:8080/realms/company/protocol/openid-connect/token"

    def test_validation_still_expects_the_public_issuer(self, configured, monkeypatch):
        """The rewrite is only for calls we make. The provider mints tokens with
        its public issuer, so that is what the token says and what must still be
        checked -- validating against the internal origin would reject every
        genuine token."""
        monkeypatch.setattr(settings, "oidc_internal_base_url", "http://keycloak:8080")
        monkeypatch.setattr(oidc, "_jwks", lambda refresh=False: {"keys": []})
        seen = {}

        def capture(token, key, **kwargs):
            seen.update(kwargs)
            return {"sub": "someone"}

        monkeypatch.setattr(oidc.jwt, "decode", capture)

        oidc.verify("a-token", audience=AUDIENCE)

        assert seen["issuer"] == ISSUER
        assert "keycloak:8080" not in seen["issuer"]


class TestWhatIsHandedToTheDecoder:
    def test_the_access_token_is_passed_through_for_at_hash(self, configured, monkeypatch):
        """Without it the decoder raises on `at_hash` and every sign-in fails."""
        monkeypatch.setattr(oidc, "_jwks", lambda refresh=False: {"keys": []})
        seen = {}

        def capture(token, key, **kwargs):
            seen.update(kwargs)
            return {"sub": "someone"}

        monkeypatch.setattr(oidc.jwt, "decode", capture)

        oidc.verify("an-id-token", audience=AUDIENCE, access_token="the-access-token")

        assert seen["access_token"] == "the-access-token"


class TestProvisioning:
    def test_a_user_is_created_on_first_sight_with_least_privilege(self, configured, db):
        claims = {"preferred_username": "companyos", "name": "Company OS", "email": "os@example"}

        user = oidc.resolve_user(db, claims)

        assert user.username == "companyos"
        assert user.role == "viewer"
        assert user.is_active is True

    def test_a_role_claim_grants_nothing(self, configured, db):
        """Entitlement is granted here by an administrator, never asserted by a
        claim in someone else's token."""
        user = oidc.resolve_user(db, {"preferred_username": "sneaky", "role": "super_admin"})

        assert user.role == "viewer"

    def test_the_provisioned_account_has_no_usable_password(self, configured, db):
        user = oidc.resolve_user(db, {"preferred_username": "companyos"})

        assert not verify_password("", user.password_hash)
        assert not verify_password("companyos", user.password_hash)

    def test_an_existing_user_is_reused_and_keeps_its_role(self, configured, db):
        db.add(
            User(
                username="operator1",
                password_hash="x",
                role="operator",
                is_active=True,
            )
        )
        db.commit()

        user = oidc.resolve_user(db, {"preferred_username": "operator1"})

        assert user.role == "operator"
        assert db.query(User).count() == 1

    def test_a_disabled_user_is_refused_whichever_door_they_use(self, configured, db):
        db.add(User(username="gone", password_hash="x", role="admin", is_active=False))
        db.commit()

        assert oidc.resolve_user(db, {"preferred_username": "gone"}) is None

    def test_a_misconfigured_default_role_falls_back_to_viewer(self, configured, db, monkeypatch):
        monkeypatch.setattr(settings, "oidc_default_role", "not_a_role")

        user = oidc.resolve_user(db, {"preferred_username": "companyos"})

        assert user.role == "viewer"

    def test_a_token_naming_nobody_provisions_nobody(self, configured, db):
        assert oidc.resolve_user(db, {}) is None
        assert db.query(User).count() == 0


class TestGroupRoles:
    """Group membership is the only thing in a token that moves entitlement.

    The half worth testing hardest is removal. A mapping that only ever promotes
    is the same stale-role bug in a nicer shape: somebody who leaves the network
    team keeps administering it until a human notices.
    """

    MAP = (
        "platform-administrators=super_admin,"
        "network-administrators=admin,"
        "noc-operators=operator"
    )

    @pytest.fixture
    def mapped(self, configured, monkeypatch):
        monkeypatch.setattr(settings, "oidc_group_roles", self.MAP)
        return configured

    def test_a_mapped_group_earns_its_role(self, mapped, db):
        user = oidc.resolve_user(
            db, {"preferred_username": "mark", "groups": ["platform-administrators"]}
        )

        assert user.role == "super_admin"

    def test_the_most_privileged_group_wins(self, mapped, db):
        """Adding a group must never take access away."""
        user = oidc.resolve_user(
            db,
            {"preferred_username": "mark", "groups": ["noc-operators", "network-administrators"]},
        )

        assert user.role == "admin"

    def test_keycloaks_group_paths_are_accepted(self, mapped, db):
        """Keycloak writes "/network-administrators"; nobody configures the slash."""
        user = oidc.resolve_user(
            db, {"preferred_username": "mark", "groups": ["/network-administrators"]}
        )

        assert user.role == "admin"

    def test_a_single_group_string_is_accepted(self, mapped, db):
        user = oidc.resolve_user(
            db, {"preferred_username": "mark", "groups": "platform-administrators"}
        )

        assert user.role == "super_admin"

    def test_an_unmapped_group_gets_the_default(self, mapped, db):
        user = oidc.resolve_user(
            db, {"preferred_username": "contractor", "groups": ["employees"]}
        )

        assert user.role == "viewer"

    def test_no_groups_at_all_gets_the_default(self, mapped, db):
        assert oidc.resolve_user(db, {"preferred_username": "nobody"}).role == "viewer"

    def test_a_role_claim_still_grants_nothing(self, mapped, db):
        """Only groups are read. A role in someone else's token is not ours."""
        user = oidc.resolve_user(
            db, {"preferred_username": "sneaky", "role": "super_admin", "groups": ["employees"]}
        )

        assert user.role == "viewer"

    def test_a_promotion_in_the_directory_arrives(self, mapped, db):
        db.add(User(username="mark", password_hash="x", role="viewer", is_active=True))
        db.commit()

        user = oidc.resolve_user(
            db, {"preferred_username": "mark", "groups": ["platform-administrators"]}
        )

        assert user.role == "super_admin"
        assert db.query(User).count() == 1, "the existing row is updated, not duplicated"

    def test_a_removal_from_the_directory_also_arrives(self, mapped, db):
        """The half that matters: losing the group loses the access."""
        db.add(User(username="mark", password_hash="x", role="super_admin", is_active=True))
        db.commit()

        user = oidc.resolve_user(db, {"preferred_username": "mark", "groups": ["employees"]})

        assert user.role == "viewer"

    def test_a_disabled_user_is_still_refused(self, mapped, db):
        """Being in the most privileged group does not reopen a closed account."""
        db.add(User(username="gone", password_hash="x", role="viewer", is_active=False))
        db.commit()

        assert (
            oidc.resolve_user(
                db, {"preferred_username": "gone", "groups": ["platform-administrators"]}
            )
            is None
        )

    def test_a_mapping_naming_an_unknown_role_is_dropped(self, configured, db, monkeypatch):
        """One bad pair costs that group its mapping, not everyone their sign-in."""
        monkeypatch.setattr(
            settings, "oidc_group_roles", "good-group=admin,typo-group=administrater"
        )

        assert oidc.resolve_user(db, {"preferred_username": "a", "groups": ["typo-group"]}).role == "viewer"
        assert oidc.resolve_user(db, {"preferred_username": "b", "groups": ["good-group"]}).role == "admin"

    def test_without_a_mapping_an_existing_role_is_untouched(self, configured, db):
        """Unset is the previous behaviour, so upgrading changes nothing until
        someone opts in -- including for a role set by hand here."""
        db.add(User(username="promoted", password_hash="x", role="admin", is_active=True))
        db.commit()

        user = oidc.resolve_user(
            db, {"preferred_username": "promoted", "groups": ["platform-administrators"]}
        )

        assert user.role == "admin"

    def test_a_custom_groups_claim_is_honoured(self, mapped, db, monkeypatch):
        monkeypatch.setattr(settings, "oidc_groups_claim", "memberOf")

        user = oidc.resolve_user(
            db,
            {
                "preferred_username": "mark",
                "groups": ["platform-administrators"],
                "memberOf": ["noc-operators"],
            },
        )

        assert user.role == "operator", "the configured claim is read, not `groups`"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
