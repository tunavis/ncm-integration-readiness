"""The liveness and readiness endpoints.

Called directly rather than over HTTP: these are plain functions, and testing
them this way keeps the suite free of a test client and its dependencies. What
the endpoints must get right is what they check, and that is visible here.
"""

import pytest
from fastapi import Response, status

from app.api import health as health_api


def test_health_reports_alive():
    assert health_api.health() == {"status": "ok"}


def test_health_touches_no_dependency(monkeypatch):
    """A liveness probe that fails when the database is down asks for a restart
    that cannot fix anything."""

    def explode():
        raise AssertionError("liveness must not touch the database")

    monkeypatch.setattr(health_api.engine, "connect", explode)

    assert health_api.health() == {"status": "ok"}


def test_ready_reports_the_database_when_it_answers():
    response = Response()

    body = health_api.ready(response)

    assert body["status"] == "ready"
    assert response.status_code == status.HTTP_200_OK


def test_ready_is_503_when_the_database_cannot_be_reached(monkeypatch):
    def explode():
        raise OSError("connection refused")

    monkeypatch.setattr(health_api.engine, "connect", explode)
    response = Response()

    body = health_api.ready(response)

    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert body["status"] == "unavailable"


def test_ready_does_not_leak_the_connection_string(monkeypatch):
    """The endpoint is unauthenticated, and a connection error routinely carries
    the database URL — credentials included."""
    secret = "postgresql://ncm:hunter2@db.internal:5432/ncm"

    def explode():
        raise OSError(f"could not connect to {secret}")

    monkeypatch.setattr(health_api.engine, "connect", explode)

    body = health_api.ready(Response())

    assert secret not in str(body)
    assert "hunter2" not in str(body)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
