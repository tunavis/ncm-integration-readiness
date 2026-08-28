"""Liveness and readiness endpoints.

Two endpoints that answer different questions, which is the whole reason there
are two of them:

* ``/health`` answers "is this process alive?" It touches nothing — no database,
  no scheduler — so it stays truthful when a dependency is down and can be used
  by a container orchestrator to decide whether to restart the process. A health
  check that fails because the database is down asks for a restart that cannot
  fix anything.
* ``/ready`` answers "can this process serve traffic?" It checks the database,
  because every route here needs one, and answers 503 when it cannot.

Both are unauthenticated on purpose. A liveness probe that needs a credential
conflates "the service is down" with "the credential expired", and whoever is
paged at 3am then has two problems instead of one.
"""

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from app.core.database import engine

router = APIRouter(tags=["Operations"])


@router.get("/health")
def health():
    """Liveness. Deliberately checks nothing."""
    return {"status": "ok"}


@router.get("/ready")
def ready(response: Response):
    """Readiness. Reports the dependencies a request actually needs."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as error:  # noqa: BLE001 - any failure means not ready
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        # The exception type, not its message: a connection error can carry the
        # database URL, and this endpoint is unauthenticated.
        return {"status": "unavailable", "database": type(error).__name__}
    return {"status": "ready", "database": "ok"}
