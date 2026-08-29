from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.core.database import init_db
from app.api.auth import router as auth_router
from app.api.health import router as health_router
from app.api.sso import enabled as sso_enabled
from app.api.sso import router as sso_router
from app.api.devices import router as devices_router
from app.api.backups import router as backups_router
from app.api.schedules import router as schedules_router
from app.api.users import router as users_router
from app.api.audit import router as audit_router
from app.services.scheduler import start_scheduler, stop_scheduler

app = FastAPI(title="Network Config Manager", version="0.1.0")

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"

@app.on_event("startup")
def startup():
    init_db()
    start_scheduler()

@app.on_event("shutdown")
def shutdown():
    stop_scheduler()

# Unauthenticated and unprefixed: an orchestrator probing liveness should not
# need a credential or know the API layout.
app.include_router(health_router)
# Unprefixed: these are browser redirects, not API calls.
app.include_router(sso_router)
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(devices_router, prefix="/api/devices", tags=["Devices"])
app.include_router(backups_router, prefix="/api/backups", tags=["Backups"])
app.include_router(schedules_router, prefix="/api/schedules", tags=["Schedules"])
app.include_router(users_router, prefix="/api/users", tags=["Users"])
app.include_router(audit_router, prefix="/api/audit", tags=["Audit"])

@app.get("/", response_class=HTMLResponse)
def home():
    """The single page, told at render time whether single sign-on is on.

    It used to ask over a second request, which meant the login form was painted
    and *then* replaced by a redirect -- a visible flash of a password box for an
    account the visitor does not use. The server already knows, so it says so.
    """
    page = (WEB_DIR / "index.html").read_text()
    return HTMLResponse(
        page.replace("__SSO_ENABLED__", "true" if sso_enabled() else "false"),
        # Never cached. This response is now built per request -- it carries
        # whether single sign-on is on -- and it is the whole application: a
        # browser holding a stale copy runs last week's sign-in logic against
        # this week's server and cannot be told otherwise. Served with neither
        # Cache-Control nor ETag, browsers cache it heuristically, which is
        # exactly the trap this closes.
        headers={"Cache-Control": "no-store, must-revalidate"},
    )

app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
