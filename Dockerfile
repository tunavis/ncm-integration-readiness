# Packaging the NCM so it can be deployed alongside Company OS.
#
# Upstream ships a `run-local.sh` venv script and no container, which is fine for
# a laptop and not enough to sit next to another service on a network. Nothing
# about the application changes here; this only puts it in a box.
#
# Everything mutable lives under /data — the SQLite database and the backup tree
# — so the image stays disposable and the volume holds the state.

FROM python:3.12-slim

WORKDIR /app

# Installed before the source is copied, so a code change does not reinstall
# netmiko and its dependency tree on every build.
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

ENV DATABASE_URL=sqlite:////data/ncm.db \
    BACKUP_ROOT=/data/backups \
    PYTHONUNBUFFERED=1

RUN mkdir -p /data/backups

EXPOSE 8000

# The liveness endpoint this fork adds, used by the packaging this fork adds.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
