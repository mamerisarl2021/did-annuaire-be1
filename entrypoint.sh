#!/usr/bin/env bash

set -euo pipefail

CONFIG="config"
APP_DIR="/app"

export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1

# Activate venv and cd
source /opt/venv/bin/activate
cd $APP_DIR

# Runtime host/port
RUNTIME_PORT=${PORT:-8899}
RUNTIME_HOST=${HOST:-0.0.0.0}
export DJANGO_ENV=production

# 1) Ensure media/static ownership
chown -R appuser:appuser /app/mediafiles || true
chown -R appuser:appuser /app/staticfiles || true

# 2) Prepare DIDS_ROOT publish area (shared volume)
#    Default to /app/data/dids/.well-known if not set
DIDS_ROOT="${DIDS_ROOT:-/app/data/dids/.well-known}"
DIDS_BASE="$(dirname "$DIDS_ROOT")"

echo "--> Preparing DIDS_ROOT: $DIDS_ROOT"
mkdir -p "$DIDS_ROOT"

# Give ownership to the runtime app user; nginx mounts the same volume read-only
chown -R appuser:appuser "$DIDS_BASE"

# Directories 0755, files 0644, so nginx can read
find "$DIDS_BASE" -type d -exec chmod 0755 {} \; || true
find "$DIDS_BASE" -type f -exec chmod 0644 {} \; || true

# Quick write probe
if ! su -s /bin/sh -c "touch '$DIDS_ROOT/.probe' && rm -f '$DIDS_ROOT/.probe'" appuser; then
  echo "ERROR: DIDS_ROOT not writable by appuser: $DIDS_ROOT" >&2
  exit 1
fi
echo "--> DIDS_ROOT ready"

# 3) Django housekeeping
python -u manage.py collectstatic --noinput
python -u manage.py migrate --noinput
python -u manage.py setup_periodic_tasks
python -u manage.py superuser || true
python -u manage.py check --deploy

# 4) Start web as appuser
echo "--> Starting web process"
exec su appuser -c "gunicorn ${CONFIG}.wsgi:application \
    --capture-output \
    --log-level info \
    --error-logfile - \
    --access-logfile - \
    --bind ${RUNTIME_HOST}:${RUNTIME_PORT} \
    --config ${APP_DIR}/gunicorn.conf.py"

#exec gunicorn ${CONFIG}.wsgi:application --bind $RUNTIME_HOST:$RUNTIME_PORT --config "gunicorn.conf.py"
