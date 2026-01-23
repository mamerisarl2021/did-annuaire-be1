#!/usr/bin/env bash

set -euo pipefail

chown -R appuser:appuser /app/mediafiles

CONFIG="config"
APP_DIR="/app"

export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1

source /opt/venv/bin/activate

cd $APP_DIR


RUNTIME_PORT=${PORT:-8899}
RUNTIME_HOST=${HOST:-0.0.0.0}

export DJANGO_ENV=production

python -u manage.py collectstatic --noinput

python -u manage.py migrate --noinput

python -u manage.py setup_periodic_tasks

python -u manage.py superuser

python -u manage.py check --deploy

echo "--> Starting web process"
exec su appuser -c "gunicorn ${CONFIG}.wsgi:application \
    --capture-output \
    --log-level info \
    --error-logfile - \
    --access-logfile - \
    --bind $RUNTIME_HOST:$RUNTIME_PORT \
    --config ${APP_DIR}/gunicorn.conf.py"

#exec gunicorn ${CONFIG}.wsgi:application --bind $RUNTIME_HOST:$RUNTIME_PORT --config "gunicorn.conf.py"
