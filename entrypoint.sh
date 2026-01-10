#!/usr/bin/env bash

set -euo pipefail

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

python -u manage.py migrate --no-input

python -u manage.py superuser

python -u manage.py check --deploy

# python -u manage.py check_openbao --mount secret --path django --required DJANGO_SECRET_KEY --json

echo "--> Starting web process"
exec gunicorn ${CONFIG}.wsgi:application --bind $RUNTIME_HOST:$RUNTIME_PORT --config "${APP_DIR}/gunicorn.conf.py"
