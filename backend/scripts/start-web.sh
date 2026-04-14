#!/bin/sh
set -eu

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${DJANGO_SECRET_KEY:?DJANGO_SECRET_KEY is required}"
: "${CELERY_BROKER_URL:?CELERY_BROKER_URL is required}"
: "${CELERY_RESULT_BACKEND:?CELERY_RESULT_BACKEND is required}"

python manage.py migrate --noinput
python manage.py collectstatic --noinput
exec gunicorn config.wsgi:application --bind "0.0.0.0:${PORT:-8000}" --workers 2 --timeout 120
