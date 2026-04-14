#!/bin/sh
set -eu

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${DJANGO_SECRET_KEY:?DJANGO_SECRET_KEY is required}"
: "${CELERY_BROKER_URL:?CELERY_BROKER_URL is required}"
: "${CELERY_RESULT_BACKEND:?CELERY_RESULT_BACKEND is required}"

exec celery -A config worker --loglevel=info --concurrency="${CELERY_CONCURRENCY:-4}"
