#!/bin/sh
set -eu

exec celery -A config worker --loglevel=info --concurrency="${CELERY_CONCURRENCY:-4}"
