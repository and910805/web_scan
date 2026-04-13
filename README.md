# Security Scanning Platform

Production-ready single-repository scaffold for Zeabur:

- `backend/`: Django Rest Framework API, Celery worker, website/API scanning logic, PDF reporting, credit system.
- `frontend/`: Next.js dashboard for submitting URL scans and polling job status.
- `scanner/`: Go static analysis CLI kept for future source-code scanning features.
- `docker-compose.yml`: local dev stack with Postgres, Redis, Django, Celery, and Next.js.
- `Dockerfile`: Python runtime for Django and Celery.

## Local development

1. Copy `.env.example` to `.env` and adjust values.
2. Start the stack:

```bash
docker compose up --build
```

3. Run migrations and create an admin user:

```bash
docker compose exec web python manage.py migrate
docker compose exec web python manage.py createsuperuser
```

API base URL: `http://localhost:8000/api/`
Frontend URL: `http://localhost:3000/`

## API flow

1. Authenticate with JWT via `POST /api/auth/token/`.
2. `POST /api/scans/` with `project_name`, `scan_type`, and `target_url`.
3. Poll `GET /api/scans/{id}/` until status becomes `completed` or `failed`.
4. Download the PDF report from `GET /api/scans/{id}/report/`.

Example request:

```json
{
  "project_name": "customer-portal",
  "scan_type": "web",
  "target_url": "https://example.com"
}
```

Web scans currently check:

- HTTP response and security headers
- TLS certificate status
- Sensitive paths such as `/.env` and `/.git/config`
- Common files such as `robots.txt` and `sitemap.xml`
- Common API surface such as `/swagger` and `/openapi.json`
- Basic CORS signals for API scans

## Zeabur deployment

Provision these services in Zeabur:

1. `PostgreSQL`
2. `Redis`
3. `security-scanner-web` from this repo using `Dockerfile`
4. `security-scanner-worker` from this repo using `Dockerfile`
5. `security-scanner-frontend` from `frontend/`

Recommended start commands:

- Web: `sh /app/backend/scripts/start-web.sh`
- Worker: `sh /app/backend/scripts/start-worker.sh`

Important notes:

- Keep `CELERY_CONCURRENCY=4` for the 2 vCPU / 4 GB instance.
- Set shared environment variables for both backend services, especially `DATABASE_URL`, `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`, and `CORS_ALLOWED_ORIGINS`.
- For the frontend, set `NEXT_PUBLIC_API_BASE_URL` to your Django API URL.
- Use the plain PostgreSQL URI format with Django, for example `postgresql://root:password@host:port/database`.

## Default credits

- New users receive credits from `DEFAULT_USER_CREDITS`.
- Each scan request consumes one credit through the `deduct_credit` decorator.

## ECPay placeholder

- `POST /api/payments/ecpay/webhook/` exists as a placeholder endpoint.
- You still need to add signature validation and credit top-up logic before using it in production.
