# WeakScan

WeakScan is a website and API weak-scanning platform built as an async job system.

- `backend/`: Django + DRF API, Celery tasks, credits, PDF reporting
- `frontend/`: Next.js dashboard for submitting scans and polling status
- `scanner/`: reserved for future source-code scanning work
- `Dockerfile`: backend image for Django web and Celery worker
- `docker-compose.yml`: local development stack

## What It Does

Current scan modes:

- `web`: baseline website checks
- `api`: baseline API checks

Current checks include:

- HTTP status and response inspection
- security headers
- TLS certificate inspection
- common sensitive paths such as `/.env` and `/.git/config`
- common discovery files such as `robots.txt` and `sitemap.xml`
- common API/docs paths such as `/swagger` and `/openapi.json`
- basic CORS signals for API scans

This is not a full OWASP scanner yet. It is a lightweight async weak-scan platform intended to be extended.

## Architecture

- `frontend` sends scan requests to Django
- Django creates a `ScanJob`
- Celery worker runs the scan in the background
- results are stored in PostgreSQL
- PDF report is generated and exposed through the API

## API Flow

1. Authenticate with JWT via `POST /api/auth/token/`
2. Submit a scan via `POST /api/scans/`
3. Poll `GET /api/scans/{id}/`
4. Download `GET /api/scans/{id}/report/`

Example request:

```json
{
  "project_name": "customer-portal",
  "scan_type": "web",
  "target_url": "https://example.com"
}
```

## Local Development

1. Copy `.env.example` to `.env`
2. Start services:

```bash
docker compose up --build
```

3. Run migrations and create an admin user:

```bash
docker compose exec web python manage.py migrate
docker compose exec web python manage.py createsuperuser
```

Local URLs:

- Frontend: `http://localhost:3000`
- Backend API: `http://localhost:8000/api`

## Zeabur Deployment

Create these services first:

1. `PostgreSQL`
2. `Redis`

Then create these app services:

1. `web`
2. `worker`
3. `frontend`

### Web Service

- Root Directory: `/`
- Build source: repository root
- Uses repo root `Dockerfile`
- Public: yes
- Start Command:

```bash
sh /app/backend/scripts/start-web.sh
```

Required env:

```env
DATABASE_URL=postgresql://<user>:<password>@<host>:<port>/<db>
REDIS_URL=redis://:<password>@<host>:<port>/0
CELERY_BROKER_URL=redis://:<password>@<host>:<port>/0
CELERY_RESULT_BACKEND=redis://:<password>@<host>:<port>/1
DJANGO_SECRET_KEY=<your-secret>
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=your-backend-domain
CORS_ALLOWED_ORIGINS=https://your-frontend-domain
DEFAULT_USER_CREDITS=10
```

Notes:

- `DJANGO_ALLOWED_HOSTS` does not include `https://`
- `CORS_ALLOWED_ORIGINS` must include `https://`

### Worker Service

- Root Directory: `/`
- Build source: repository root
- Uses repo root `Dockerfile`
- Public: no
- Start Command:

```bash
sh /app/backend/scripts/start-worker.sh
```

Required env:

```env
DATABASE_URL=postgresql://<user>:<password>@<host>:<port>/<db>
REDIS_URL=redis://:<password>@<host>:<port>/0
CELERY_BROKER_URL=redis://:<password>@<host>:<port>/0
CELERY_RESULT_BACKEND=redis://:<password>@<host>:<port>/1
DJANGO_SECRET_KEY=<same-secret-as-web>
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=your-backend-domain
DEFAULT_USER_CREDITS=10
CELERY_CONCURRENCY=4
```

### Frontend Service

- Root Directory: `frontend`
- Build source: `frontend/`
- Public: yes
- Do not use repo root `Dockerfile`
- Start Command:

```bash
npm run start -- --hostname 0.0.0.0 --port 8080
```

Required env:

```env
NEXT_PUBLIC_API_BASE_URL=https://your-backend-domain/api
```

Important notes:

- If you run `next start` directly and see `/bin/sh: 1: next: not found`, use `npm run start -- --hostname 0.0.0.0 --port 8080`
- The frontend service must use `frontend` as its Root Directory

## Example Zeabur Mapping

If your domains are:

- frontend: `https://web-scan-front.zeabur.app`
- backend: `https://web-scan-web.zeabur.app`

Then use:

```env
DJANGO_ALLOWED_HOSTS=web-scan-web.zeabur.app
CORS_ALLOWED_ORIGINS=https://web-scan-front.zeabur.app
NEXT_PUBLIC_API_BASE_URL=https://web-scan-web.zeabur.app/api
```

## Credits

- each scan deducts 1 credit
- new users receive `DEFAULT_USER_CREDITS`

## Payment Webhook

Placeholder endpoint:

- `POST /api/payments/ecpay/webhook/`

This endpoint exists, but production-safe ECPay validation and credit top-up logic still need to be implemented.

## Current Limits

- current scanner is baseline only
- no OWASP ZAP integration yet
- no SonarQube-style source-code scanning yet
- frontend currently expects a JWT access token pasted manually

## Next Recommended Steps

1. Add a proper login flow in the frontend
2. Add OWASP ZAP integration as an advanced scan mode
3. Add issue detail pages instead of summary-only reporting
4. Add payment top-up logic for credits
