FROM golang:1.23-alpine AS scanner-builder
WORKDIR /src
COPY scanner/go.mod ./scanner/go.mod
RUN cd scanner && go mod download
COPY scanner ./scanner
RUN cd scanner && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/scanner ./cmd/scanner

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

RUN python -m venv /opt/venv \
    && apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY --from=scanner-builder /out/scanner /app/bin/scanner
COPY backend /app/backend

RUN chmod +x /app/bin/scanner /app/backend/scripts/start-web.sh /app/backend/scripts/start-worker.sh

EXPOSE 8000

WORKDIR /app/backend
