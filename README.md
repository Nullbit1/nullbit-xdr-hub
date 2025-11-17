# SentraCore – Minimal XDR Hub

SentraCore is a small XDR / mini-SIEM hub for a single organisation. It accepts security telemetry
from multiple sensors over HTTP, stores events in PostgreSQL and runs simple correlation rules to
raise incidents.

This repository focuses on the backend service only (Go + PostgreSQL). A web UI can be added on top
of the HTTP API later.

Key capabilities:

* HTTP ingestion endpoint for structured security events (`/api/v1/ingest/events`).
* Normalised event model (source, host, timestamp, severity, tags, free-form fields).
* Storage of events and incidents in PostgreSQL.
* YAML-driven correlation rules with time windows.
* Incident life-cycle with statuses (`open`, `triaged`, `closed`).
* Simple username/password login issuing JWT tokens.
* RBAC with three roles: `admin`, `analyst`, `read_only`.
* Basic query APIs for events and incidents.

Design decisions made here:

* Only HTTP ingestion is implemented. gRPC and message queues were intentionally skipped to keep
  the first version compact and easy to run.
* The service is single-tenant and optimised for small labs (tens of hosts, not thousands).
* Configuration is done via environment variables and a couple of YAML files.

## Quick start with Docker

Requirements:

* Docker + docker-compose
* Port 8080 free on the host

```bash
docker-compose up --build
```

This will start:

* `db` – PostgreSQL 16
* `backend` – SentraCore API on `http://localhost:8080`

On first start an admin/analyst user set is seeded from `backend/config/users.yaml`.

## Manual backend run

```bash
cd backend
go mod tidy
go run ./cmd/sentracore
```

Environment variables (with sensible defaults):

* `SENTRACORE_HTTP_ADDR` – HTTP listen address, default `:8080`.
* `SENTRACORE_DB_DSN` – PostgreSQL DSN, default
  `postgres://sentracore:sentracore@localhost:5432/sentracore?sslmode=disable`.
* `SENTRACORE_RULES_PATH` – path to correlation rules YAML (default `config/rules.yaml`).
* `SENTRACORE_USERS_PATH` – path to initial users YAML (default `config/users.yaml`).
* `SENTRACORE_JWT_SECRET` – HMAC secret for JWTs. When empty, a weak dev secret is used.
* `SENTRACORE_INGEST_TOKEN` – optional API token for ingestion. When set, agents must send
  `X-Api-Key: <token>`.

## API overview

### Ingest events

```bash
curl -X POST http://localhost:8080/api/v1/ingest/events \
  -H 'Content-Type: application/json' \
  -H 'X-Api-Key: dev-ingest-token' \
  -d '{
    "source": "sentrafim",
    "host_id": "win-host-1",
    "timestamp": "2024-11-16T12:00:00Z",
    "kind": "file_change",
    "severity": "medium",
    "tags": ["windows", "fim"],
    "fields": {
      "path": "C:\\Users\\Alice\\AppData\\Roaming\\weird.exe",
      "change_type": "create"
    }
  }'
```

### Login and query incidents

```bash
# Login (credentials from backend/config/users.yaml)
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}'

# Use returned token to query incidents
curl http://localhost:8080/api/v1/incidents \
  -H 'Authorization: Bearer <token>'
```

The same JWT token can be used to query `/api/v1/events` and to update incident status.

## Correlation rules

Rules live in `backend/config/rules.yaml` and are hot-loaded on startup.

The engine is deliberately simple: each rule defines a sliding time window and a sequence of event
matchers. When all matchers have at least one matching event for the same host within the window,
a new incident is created (if there is no similar open incident already).

Example (included in the repo):

```yaml
rules:
  - id: powershell_fim_http_combo
    title: Suspicious PowerShell + FIM change + outbound HTTP
    description: >
      Detects a sequence of suspicious PowerShell, FIM change in roaming profile, and outbound HTTP
      on the same host within 5 minutes.
    severity: high
    window: 5m
    tags: ["windows", "powershell", "fim", "http"]
    steps:
      - name: suspicious_powershell
        match:
          source: "powershell-hunt"
          kind: "process_start"
          tags_any: ["suspicious", "encoded", "download"]
      - name: fim_change_roaming
        match:
          source: "sentrafim"
          kind: "file_change"
          field_contains:
            path: "AppData\\Roaming"
      - name: outbound_http
        match:
          source: "stealershield"
          kind: "network_http"
          tags_any: ["unknown_domain"]
```

## Testing

```bash
cd backend
go test ./...
```

The main test verifies that the correlator correctly turns a synthetic sequence of events into a
single incident, and that duplicates are suppressed.
