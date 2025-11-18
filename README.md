# SentraCore - Minimal XDR Hub

SentraCore is a small XDR / mini SIEM hub for a single organisation.
It accepts security telemetry from multiple sensors over HTTP, stores events in PostgreSQL and runs simple correlation rules to raise incidents when several suspicious signals line up on the same host.

This repository contains only the backend service (Go + PostgreSQL).
A web UI or dashboards can be added later on top of the HTTP API.

---

## What SentraCore gives you

SentraCore is deliberately minimal but practical. Out of the box you get:

* HTTP ingestion endpoint for structured security events
  `POST /api/v1/ingest/events`
* Normalised event model:

  * `source` - which sensor produced the event
  * `host_id` - which endpoint or server it belongs to
  * `ts` - timestamp in UTC
  * `kind` - high level type of activity (process_start, file_change, network_http, and so on)
  * `severity` - low, medium, high, critical
  * `tags` - simple list of labels for easy filtering and correlation
  * `fields` - arbitrary JSON with sensor specific fields
* Storage of events and incidents in PostgreSQL with reasonable indexes
* YAML driven correlation rules with sliding time windows
* Incident life cycle with statuses:

  * `open`
  * `triaged`
  * `closed`
* Simple RBAC with three roles:

  * `admin`
  * `analyst`
  * `read_only`
* JWT based login for humans and tools
* A small JSON API that you can put a UI or Grafana panel on top of

It is intentionally not:

* A full blown, multi tenant SIEM
* A log shipping system
* A replacement for production XDR products

Think of it as a focused hub for a homelab or a small team that already has a few sensors and wants a single place where they come together and trigger incidents.

---

## High level architecture

At a very high level the data flow looks like this:

```text
[sensors]  --->  HTTP ingest  --->  SentraCore backend  --->  PostgreSQL
  (EDR,           /api/v1/            (Go service)            (events,
   FIM,           ingest/events                                incidents,
   network)                                                     users)

                                     |
                                     +--> correlation engine
                                     |     (rules.yaml, sliding windows)
                                     |
                                     +--> incidents API
                                           /api/v1/incidents
```

Roughly:

1. Your sensors send JSON events to the ingest endpoint with an API key.
2. SentraCore normalises and stores them in the `events` table.
3. On every new event the correlation engine looks at the recent history on that host and applies the rules from `config/rules.yaml`.
4. If a rule matches, a new incident is created in the `incidents` table (unless there is already a similar open incident).
5. Analysts log in, pull incidents and events over HTTP, and update statuses when they are done.

---

## Data model

### Events

Events are the atomic pieces of telemetry. They are stored in the `events` table:

```sql
CREATE TABLE events (
    id          bigserial primary key,
    source      text not null,
    host_id     text not null,
    ts          timestamptz not null,
    kind        text not null,
    severity    text not null,
    tags        text[] not null default '{}',
    fields      jsonb not null default '{}'::jsonb,
    created_at  timestamptz not null default now()
);
```

In Go this is represented as:

```go
type Event struct {
    ID        int64                  `json:"id"`
    Source    string                 `json:"source"`
    HostID    string                 `json:"host_id"`
    Timestamp time.Time              `json:"ts"`
    Kind      string                 `json:"kind"`
    Severity  Severity               `json:"severity"`
    Tags      []string               `json:"tags"`
    Fields    map[string]interface{} `json:"fields"`
    CreatedAt time.Time              `json:"created_at"`
}
```

Defaults applied on ingest:

* If `ts` is missing or zero
  SentraCore sets it to `time.Now().UTC()`.
* If `severity` is empty
  It is set to `"low"`.
* If `tags` is null
  It becomes an empty list `[]`.
* If `fields` is null
  It becomes an empty object `{}`.

Minimal valid event payload:

```json
{
  "source": "powershell-hunt",
  "host_id": "win-01",
  "kind": "process_start"
}
```

Typical richer event:

```json
{
  "source": "powershell-hunt",
  "host_id": "win-01",
  "ts": "2025-01-01T10:15:00Z",
  "kind": "process_start",
  "severity": "high",
  "tags": ["windows", "powershell", "suspicious"],
  "fields": {
    "user": "alice",
    "command_line": "powershell.exe -enc ...",
    "parent_process": "explorer.exe",
    "session_id": 3
  }
}
```

### Incidents

Incidents are created by the correlation engine when several events on the same host match a rule within a time window.

Database schema:

```sql
CREATE TABLE incidents (
    id             bigserial primary key,
    rule_id        text not null,
    title          text not null,
    description    text not null,
    severity       text not null,
    host_id        text not null,
    status         text not null,
    first_event_ts timestamptz not null,
    last_event_ts  timestamptz not null,
    event_ids      bigint[] not null,
    tags           text[] not null default '{}',
    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now()
);
```

Go model:

```go
type Incident struct {
    ID           int64     `json:"id"`
    RuleID       string    `json:"rule_id"`
    Title        string    `json:"title"`
    Description  string    `json:"description"`
    Severity     string    `json:"severity"`
    HostID       string    `json:"host_id"`
    Status       Status    `json:"status"`
    FirstEventTS time.Time `json:"first_event_ts"`
    LastEventTS  time.Time `json:"last_event_ts"`
    EventIDs     []int64   `json:"event_ids"`
    Tags         []string  `json:"tags"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
}
```

Status values:

* `open` - new or still under investigation
* `triaged` - looked at, maybe parked
* `closed` - considered done, will not be de duplicated against

Indexes for common queries:

* By status
* By host
* By rule id, host id, last event timestamp
  used when checking if a similar incident already exists

Example incident returned by the API:

```json
{
  "id": 42,
  "rule_id": "powershell_fim_http_combo",
  "title": "Suspicious PowerShell + FIM change + outbound HTTP",
  "description": "Detects a sequence of suspicious PowerShell, FIM change in roaming profile, and outbound HTTP on the same host within 5 minutes.",
  "severity": "high",
  "host_id": "win-01",
  "status": "open",
  "first_event_ts": "2025-01-01T10:15:00Z",
  "last_event_ts": "2025-01-01T10:17:10Z",
  "event_ids": [1001, 1005, 1010],
  "tags": ["windows", "powershell", "fim", "http"],
  "created_at": "2025-01-01T10:17:11Z",
  "updated_at": "2025-01-01T10:17:11Z"
}
```

### Users and roles

Users live in the `users` table and in `config/users.yaml` for initial seeding.

Schema:

```sql
CREATE TABLE users (
    id            bigserial primary key,
    username      text not null unique,
    password_hash text not null,
    role          text not null,
    created_at    timestamptz not null default now()
);
```

Roles:

* `admin`
  Full access, including changing incident status and managing users in the future.
* `analyst`
  Can view events and incidents, and change incident status.
* `read_only`
  Can only view events and incidents.

On first start the backend seeds users from `backend/config/users.yaml`. The example file contains three users:

```yaml
users:
  - username: admin
    password: admin123
    role: admin
  - username: analyst
    password: analyst123
    role: analyst
  - username: viewer
    password: viewer123
    role: read_only
```

---

## Running SentraCore

You have two main options.

### Option 1. Using docker compose (recommended for first run)

Requirements:

* Docker
* docker compose
* Port 8080 free on the host

From the repo root:

```bash
docker compose up --build
```

This will start two services:

* `db`
  PostgreSQL 16 with database `sentracore` and user `sentracore`.
* `backend`
  SentraCore HTTP API on `http://localhost:8080`.

Environment for the backend is defined in `docker-compose.yml`:

```yaml
environment:
  SENTRACORE_HTTP_ADDR: ":8080"
  SENTRACORE_DB_DSN: "postgres://sentracore:sentracore@db:5432/sentracore?sslmode=disable"
  SENTRACORE_RULES_PATH: "/app/config/rules.yaml"
  SENTRACORE_USERS_PATH: "/app/config/users.yaml"
  SENTRACORE_JWT_SECRET: "dev-change-me"
  SENTRACORE_INGEST_TOKEN: "dev-ingest-token"
```

On first start:

* Database schema is applied from `backend/sql/schema.sql`.
* Users are loaded from `backend/config/users.yaml`.

You should change at least:

* `SENTRACORE_JWT_SECRET`
* `SENTRACORE_INGEST_TOKEN`

before exposing the service to anything outside a lab.

### Option 2. Running the backend manually

Requirements:

* Go 1.22 or newer
* Local PostgreSQL reachable with a DSN similar to
  `postgres://sentracore:sentracore@localhost:5432/sentracore?sslmode=disable`

Steps:

```bash
cd backend
go mod tidy
go run ./cmd/sentracore
```

Environment variables (with defaults):

* `SENTRACORE_HTTP_ADDR`
  HTTP listen address, default `:8080`.
* `SENTRACORE_DB_DSN`
  PostgreSQL DSN, default
  `postgres://sentracore:sentracore@localhost:5432/sentracore?sslmode=disable`.
* `SENTRACORE_RULES_PATH`
  Path to correlation rules YAML, default `config/rules.yaml`.
* `SENTRACORE_USERS_PATH`
  Path to users YAML for seeding, default `config/users.yaml`.
* `SENTRACORE_JWT_SECRET`
  Secret key for signing JWTs. If not set, a development value `dev-secret-change-me` is used.
* `SENTRACORE_INGEST_TOKEN`
  Shared secret for the ingest endpoint. If empty, ingest is open without an API key.

---

## API overview

Base URL in development:

```text
http://localhost:8080
```

All endpoints return JSON.

### Health check

```http
GET /healthz
```

Example:

```bash
curl http://localhost:8080/healthz
```

Response:

```json
{"status":"ok"}
```

### Authentication

Login endpoint:

```http
POST /api/v1/auth/login
```

Request body:

```json
{
  "username": "admin",
  "password": "admin123"
}
```

Example curl:

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

Response structure is simple:

```json
{
  "token": "<jwt-token>",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin"
  }
}
```

You then pass the token in the `Authorization` header:

```http
Authorization: Bearer <jwt-token>
```

This is required for all read and write endpoints except `/healthz` and `/api/v1/ingest/events`.

### Ingesting events

Endpoint:

```http
POST /api/v1/ingest/events
```

This endpoint does not use JWT. Instead it uses a shared API key.

Headers:

* `Content-Type: application/json`
* `X-Api-Key: <SENTRACORE_INGEST_TOKEN>`

Body: single event object as described earlier.

Example:

```bash
curl -X POST http://localhost:8080/api/v1/ingest/events \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: dev-ingest-token" \
  -d '{
    "source": "powershell-hunt",
    "host_id": "win-01",
    "ts": "2025-01-01T10:15:00Z",
    "kind": "process_start",
    "severity": "high",
    "tags": ["windows", "powershell", "suspicious"],
    "fields": {
      "user": "alice",
      "command_line": "powershell.exe -enc ...",
      "parent_process": "explorer.exe"
    }
  }'
```

On success you get HTTP 200 with the stored event including generated `id` and `created_at`.

If the API key is wrong or missing you get HTTP 401.

Required fields:

* `source`
* `host_id`
* `kind`

If any of these are missing you get HTTP 400.

Behind the scenes the correlator is called for every accepted event.

### Querying events

Endpoint:

```http
GET /api/v1/events
Authorization: Bearer <jwt-token>
```

Query parameters:

* `host_id`
  Filter by host id.
* `source`
  Filter by event source.
* `kind`
  Filter by event kind.
* `severity`
  Filter by severity (`low`, `medium`, `high`, `critical`).
* `tag`
  Filter by a single tag value. Events are returned only if their `tags` array contains this tag.
* `since`
  Lower bound for timestamp in RFC3339 format, for example `2025-01-01T00:00:00Z`.
* `until`
  Upper bound for timestamp in RFC3339 format.
* `limit`
  Max number of events to return. If not set or if invalid, a default limit of 200 is used.
  Values larger than 1000 are clamped to 200.

Example:

```bash
curl "http://localhost:8080/api/v1/events?host_id=win-01&severity=high&limit=50" \
  -H "Authorization: Bearer <token>"
```

Response: JSON array of events ordered by `ts` descending.

### Listing incidents

Endpoint:

```http
GET /api/v1/incidents
Authorization: Bearer <jwt-token>
```

Query parameters:

* `status`
  Optional, one of `open`, `triaged`, `closed`.
* `host_id`
  Optional, filter by host.
* `severity`
  Optional, filter by severity.
* `limit`
  Optional, maximum number of incidents to return.

Example:

```bash
curl "http://localhost:8080/api/v1/incidents?status=open&limit=20" \
  -H "Authorization: Bearer <token>"
```

Response: JSON array of incidents.

### Incident details and status updates

Endpoint to get a single incident:

```http
GET /api/v1/incidents/{id}
Authorization: Bearer <jwt-token>
```

Example:

```bash
curl http://localhost:8080/api/v1/incidents/42 \
  -H "Authorization: Bearer <token>"
```

To update status you use the same path with `PATCH` and a small JSON payload.
Role check is enforced: usually `admin` or `analyst` can change status, `read_only` cannot.

```http
PATCH /api/v1/incidents/{id}
Authorization: Bearer <jwt-token>
Content-Type: application/json
```

Body:

```json
{
  "status": "triaged"
}
```

Example:

```bash
curl -X PATCH http://localhost:8080/api/v1/incidents/42 \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"status":"closed"}'
```

On success you get HTTP 204 with empty body.

---

## Correlation rules

Rules live in `backend/config/rules.yaml` and are loaded on startup.
If you change them you need to restart the backend in the current version.

A rule describes:

* an id
* a human readable title and description
* severity and tags for the resulting incident
* a sliding time window
* a list of steps, each step describing what events must be present

Go structure:

```go
type RuleConfig struct {
    ID          string        `yaml:"id"`
    Title       string        `yaml:"title"`
    Description string        `yaml:"description"`
    Severity    string        `yaml:"severity"`
    Window      time.Duration `yaml:"window"`
    Tags        []string      `yaml:"tags"`
    Steps       []RuleStep    `yaml:"steps"`
}

type RuleStep struct {
    Name  string    `yaml:"name"`
    Match StepMatch `yaml:"match"`
}

type StepMatch struct {
    Source        string            `yaml:"source"`
    Kind          string            `yaml:"kind"`
    TagsAny       []string          `yaml:"tags_any"`
    FieldEquals   map[string]string `yaml:"field_equals"`
    FieldContains map[string]string `yaml:"field_contains"`
}
```

Matching semantics:

* Events must come from the same host (`host_id`).
* Time window is relative to the last event in the sequence.
* For each step SentraCore looks for at least one event that:

  * has matching `source` if given
  * has matching `kind` if given
  * has at least one tag from `tags_any` if specified
  * has `fields[key] == value` for every entry in `field_equals`
  * has `value` as substring of `fields[key]` for every entry in `field_contains`
* If every step has at least one matching event in the window, an incident is eligible.

Duplicate suppression:

Before creating an incident, the correlator asks the store:

```sql
SELECT 1 FROM incidents
WHERE rule_id = $1
  AND host_id = $2
  AND last_event_ts >= $3
  AND status != 'closed'
LIMIT 1;
```

If such an incident exists, the rule is considered already triggered for that host in the current window, and no new incident is created.

### Example rule

This is the rule shipped in `config/rules.yaml`:

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

Plain language:

* On a single host within 5 minutes:

  1. A suspicious PowerShell process start was seen (based on tags).
  2. A file change was seen in a roaming profile path.
  3. An HTTP request went out to a domain the network sensor does not know.

If there is no open incident for this rule and host with `last_event_ts` inside the last 5 minutes, SentraCore creates a new high severity incident.

---

## Example end to end flow

1. Start services:

   ```bash
   docker compose up --build
   ```

2. Send three test events that fit the example rule (one per step).

3. Log in:

   ```bash
   curl -X POST http://localhost:8080/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"analyst","password":"analyst123"}'
   ```

   Copy the `"token"` from the response.

4. List incidents:

   ```bash
   curl "http://localhost:8080/api/v1/incidents?status=open" \
     -H "Authorization: Bearer <token>"
   ```

   You should see a single incident created by the rule, referencing the three event ids.

5. If you want to close it:

   ```bash
   curl -X PATCH http://localhost:8080/api/v1/incidents/<id> \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"status":"closed"}'
   ```

---

## Testing

There is a small but meaningful test suite for the backend.

Run from the `backend` directory:

```bash
cd backend
go test ./...
```

Tests cover:

* Correlator logic that turns a synthetic sequence of events into a single incident
* Duplicate suppression logic for incidents
* Basic storage operations

---

## License

MIT.
