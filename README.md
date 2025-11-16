# Nullbit XDR Hub (SentraCore)

Mini XDR / poor man's SIEM to aggregate events from your custom sensors (SentraFIM, StealerShield, PowerShell hunters, kernel loggers, eBPF, yara scanners, etc.), correlate them via YAML rules and track incidents in a single timeline.

Backend is Go (HTTP + gRPC), PostgreSQL for configuration/incidents, NATS for the event bus, and a small Next.js UI for timeline search and incident handling.

Author assumptions:
- PostgreSQL is the primary store, single-tenant, up to ~50 hosts.
- NATS is used as the event queue; correlation is triggered from it (with an in-process fallback).
- Auth is JWT-based with simple RBAC: `admin`, `analyst`, `read-only`.
- Raw events live in Postgres; ClickHouse is not wired in this initial version.

## Features

- HTTP ingest: `POST /api/v1/events`
- gRPC ingest: bidirectional-like client stream defined in `proto/ingest.proto` (server on `:9090`)
- Unified event schema:

  ```
  {
    "source": "sentrafim",
    "host_id": "host-01",
    "timestamp": "2025-11-16T12:00:00Z",
    "kind": "powershell",
    "severity": "high",
    "tags": ["suspicious", "t1059"],
    "fields": {
      "path": "C:\\Users\\bob\\AppData\\Roaming\\evil.ps1",
      "command_line": "powershell.exe -Enc ...",
      "remote_domain": "weird-bad-domain.biz"
    }
  }
````
