CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    source TEXT NOT NULL,
    host_id TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    fields JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_events_host_ts ON events (host_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);

CREATE TABLE IF NOT EXISTS incidents (
    id BIGSERIAL PRIMARY KEY,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    host_id TEXT NOT NULL,
    status TEXT NOT NULL,
    first_event_ts TIMESTAMPTZ NOT NULL,
    last_event_ts TIMESTAMPTZ NOT NULL,
    event_ids BIGINT[] NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_host ON incidents (host_id);
CREATE INDEX IF NOT EXISTS idx_incidents_rule_host_ts ON incidents (rule_id, host_id, last_event_ts);

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
