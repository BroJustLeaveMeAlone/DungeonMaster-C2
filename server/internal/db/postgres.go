package db

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool is the shared connection pool. Call Init once at startup.
var Pool *pgxpool.Pool

func Init(ctx context.Context) error {
	dsn := os.Getenv("DM_DB_DSN")
	if dsn == "" {
		return fmt.Errorf("db: DM_DB_DSN environment variable is not set")
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("db: parse config: %w", err)
	}
	cfg.MaxConns = 20

	Pool, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("db: connect: %w", err)
	}

	if err := Pool.Ping(ctx); err != nil {
		return fmt.Errorf("db: ping: %w", err)
	}

	return migrate(ctx)
}

func migrate(ctx context.Context) error {
	_, err := Pool.Exec(ctx, schema)
	return err
}

// SeedDefaultListener inserts the C2 listener config if no listeners exist yet.
func SeedDefaultListener(ctx context.Context, c2Addr string) error {
	var count int
	if err := Pool.QueryRow(ctx, `SELECT COUNT(*) FROM listeners`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	host, portStr, err := net.SplitHostPort(c2Addr)
	if err != nil {
		return fmt.Errorf("parse c2 addr %q: %w", c2Addr, err)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	port, _ := strconv.Atoi(portStr)

	callbackHost := os.Getenv("DM_CALLBACK_HOST")
	if callbackHost == "" {
		callbackHost = host
	}

	_, err = Pool.Exec(ctx, `
		INSERT INTO listeners (name, bind_host, bind_port, callback_host, type)
		VALUES ('Default HTTPS C2', $1, $2, $3, 'https')`, host, port, callbackHost)
	return err
}

const schema = `
CREATE TABLE IF NOT EXISTS operators (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    totp_secret TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'operator',
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS campaigns (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL,
    description  TEXT,
    client_name  TEXT,
    objective    TEXT,
    scope_cidrs  TEXT[],
    scope_domains TEXT[],
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at   TIMESTAMPTZ,
    ended_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS listeners (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT NOT NULL,
    bind_host     TEXT NOT NULL,
    bind_port     INT NOT NULL,
    callback_host TEXT,
    type          TEXT NOT NULL DEFAULT 'https',
    profile_name  TEXT,
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    cert_pem      TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE listeners ADD COLUMN IF NOT EXISTS callback_host TEXT;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS seq BIGSERIAL;

CREATE TABLE IF NOT EXISTS builds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id     UUID REFERENCES campaigns(id),
    operator_id     UUID REFERENCES operators(id),
    target_os       TEXT NOT NULL,
    target_arch     TEXT NOT NULL,
    listener_id     UUID REFERENCES listeners(id),
    traffic_profile TEXT,
    sleep_seconds   INT NOT NULL DEFAULT 30,
    jitter_pct      INT NOT NULL DEFAULT 20,
    evasion_flags   JSONB NOT NULL DEFAULT '{}',
    ephemeral       BOOLEAN NOT NULL DEFAULT TRUE,
    status          TEXT NOT NULL DEFAULT 'queued',
    artifact_url    TEXT,
    sha256          TEXT,
    build_uuid      UUID NOT NULL DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    build_id        UUID REFERENCES builds(id),
    campaign_id     UUID REFERENCES campaigns(id),
    hostname        TEXT,
    username        TEXT,
    domain          TEXT,
    ip_internal     TEXT,
    ip_external     TEXT,
    os              TEXT,
    arch            TEXT,
    os_version      TEXT,
    is_elevated     BOOLEAN NOT NULL DEFAULT FALSE,
    process_name    TEXT,
    pid             INT,
    is_alive        BOOLEAN NOT NULL DEFAULT TRUE,
    is_revoked      BOOLEAN NOT NULL DEFAULT FALSE,
    revoke_reason   TEXT,
    active_channel  TEXT NOT NULL DEFAULT 'https',
    sleep_seconds   INT NOT NULL DEFAULT 30,
    jitter_pct      INT NOT NULL DEFAULT 20,
    edr_detected    TEXT[],
    av_detected     TEXT[],
    session_pubkey  BYTEA,
    server_privkey  BYTEA,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tasks (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id           UUID REFERENCES sessions(id),
    operator_id          UUID REFERENCES operators(id),
    type                 TEXT NOT NULL,
    args                 BYTEA,
    status               TEXT NOT NULL DEFAULT 'queued',
    output               BYTEA,
    mitre_technique_id   TEXT,
    requires_confirmation BOOLEAN NOT NULL DEFAULT FALSE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at              TIMESTAMPTZ,
    completed_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tasks_session_status ON tasks(session_id, status);
CREATE INDEX IF NOT EXISTS idx_sessions_campaign ON sessions(campaign_id);
CREATE INDEX IF NOT EXISTS idx_sessions_alive ON sessions(is_alive) WHERE is_alive = TRUE;

CREATE TABLE IF NOT EXISTS events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type         TEXT NOT NULL,
    campaign_id  UUID,
    session_id   UUID,
    operator_id  UUID,
    payload      JSONB,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_campaign ON events(campaign_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS vault_credentials (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id   TEXT NOT NULL DEFAULT '',
    campaign_id  TEXT NOT NULL DEFAULT '',
    hostname     TEXT NOT NULL DEFAULT '',
    username     TEXT NOT NULL DEFAULT '',
    domain       TEXT NOT NULL DEFAULT '',
    secret       TEXT NOT NULL DEFAULT '',
    kind         TEXT NOT NULL DEFAULT 'other',
    source       TEXT NOT NULL DEFAULT 'manual',
    notes        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS evidence (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id          UUID REFERENCES campaigns(id),
    session_id           UUID REFERENCES sessions(id),
    task_id              UUID REFERENCES tasks(id),
    operator_id          UUID REFERENCES operators(id),
    type                 TEXT NOT NULL,
    filename             TEXT,
    url                  TEXT,
    caption              TEXT,
    mitre_technique_id   TEXT,
    tags                 TEXT[],
    captured_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ttp_mappings (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id          UUID REFERENCES campaigns(id),
    session_id           UUID,
    task_id              UUID,
    mitre_technique_id   TEXT NOT NULL,
    mitre_technique_name TEXT,
    tactic               TEXT,
    confirmed_by         UUID REFERENCES operators(id),
    confirmed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS c2_profiles (
    name          TEXT PRIMARY KEY,
    user_agent    TEXT NOT NULL DEFAULT '',
    register_path TEXT NOT NULL DEFAULT '/r',
    poll_path     TEXT NOT NULL DEFAULT '/c',
    extra_headers JSONB NOT NULL DEFAULT '[]',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_id  UUID,
    action       TEXT NOT NULL,
    resource     TEXT,
    resource_id  TEXT,
    detail       JSONB,
    ip_address   TEXT,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS playbooks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    auto_run    BOOLEAN NOT NULL DEFAULT TRUE,
    tasks       JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_playbooks_campaign ON playbooks(campaign_id);
`
