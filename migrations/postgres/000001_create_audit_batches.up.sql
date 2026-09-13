CREATE TABLE IF NOT EXISTS audit_batches (
    id UUID PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ NOT NULL,
    event_count INT NOT NULL,
    merkle_root BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    key_version VARCHAR(64) NOT NULL,
    binlog_file VARCHAR(255) NOT NULL,
    binlog_position BIGINT NOT NULL,
    status VARCHAR(32) NOT NULL, -- 'open', 'closed', 'signed', 'archived', 'purged'
    worm_object_key TEXT,
    is_bootstrap BOOLEAN NOT NULL DEFAULT FALSE,
    bootstrap_table_name VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_audit_batches_closed_status ON audit_batches (closed_at, status);
