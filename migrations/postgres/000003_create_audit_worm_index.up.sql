CREATE TABLE IF NOT EXISTS audit_worm_index (
    batch_id UUID PRIMARY KEY REFERENCES audit_batches(id) ON DELETE CASCADE,
    worm_object_key TEXT NOT NULL,
    tiered_at TIMESTAMPTZ NOT NULL,
    purged_from_postgres_at TIMESTAMPTZ
);
