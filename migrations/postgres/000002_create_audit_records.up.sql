CREATE TABLE IF NOT EXISTS audit_records (
    id UUID PRIMARY KEY,
    batch_id UUID NOT NULL REFERENCES audit_batches(id) ON DELETE CASCADE,
    table_name VARCHAR(255) NOT NULL,
    primary_key JSONB NOT NULL,
    event_type VARCHAR(16) NOT NULL, -- 'INSERT', 'UPDATE', 'DELETE'
    before_image JSONB,
    after_image JSONB,
    actor_user_id VARCHAR(255),
    actor_type VARCHAR(32) NOT NULL, -- 'USER', 'SYSTEM', 'UNATTRIBUTED'
    transaction_id VARCHAR(255) NOT NULL,
    schema_version VARCHAR(64) NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL,
    merkle_leaf_index INT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_records_table_pk ON audit_records (table_name, primary_key);
CREATE INDEX IF NOT EXISTS idx_audit_records_batch_id ON audit_records (batch_id);
