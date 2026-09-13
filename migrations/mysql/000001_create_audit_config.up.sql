CREATE TABLE IF NOT EXISTS _audit_config (
    table_name VARCHAR(255) PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    unattributed_policy VARCHAR(32) NOT NULL DEFAULT 'tolerate', -- 'tolerate', 'alert'
    severity_tier VARCHAR(32) NOT NULL DEFAULT 'normal',         -- 'normal', 'critical'
    encrypted_columns JSON NOT NULL,                             -- e.g. ["ssn", "credit_card"]
    bootstrap_required BOOLEAN NOT NULL DEFAULT FALSE,
    bootstrap_status VARCHAR(32) NOT NULL DEFAULT 'not_started', -- 'not_started', 'in_progress', 'complete'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
