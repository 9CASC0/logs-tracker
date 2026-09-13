-- Example application table: users
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    ssn VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Register 'users' table into _audit_config in the same migration
INSERT INTO _audit_config (
    table_name,
    enabled,
    unattributed_policy,
    severity_tier,
    encrypted_columns,
    bootstrap_required,
    bootstrap_status
) VALUES (
    'users',
    TRUE,
    'alert',
    'critical',
    JSON_ARRAY('ssn'),
    FALSE,
    'complete'
) ON DUPLICATE KEY UPDATE enabled = TRUE;

-- Example transaction illustrating how the application attributes changes:
-- START TRANSACTION;
-- INSERT INTO _audit_context (user_id, actor_type, request_id) VALUES ('usr-123', 'USER', 'req-abc');
-- INSERT INTO users (name, email, ssn) VALUES ('Alice', 'alice@example.com', '123-45-6789');
-- COMMIT;
