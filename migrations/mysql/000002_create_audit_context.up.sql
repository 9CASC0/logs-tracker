CREATE TABLE IF NOT EXISTS _audit_context (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    transaction_id VARCHAR(255),
    user_id VARCHAR(255) NOT NULL,
    actor_type VARCHAR(32) NOT NULL DEFAULT 'USER',
    request_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_context_tx (transaction_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
