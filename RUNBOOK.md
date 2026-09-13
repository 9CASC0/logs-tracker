# Global Audit Logger — Operations & Rollout Runbook

This document serves as the operational guide and quick reference for operating, troubleshooting, and verifying the Global Audit Logger system.

---

## 1. Quick Architecture Recap

- **Source**: MySQL binary log with `ROW` format and `FULL` row image.
- **Attribution**: Transactions writing context to `_audit_context` are attributed to that user (`actor_type = 'USER'`). Missing context rows evaluate `_audit_config.unattributed_policy` (`tolerate` -> `SYSTEM`, `alert` -> `UNATTRIBUTED` + alert).
- **Tamper Evidence**: Changes grouped into batches (max 60s or 5,000 events). Each batch constructs a deterministic Merkle tree. The Merkle root is signed with an Ed25519 key encrypted at rest on disk (`keys.enc`). Checkpoints are written to WORM storage.
- **Storage**: PostgreSQL hot store (90-day retention). Older batches are tiered to immutable local WORM directory (`archives/{batch_id}.jsonl`) by `cmd/tiering`.
- **API**: Internal RBAC-protected API (`/audit/*`) + unauthenticated Public Verification Feed (`/public/verification/*`).

---

## 2. Initial Setup & Key Provisioning

Before starting the daemon, generate an encrypted keyfile containing the Ed25519 signing keypair and AES-256-GCM encryption key:

```bash
# Generate keys.enc encrypted with your passphrase
go run ./cmd/keygen -action generate -keyfile ./keys/keys.enc -passphrase "YOUR_SECURE_PASSPHRASE" -version v1

# Inspect the public key for publication
go run ./cmd/keygen -action pubkey -keyfile ./keys/keys.enc -passphrase "YOUR_SECURE_PASSPHRASE" -version v1
```

*Note: In production, store the passphrase in the OS keychain or secret manager. The file permissions on `keys.enc` are restricted to `0600`.*

---

## 3. Starting the Services

### Using Docker Compose

```bash
# 1. Bring up databases and services
docker compose up -d

# 2. Check logs
docker compose logs -f auditlogd
docker compose logs -f apiserver
```

### Running Natively

```bash
# Start daemon
go run ./cmd/daemon \
  -mysql-host 127.0.0.1 -mysql-port 3306 -mysql-user root -mysql-pass root -mysql-db app \
  -postgres-url "postgres://postgres:postgres@localhost:5432/auditlog?sslmode=disable" \
  -worm-dir "./worm-storage" \
  -keyfile "./keys/keys.enc" \
  -passphrase "YOUR_SECURE_PASSPHRASE" \
  -webhook-url "https://discord.com/api/webhooks/..."

# Start API server
go run ./cmd/apiserver \
  -addr :8080 \
  -postgres-url "postgres://postgres:postgres@localhost:5432/auditlog?sslmode=disable" \
  -keyfile "./keys/keys.enc" \
  -passphrase "YOUR_SECURE_PASSPHRASE"
```

---

## 4. Operational Incident Runbooks

### Incident 1: "Unattributed change alert fired"

1. **Check alert severity**:
   - `[CRITICAL]` with `@here`: Touched a critical table (e.g. `payments`, `permissions`). Immediate triage required.
   - `[NORMAL]`: Touched a strict table, but standard tier. Batch review acceptable.
2. **Retrieve alert details**:
   Look at the Discord/Telegram message for:
   - `Table Name`
   - `Transaction ID`
   - `Record ID`
3. **Query record history via API**:
   ```bash
   curl -H "Authorization: Bearer admin-secret-token" \
     "http://localhost:8080/audit/records/{RECORD_ID}"
   ```
4. **Determine cause**:
   - Was a manual SQL update executed by an engineer?
   - Was a migration or background worker script run without setting `_audit_context`?
5. **Action**:
   - If legitimate system process: update the process to write `_audit_context` in its transaction, or update `_audit_config.unattributed_policy = 'tolerate'` for that table.
   - If unauthorized query: escalate to security response immediately.
6. **Acknowledge alert**:
   ```bash
   curl -X POST -H "Authorization: Bearer admin-secret-token" \
     "http://localhost:8080/audit/alerts/{ALERT_ID}/ack"
   ```

---

### Incident 2: "Daemon is down or crashed"

1. **Verify binlog safety**:
   MySQL binlog retention protects against lost events. The daemon commits its exact binlog coordinate (`binlog_file`, `binlog_position`) transactionally with each batch into PostgreSQL.
2. **Check last committed position**:
   ```sql
   SELECT binlog_file, binlog_position, closed_at FROM audit_batches ORDER BY closed_at DESC LIMIT 1;
   ```
3. **Restart daemon**:
   The daemon reads the checkpoint automatically and resumes replication with zero duplicate or skipped records:
   ```bash
   docker compose restart auditlogd
   ```
4. **Confirm catch-up**:
   Inspect daemon logs:
   `Resuming binlog consumption from checkpoint mysql-bin.00000X:YYYYYY`

---

## 5. Dispute Resolution & Cryptographic Verification

When an end-user, customer, auditor, or external regulator disputes a record:

### Method A: Internal API Verification

```bash
curl -H "Authorization: Bearer app-service-token" \
  "http://localhost:8080/audit/records/{RECORD_ID}/verify"
```
Returns:
```json
{
  "valid": true,
  "record_id": "...",
  "batch_id": "...",
  "merkle_root_hex": "...",
  "signature_hex": "...",
  "key_version": "v1",
  "verified_at": "..."
}
```

### Method B: External Public Verification (Zero Internal Trust)

1. Fetch published public key:
   ```bash
   curl http://localhost:8080/public/verification/keys
   ```
2. Fetch signed roots history:
   ```bash
   curl http://localhost:8080/public/verification/roots
   ```
3. Submit proof to public verification endpoint:
   ```bash
   curl -X POST http://localhost:8080/public/verification/verify \
     -H "Content-Type: application/json" \
     -d '{
       "record": { ...canonical record fields... },
       "proof": [ ...merkle proof siblings... ],
       "merkle_root_hex": "...",
       "signature_hex": "...",
       "key_version": "v1"
     }'
   ```

---

## 6. Table Rollout & Bootstrap Strategy

Onboard tables in risk-ordered waves:
1. **Wave 1 (Low Risk)**: Low-volume lookup tables without PII.
2. **Wave 2 (Medium Risk)**: Tables with configured PII encryption.
3. **Wave 3 (Critical)**: High-security tables (`payments`, `permissions`, `credentials`).

### Registering a New Table for Audit

In MySQL:
```sql
INSERT INTO _audit_config (
    table_name,
    enabled,
    unattributed_policy,
    severity_tier,
    encrypted_columns,
    bootstrap_required,
    bootstrap_status
) VALUES (
    'customers',
    TRUE,
    'alert',
    'critical',
    JSON_ARRAY('ssn', 'tax_id'),
    TRUE,
    'not_started'
);
```

- The daemon detects the insert on `_audit_config` via CDC automatically without restart.
- Because `bootstrap_required = TRUE` and `bootstrap_status = 'not_started'`, the daemon performs a consistent point-in-time snapshot of existing rows, builds a Merkle-anchored batch, signs the root, commits to WORM storage, and sets `bootstrap_status = 'complete'`.

---

## 7. Scheduled Retention Tiering

Run the standalone tiering binary periodically (e.g. daily via cron or Kubernetes CronJob):

```bash
# Run tiering job for records older than 90 days
go run ./cmd/tiering \
  -postgres-url "postgres://postgres:postgres@localhost:5432/auditlog?sslmode=disable" \
  -worm-dir "./worm-storage" \
  -retention-days 90
```

- Exports full batch records to `./worm-storage/archives/{batch_id}.jsonl`.
- Chmods archive file read-only (`0444`).
- Inserts index in `audit_worm_index`.
- Purges records from PostgreSQL `audit_records`.
- Updates `audit_batches.status = 'archived'`.
- Fully idempotent: safe to re-run anytime.
