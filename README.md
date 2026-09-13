# Global Audit Logger (`auditlogd`)

<p align="center">
  <img src="docs/images/hero_banner.jpg" alt="Global Audit Logger Banner" width="100%" />
</p>

<p align="center">
  <a href="https://golang.org"><img src="https://img.shields.io/badge/go-1.24+-00ADD8?style=for-the-badge&logo=go" alt="Go Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License: MIT"></a>
  <a href=".github/workflows/ci.yml"><img src="https://img.shields.io/badge/CI-Passing-brightgreen.svg?style=for-the-badge&logo=githubactions" alt="CI Status"></a>
  <a href="#cryptographic-guarantees--benchmarks"><img src="https://img.shields.io/badge/Tamper--Evident-RFC%206962%20%2B%20Ed25519-blueviolet.svg?style=for-the-badge" alt="Tamper Evident"></a>
  <a href="#rest-api--public-verification"><img src="https://img.shields.io/badge/Verification-Zero--Trust%20Portal-orange.svg?style=for-the-badge" alt="Verification Portal"></a>
</p>

---

## Table of Contents

- [The Real-World Problem](#the-real-world-problem)
- [How `auditlogd` Solves It](#how-auditlogd-solves-it)
- [Architecture & Dataflow](#architecture--dataflow)
- [Real-World Dispute Scenarios](#real-world-dispute-scenarios)
  - [Scenario 1: Customer Disputing a Balance Alteration](#scenario-1-customer-disputing-a-balance-alteration)
  - [Scenario 2: Rogue DBA Direct SQL Injection](#scenario-2-rogue-dba-direct-sql-injection)
  - [Scenario 3: PII Privacy Protection (GDPR / HIPAA)](#scenario-3-pii-privacy-protection-gdpr--hipaa)
- [Cryptographic Guarantees & Benchmarks](#cryptographic-guarantees--benchmarks)
- [Interactive Web Verification Portal](#interactive-web-verification-portal)
- [CLI Dispute Verification Tool](#cli-dispute-verification-tool)
- [Quick Start Guide](#quick-start-guide)
  - [1. Running with Docker Compose](#1-running-with-docker-compose)
  - [2. Running Natively](#2-running-natively)
- [REST API Reference](#rest-api-reference)
- [Retention Tiering & WORM Archival](#retention-tiering--worm-archival)
- [Testing & Quality Verification](#testing--quality-verification)
- [Runbooks & Operations](#runbooks--operations)
- [License](#license)

---

## The Real-World Problem

In production database environments, organizations routinely face a critical blind spot: **How can you definitively prove who changed a piece of data, what the exact row state was before and after, and that the audit record itself hasn't been quietly manipulated?**

Conventional approaches fail in practice:
1. **Application-Level Logs (`logger.info`)**:
   - Easily skipped by direct SQL sessions, background batch jobs, or migration scripts.
   - Text logs can be deleted, rewritten, or truncated by anyone with server access.
   - No cryptographic proof of integrity; easily disputed in court or by regulators.
2. **Database Triggers**:
   - Heavy performance penalty on high-throughput OLTP databases.
   - Triggers can be disabled or bypassed (`ALTER TABLE ... DISABLE TRIGGER`).
   - Bloat the primary database storage and cannot sign batches with external cryptographic keys.
3. **Bulky CDC Platforms (Kafka + Debezium)**:
   - Introduce massive infrastructure complexity (Zookeeper/Kafka clusters, Connect workers, schema registries) for what should be a straightforward, rock-solid service.

---

## How `auditlogd` Solves It

`auditlogd` is a **standalone, zero-downtime Go daemon** that taps directly into the MySQL binary log (binlog) at the storage engine layer:

- **Zero App Refactoring**: Your application does not need SDK imports or ORM hooks. It simply writes a lightweight attribution context row (`_audit_context`) inside the same database transaction as the business change.
- **Captures Everything**: Captures changes from applications, admin scripts, direct SQL prompts, and migrations alike with `binlog_row_image=FULL`.
- **Tamper-Evident History**: Changes are batched, structured into RFC 6962 domain-separated Merkle trees, and only the root hash is signed using an Ed25519 private key.
- **Independent Verification**: A dispute can be settled by handing an external party a small Merkle proof. They verify it using only the published public key—no access to your private databases is required.
- **Cost-Effective 90-Day Retention**: Hot data is indexed in PostgreSQL for immediate search. After 90 days, a standalone tiering job moves full row data to immutable WORM archives (`0444` read-only) and purges Postgres storage.

---

## Architecture & Dataflow

```mermaid
flowchart TD
    subgraph Primary MySQL Database
        App[Application Write] -->|Data row + context row, same TX| MySQL[(MySQL Server)]
        DirectDBA[Direct DBA / Script] -->|Direct SQL, no context row| MySQL
        Config[(_audit_config table)] -.->|Live watched via CDC| Daemon
    end

    MySQL -->|Binlog stream: ROW format, FULL image| Daemon[auditlogd Daemon]

    subgraph Core Pipeline
        Daemon --> Attribution[Attribution Correlator]
        Attribution --> Snapshot[Snapshot Builder: Before/After Images + AES-256 PII Encryption]
        Snapshot --> Batch[Batch Buffer: 60s or 5,000 events]
        Batch --> Merkle[Merkle Tree Builder: RFC 6962]
        Merkle -->|Sign Root Only| Signer[Ed25519 Local Signer: keys.enc]
    end

    subgraph Storage & Sinks
        Merkle --> Postgres[(PostgreSQL Hot Store: 90 Days)]
        Signer --> WORM[(Local WORM Storage: checkpoints/)]
        Attribution -->|Unattributed Alert| AlertWebhook[Discord / Telegram Webhook]
    end

    subgraph Tiering & Access
        Postgres -->|Older than 90 Days| TieringJob[cmd/tiering Job]
        TieringJob -->|JSONL Full Batch| WORMArchive[(WORM Storage: archives/)]
        Postgres --> API[Internal REST API: :8080]
        WORM --> Portal[Web Verification Portal & Public Feed]
    end
```

---

## Real-World Dispute Scenarios

### Scenario 1: Customer Disputing a Balance Alteration

> **The Dispute**: A customer claims their account balance was reduced by $5,000 without authorization. Internal staff claim the customer initiated a wire transfer.

1. **The Investigation**: Support fetches the record history via the internal API:
   ```bash
   curl -H "Authorization: Bearer app-service-token" \
     "http://localhost:8080/audit/records?table=accounts&primary_key=ACC-90210"
   ```
2. **The Cryptographic Proof**: The daemon returns the record along with its batch Merkle proof:
   - **Committed At**: `2026-09-12T14:32:01.402Z`
   - **Actor**: `usr-customer-session-781` (attributed via context row)
   - **Before Image**: `{"balance": 15000.00}`
   - **After Image**: `{"balance": 10000.00}`
   - **Batch ID**: `b891a2...`
   - **Merkle Root**: `5e884898da28...`
   - **Signature**: `a4b9c8d7...`
3. **Verification**: Using [`cmd/verify`](cmd/verify/main.go) or the Web Portal, the customer or regulator recomputes the Merkle path. Because the computed root matches the signed root issued on `2026-09-12`, it is mathematically impossible for the company to have fabricated or altered this record after the fact.

---

### Scenario 2: Rogue DBA Direct SQL Injection

> **The Threat**: A database administrator logs directly into MySQL and runs `UPDATE users SET role = 'admin' WHERE id = 42;` bypassing all application logging.

1. **The Interception**: `auditlogd` reads the raw binlog `UPDATE` event.
2. **Attribution Correlator**: Inspects the transaction for a `_audit_context` write. None exists.
3. **Policy Evaluation**: The `users` table is configured in `_audit_config` with:
   - `unattributed_policy = 'alert'`
   - `severity_tier = 'critical'`
4. **Immediate Action**:
   - The record is saved with `actor_type = 'UNATTRIBUTED'`.
   - The alert dispatcher immediately posts a high-priority alert to Discord/Telegram:
     ```text
     🚨 @here [CRITICAL AUDIT ALERT] 🚨
     Table: users
     Trigger: unattributed_change
     Message: unattributed change on strict table users (severity: critical)
     Record ID: 1cf72c96-52cd-4eea-9268-62d9d55a2f25
     Transaction ID: mysql-bin.000004:1892
     Time: 2026-09-13T20:29:20Z
     ```
   - On-call engineers are alerted within seconds.

---

### Scenario 3: PII Privacy Protection (GDPR / HIPAA)

> **The Requirement**: Auditing must capture full row snapshots, but storing raw Social Security Numbers or credit card details in the audit table violates privacy regulations.

1. **Configuration**: In `_audit_config`, sensitive columns are flagged:
   ```sql
   UPDATE _audit_config SET encrypted_columns = JSON_ARRAY('ssn', 'tax_id') WHERE table_name = 'customers';
   ```
2. **On-the-Fly Encryption**: When `auditlogd` builds the snapshot, the AES-256-GCM `Encryptor` encrypts only those fields:
   ```json
   {
     "id": 101,
     "name": "Jane Doe",
     "ssn": "enc:v1:qK8w7e2J9L...",
     "tax_id": "enc:v1:mN3v4x..."
   }
   ```
3. **Access Gating**: Plain text queries to PostgreSQL show ciphertext. Only authenticated callers with authorized credentials requesting `?decrypt=true` on `/audit/records/{id}` receive decrypted values.

---

## Cryptographic Guarantees & Benchmarks

`auditlogd` employs RFC 6962 domain-separated SHA-256 hashing to prevent second-preimage attacks:
- **Leaf Node Hash**: `SHA-256(0x00 || CanonicalJSON(Record))`
- **Interior Node Hash**: `SHA-256(0x01 || LeftHash || RightHash)`

```
                 Merkle Root (Signed by Ed25519 Private Key)
                              /              \
                    Interior Node          Interior Node
                       /      \               /      \
                    Leaf 0   Leaf 1        Leaf 2   Leaf 3
                      |        |             |        |
                   Record 0 Record 1      Record 2 Record 3
```

### Performance Benchmarks (AMD Ryzen 5, 12 Threads)

| Benchmark Target | Operations / sec | Latency | Real-World Impact |
|---|---|---|---|
| **`BuildTree (1,000 leaves)`** | 2,436 ops/sec | **0.46 ms** | Negligible batch close overhead |
| **`BuildTree (5,000 leaves)`** | 871 ops/sec | **2.14 ms** | Closes 5,000-event batches in ~2ms |
| **`GenerateProof`** | **956,937 ops/sec** | **1.04 µs** | Instantaneous proof extraction |
| **`VerifyProof`** | **412,371 ops/sec** | **2.42 µs** | High-throughput dispute verification |

---

## Interactive Web Verification Portal

The API server embeds a zero-dependency, dark-themed **Public Verification Portal** accessible directly at `http://localhost:8080/verify`:

<p align="center">
  <img src="docs/images/merkle_dashboard.jpg" alt="Web Verification Portal" width="90%" />
</p>

Anyone can paste a dispute proof JSON to verify the cryptographic Merkle authentication path and digital signature in real-time.

---

## CLI Dispute Verification Tool

For air-gapped or automated verification without a browser, the repository provides [`cmd/verify`](cmd/verify/main.go):

<p align="center">
  <img src="docs/images/dispute_verification_cli.jpg" alt="CLI Dispute Verification" width="90%" />
</p>

```bash
# Verify against live database
./bin/verify -record "7f2a18c0-829d-4e92-bc10-91a82f349102" -passphrase "dev-passphrase"

# Offline zero-trust verification
./bin/verify -proof-file proof.json -pubkey "7e43a9f0b123d4e68e0992a5b172087d..."
```

---

## Quick Start Guide

### 1. Running with Docker Compose

The fastest way to spin up the entire architecture (MySQL 8.0 with binlog replication, PostgreSQL 16, `auditlogd`, and `apiserver`):

```bash
# 1. Clone repository
git clone https://github.com/9CASC0/logs-tracker.git
cd logs-tracker

# 2. Start the full stack
docker compose up -d

# 3. Check live daemon logs
docker compose logs -f auditlogd
```

### 2. Running Natively

```bash
# 1. Build all executables
make build

# 2. Generate local encrypted keyfile
./bin/keygen -action generate -keyfile ./keys.enc -passphrase "my-secret-pass" -version v1

# 3. Start auditlogd daemon
./bin/auditlogd \
  -mysql-host 127.0.0.1 -mysql-port 3306 -mysql-user root -mysql-pass root -mysql-db app \
  -postgres-url "postgres://postgres:postgres@localhost:5432/auditlog?sslmode=disable" \
  -worm-dir "./worm-storage" \
  -keyfile "./keys.enc" \
  -passphrase "my-secret-pass"

# 4. Start API server (in another terminal)
./bin/apiserver \
  -addr :8080 \
  -postgres-url "postgres://postgres:postgres@localhost:5432/auditlog?sslmode=disable" \
  -keyfile "./keys.enc" \
  -passphrase "my-secret-pass"
```

---

## REST API Reference

Full OpenAPI 3.0 specification available at [`docs/openapi.yaml`](docs/openapi.yaml).

| Method | Path | Auth / Permission | Description |
|---|---|---|---|
| `GET` | `/health` | Public | System liveness probe |
| `GET` | `/verify` | Public | Interactive Web Verification Portal |
| `GET` | `/public/verification/keys` | Public | Published Ed25519 public keys |
| `GET` | `/public/verification/roots` | Public | Published signed Merkle root feed |
| `POST`| `/public/verification/verify`| Public | Independent zero-trust proof verification |
| `GET` | `/audit/records` | Bearer (`record:read`) | Query history by table and primary key |
| `GET` | `/audit/records/{id}` | Bearer (`record:read`) | Full record detail (supports `?decrypt=true`) |
| `GET` | `/audit/records/{id}/verify`| Bearer (`verification:read`) | Recomputes proof and verifies record |
| `GET` | `/audit/batches/{id}` | Bearer (`batch:read`) | Batch root, signature, and binlog coords |
| `GET` | `/audit/config` | Bearer (`config:read`) | Active table audit policies |
| `POST`| `/audit/alerts/{id}/ack` | Bearer (`alert:acknowledge`) | Acknowledge security alert |

---

## Retention Tiering & WORM Archival

To keep PostgreSQL storage bounded, `cmd/tiering` runs as a scheduled job:

```bash
./bin/tiering -retention-days 90 -worm-dir ./worm-storage
```

<p align="center">
  <img src="docs/images/build_and_tests.jpg" alt="Build and Test Execution" width="90%" />
</p>

1. Identifies batches older than 90 days (`closed_at < NOW() - 90 days`).
2. Serializes full records into `archives/{batch_id}.jsonl`.
3. Sets file permissions to read-only (`0444`).
4. Logs entry in `audit_worm_index`.
5. Purges records from `audit_records` in PostgreSQL.
6. Updates `audit_batches.status = 'archived'`.

---

## Testing & Quality Verification

Run the comprehensive unit, fuzz, and primary seam integration test suite:

```bash
# Run tests with race detection
make test

# Run benchmarks
make bench

# Run linter
make lint
```

---

## Runbooks & Operations

- Operational triage, incident response, table onboarding, and disaster recovery: [`RUNBOOK.md`](RUNBOOK.md).
- Security policy, threat model, and cryptographic disclosure: [`SECURITY.md`](SECURITY.md).
- Architectural decision records (ADRs) and specification phase documents: [`specs/audit-logger/`](specs/audit-logger/).

---

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.
