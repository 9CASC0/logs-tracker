# Phase 3 — Attribution, Key Management & Access Control

**Goal:** Implement the attribution mechanism, generate the local signing/
encryption keyfile, and define who/what can read or write which parts of
the system.
**Estimated Duration:** 4–5 days
**Depends On:** Phase 2
**Primary Owner:** You (solo project)

## Objectives

- Implement transaction-based attribution correlation.
- Generate the local encrypted keyfile (signing + encryption keys).
- Define Postgres roles and internal API permissions.
- Add session/security basics appropriate for a system that itself
  protects sensitive data.

## Attribution Mechanism (recap + implementation notes)

- Application code writes a **context row** (actor/user identity, request
  id) in the **same transaction** as the data change it's attributing.
- The daemon groups binlog row events by transaction boundary
  (`BEGIN` → row events → `XID`/`COMMIT`) and matches the context-row
  insert against the data-row change(s) in that same transaction.
- If no context row is found for a transaction touching an audited table,
  the daemon consults `_audit_config.unattributed_policy` for that table:
  - `tolerate` → record with `actor_type = SYSTEM`, no alert.
  - `alert` → record with `actor_type = UNATTRIBUTED`, plus an alert per
    `_audit_config.severity_tier` (Phase 7).

## Local Key Provisioning

| Item | Detail |
|---|---|
| Storage | One encrypted local keyfile, containing both keys below, protected by a passphrase |
| Signing key | Asymmetric, Ed25519, used only to sign Merkle roots |
| Encryption key | AES-256-GCM, used only to encrypt configured PII columns before persistence |
| Unlock mechanism | Passphrase held in the OS keychain (e.g. via `zalando/go-keyring` or platform equivalent); the daemon reads it once at startup to decrypt the keyfile in memory, then never touches the passphrase again |
| Access boundary: daemon | Can sign and encrypt/decrypt in-process; the raw private key material never touches disk unencrypted or crosses a network boundary |
| Access boundary: verification consumers | Only need the **public** key (published openly, Phase 7) to verify a signature — they never need keyfile access at all |
| Access boundary: decrypt-for-read | The API server process (Phase 7) holds its own copy of the unlock passphrase (separately in the OS keychain of whatever host it runs on), independent from the daemon's copy |
| Key rotation | Manual for v1: generate a new keypair, keep the old public key around (versioned) so historical signatures remain verifiable. No automatic rotation cadence needed at this scale, but the `keyVersion` field (Phase 2 schema) means rotation won't break old proofs if you ever do it |

## Postgres Roles

| Role | Access |
|---|---|
| `auditlogd_writer` | INSERT-only on `audit_batches`/`audit_records`/`audit_worm_index`; no UPDATE/DELETE except the tiering job's documented purge path |
| `auditlogd_tiering` | The one role allowed to DELETE from `audit_records` (and only via the retention job, Phase 6), and INSERT into `audit_worm_index` |
| `auditlogd_api` | SELECT-only, used by the internal read API service |
| `auditor_readonly` | SELECT-only, granted directly to compliance/security/audit personnel for ad hoc SQL access |

## Internal API Permission Model

Simple, explicit **action → allowed caller** map (avoid a generic policy
engine for v1):

| Action | Allowed Callers |
|---|---|
| `record:read` (single record + history) | Internal API service, any authenticated app service acting on behalf of a permitted user |
| `record:search` | Same as above, scoped to records the caller's user is allowed to see (mirrors the underlying application's own authorization for that record) |
| `batch:read` | You (the operator/admin role) |
| `verification:read` (Merkle path + signature check for a record) | Any authenticated caller — this is intentionally low-friction since it's a read-only proof, and needs no key access at all (public key only) |
| `config:read` (view `_audit_config`) | You (the operator/admin role) |
| `alert:acknowledge` | You (the operator/admin role) |

In a solo project there's really one human behind all of the
"compliance/security/admin" roles above — the table is kept explicit
anyway so the permission guard has real, testable rules, and so it's
ready to differentiate roles again if this ever isn't solo.

Implemented as a middleware/dependency similar in spirit to a typical
`require_permission(action)` guard, checked on every route.

## Security Hardening for This Phase

- [ ] Keyfile unlock passphrase never committed to source or written to a
      plain config file; lives only in the OS keychain.
- [ ] The encrypted keyfile has restrictive file permissions (0600),
      confirmed by testing that another local user account cannot read it.
- [ ] Postgres roles above created with least-privilege grants, verified by
      a test that `auditlogd_api` cannot INSERT/UPDATE/DELETE.
- [ ] Connections between daemon and Postgres use TLS in staging/prod.

## Deliverables

- Attribution correlation logic implemented and unit-tested against
  synthetic transaction sequences (attributed, unattributed-tolerated,
  unattributed-alerting).
- Local encrypted keyfile generated (signing + PII encryption keys), with
  its unlock passphrase stored in the OS keychain and the generation
  process documented/scripted so it's repeatable per environment.
- Postgres roles created via migration, with grants matching the table
  above.
- Internal API permission map implemented as a reusable guard.

## Acceptance Criteria / Definition of Done

- [ ] A transaction with a context row produces a record with
      `actor_type = USER` and the correct `actor_user_id`.
- [ ] A transaction without a context row on a `tolerate` table produces
      `actor_type = SYSTEM` with no alert.
- [ ] A transaction without a context row on an `alert` table produces
      `actor_type = UNATTRIBUTED` and triggers the correct severity alert
      (verified once Phase 7 alerting exists; stub the alert call for now).
- [ ] `auditor_readonly` can `SELECT` but not write, verified by test.
- [ ] Only the intended local user account/process can read the encrypted
      keyfile or its unlock passphrase, verified by test.
