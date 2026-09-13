# Phase 7 — Access API, Verification Surface & Alerting

**Goal:** Make the audit trail actually usable by the people who need it —
in-app history views, ad hoc auditor queries, public verification, and
timely alerts.
**Estimated Duration:** 6 days
**Depends On:** Phase 5 (data shape), can start scaffolding once Phase 4 is
stable
**Primary Owner:** You (solo project)

## Functional Requirements

- Serve a record's change history to authorized callers via an internal
  API.
- Allow compliance/security/auditor personnel direct read-only SQL access.
- Publish the signing public key and historical signed Merkle roots
  somewhere externally verifiable.
- Fire a Discord/Telegram notification for unattributed changes on
  `normal`-severity strict tables, and a distinct @mention-marked one for
  `critical`-severity tables.

## Backend Components

### `internal/api` — Internal Read API

- `GET /audit/records?table=&primary_key=` — history for a specific record.
- `GET /audit/records/{id}` — single record detail.
- `GET /audit/records/{id}/verify` — runs the Phase 5 verification service,
  returns valid/invalid + proof metadata.
- `GET /audit/batches/{id}` — batch metadata (root, signature, time range,
  status).
- `GET /audit/config` — read `_audit_config` (compliance/security/admin
  only).
- `POST /audit/alerts/{id}/ack` — acknowledge an alert (on-call/security
  only).

### Direct SQL Access

- `auditor_readonly` Postgres role (Phase 3) granted to named
  compliance/security/audit personnel or a BI tool connection.

### Public Verification Feed

- A minimal, publicly reachable surface (separate from the internal API's
  auth boundary) exposing:
  - The current and historical local public signing key(s) (versioned via
    `key_version`, so old signatures stay verifiable even if the key is
    ever rotated).
  - The full history of signed Merkle roots + batch time ranges (not the
    underlying record data — just enough for an independent party to
    verify a proof presented to them separately).

### Alerting (`internal/alerting`)

All alerts go to a single Discord/Telegram webhook; severity changes
presentation, not the destination:

| Trigger | Severity | Presentation |
|---|---|---|
| Unattributed change on a `normal`-tier `alert`-policy table | medium | Plain message |
| Unattributed change on a `critical`-tier `alert`-policy table | high | @mention + distinct marker (e.g. a leading emoji/prefix) |
| Retention tiering job failure | high | @mention + distinct marker |
| Bootstrap run failure | medium | Plain message |

- Rate-limit repeated identical alerts (e.g. many unattributed changes from
  the same known migration script in a short window) rather than firing one
  page per row — fire once, escalate if the underlying condition persists
  past a threshold.

## Tasks

- [ ] Implement the internal API endpoints above with the Phase 3
      permission guards.
- [ ] Grant and test `auditor_readonly` access end-to-end.
- [ ] Implement the public verification feed (public keys + signed roots),
      decoupled from the internal API's auth.
- [ ] Implement the alerting sink (Discord or Telegram webhook) behind the
      `AlertSink` interface (Phase 8's adapter pattern).
- [ ] Implement alert rate-limiting/deduplication.

## Deliverables

- Working `/audit/*` internal API, documented (OpenAPI or equivalent).
- `auditor_readonly` role granted and verified for at least one real
  compliance/security user.
- Public verification feed reachable without internal authentication.
- End-to-end alert delivery verified for the Discord/Telegram webhook,
  including that critical alerts are visibly distinct from normal ones.

## Acceptance Criteria / Definition of Done

- [ ] A caller with appropriate permissions can fetch a record's full
      history and verify any individual entry via the API.
- [ ] An unauthorized caller is rejected with `403`, not a silent empty
      result or `500`.
- [ ] A deliberately unattributed test change on a critical-tier table
      pages on-call within the alerting pipeline's expected latency.
- [ ] An external party, given only the published public key and a
      signature/proof handed to them separately, can verify a record
      without any internal system access.
