# Phase 1 — System Architecture & Tech Stack Design

**Goal:** Lock the technical architecture, module boundaries, and
conventions before writing pipeline code.
**Estimated Duration:** 3–4 days
**Depends On:** Phase 0
**Primary Owner:** You (solo project)

## Objectives

- Decide the daemon's internal module boundaries.
- Define API, error, and logging conventions.
- Confirm the migration tool and batching strategy.
- Establish a folder structure so work can be split without collisions.

## Recommended Decision: Single Daemon, Internally Modular

Build `auditlogd` as **one deployable Go binary** with clearly separated
internal packages, rather than multiple microservices, because:

- There is exactly one daemon instance in v1 (no HA) — a monolith-per-
  process is simplest to operate and reason about.
- The pipeline stages (attribution → snapshot → batch → Merkle → sign →
  persist) are sequential and tightly coupled by design (see Phase 0
  decisions) — splitting them into separate services would add network
  hops with no benefit at this scale.
- The access API (Phase 7) is the one component that could reasonably be
  its own deployable later if load justifies it; keep it as a separate
  internal package now so that split is easy if needed.

Suggested module layout:

```
auditlogd/
  cmd/
    daemon/            # binlog capture + pipeline entrypoint
    apiserver/         # internal read API entrypoint (separate binary, shares packages)
    tiering/           # retention tiering job entrypoint (separate binary; run on a schedule/CronJob)
  internal/
    binlog/            # go-mysql client, transaction boundary grouping
    config/            # _audit_config loading + live-watch
    attribution/       # context-row correlation
    snapshot/          # before/after image capture, event tagging, PII encryption hook
    batch/             # batch buffering (time/count thresholds)
    merkle/            # Merkle tree construction + proof generation, verification service
    signing/           # Signer/Encryptor interfaces + local encrypted-keyfile implementation
    archive/           # ArchiveStore interface + local write-once-directory implementation
    store/             # Postgres repositories (records, batches, config)
    alerting/          # Discord/Telegram webhook sink
    api/               # internal read API handlers
  migrations/          # golang-migrate SQL migrations
  deploy/              # Dockerfiles, compose files

Splitting `tiering` into its own binary (rather than a mode flag on
`daemon`) makes the retention job a genuinely separate deployable —
important for Phase 10's testing seam boundaries and for Phase 11's
deployment/scheduling story (it runs as a scheduled job, not a long-lived
process).
```

## Batching Strategy

- Batches close on a **hybrid** time-or-count threshold (Phase 0, decision
  16). Locked v1 default: **60 seconds OR 5,000 events**, whichever comes
  first.
- Thresholds are runtime-configurable (env var or config file), not
  hardcoded, so they can be tuned without a rebuild once real write-volume
  data is available (Phase 0's one remaining open question on this topic).

## Storage Strategy

- **Postgres** for the hot store; introduce **`golang-migrate`** from day
  one so schema evolves via tracked, reviewable migrations rather than
  ad hoc `CREATE TABLE` calls.
- **WORM object storage**: a local write-once directory, behind an
  internal `ArchiveStore` interface, with `checkpoints/` and `archives/`
  subpaths. Objects are written once, then `chmod`'d read-only (0444) —
  this is deliberately the same implementation in every environment (dev,
  staging, prod each just point at a different path), with no cloud
  account required. This is documented as *best-effort* immutability: it
  protects against accidental overwrite and casual tampering, not against
  a determined local root user, unlike cloud Object Lock. That trade-off
  is accepted given the personal-project threat model (Phase 9 covers this
  explicitly).

## API Conventions (Internal Read API, Phase 7)

- Base path: `/audit/...`.
- All endpoints require an authenticated internal service token or mTLS
  client identity; no unauthenticated internal endpoints.
- Response envelope: `{ "data": ..., "meta": {...} }` for lists (paging),
  plain object for single resources.
- Timestamps: ISO 8601 UTC everywhere.
- Errors: consistent `{ "error": { "code": ..., "message": ... } }` body
  with standard HTTP status codes (400 validation, 403 authz, 404 missing,
  409 conflict).

## Logging & Observability Conventions

- Structured (JSON) logs from day one; every log line tied to a batch id
  and/or transaction id where applicable.
- Never log full before/after row payloads at info level (may contain PII
  even before encryption is applied) — log row identifiers and counts only;
  full payloads at debug level in non-prod only.

## Non-Functional Requirements

| Concern | Decision |
|---|---|
| Availability | Single instance, supervisor-restarted; brief gaps on restart accepted (Phase 0) |
| Checkpoint latency | Signed batch available within one batch interval (default ≤60s) of the underlying change |
| Data retention | 90 days hot, tiered thereafter (Phase 0) |
| Backups | Nightly Postgres backups + point-in-time recovery once in staging/prod |
| Config safety | `_audit_config` changes are migration-reviewed, not ad hoc runtime writes |

## Deliverables

- Architecture doc (this file) reviewed and agreed.
- Module/folder structure created (empty package scaffolds committed).
- Decision recorded: `golang-migrate` for schema migrations.
- Decision recorded: batch thresholds locked at 60 seconds OR 5,000
  events (Phase 0, decision 31), configurable at runtime.

## Acceptance Criteria / Definition of Done

- [ ] Module boundaries documented and matched by actual folders in the
      repo.
- [ ] API path/response/error conventions written down and followed from
      Phase 7 onward.
- [ ] `golang-migrate` initialized against a fresh Postgres instance with a
      baseline migration.
- [ ] Batch threshold defaults set as configuration, not hardcoded
      constants.
