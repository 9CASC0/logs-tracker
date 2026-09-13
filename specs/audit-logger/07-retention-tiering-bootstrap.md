# Phase 6 — Retention Tiering & Bootstrap Snapshotting

**Goal:** Keep the hot store bounded in size over time, and give
newly-registered tables a trustworthy starting point instead of a blank
slate.
**Estimated Duration:** 6 days
**Depends On:** Phase 5
**Primary Owner:** You (solo project)

## Part A — Retention Tiering

### Functional Requirements

- Identify batches whose `closed_at` is older than the 90-day retention
  window.
- Move the **full** batch data (`audit_records` rows, not just the signed
  root) into a WORM archive object.
- Purge the tiered records from `audit_records` in Postgres, recording the
  move in `audit_worm_index`.
- Leave the batch's signed checkpoint (root + signature) permanently
  referenced and retrievable regardless of tiering state — tiering must
  never be able to orphan a checkpoint.

### Backend Components

- **Tiering Job** — packaged as its own binary, `cmd/tiering` (Phase 1),
  invoked on a schedule (e.g. a daily Kubernetes CronJob or equivalent),
  not as a mode of the long-running daemon. It selects candidate batches
  via `audit_batches(closed_at, status)`, and for each: writes the archive
  object to the local write-once archive directory (per Phase 2), records
  `audit_worm_index`, deletes the `audit_records` rows, and updates
  `audit_batches.status = archived`.
- Runs under the dedicated `auditlogd_tiering` Postgres role (Phase 3) —
  the only role permitted to delete audit records.
- Being a separate binary (rather than a flag on `auditlogd`) is also what
  makes retention tiering its own testing seam in Phase 10: it can be run
  and verified in complete isolation from live ingestion.

### Business Rules

- Tiering is idempotent: re-running the job on an already-tiered batch is a
  no-op (checked via `audit_worm_index`/`audit_batches.status` before
  acting).
- A batch is never partially tiered — the archive write, `audit_worm_index`
  insert, and `audit_records` purge happen as one logical unit; a crash
  mid-operation must be safely retryable, not leave orphaned partial state.
- Retrieval of a tiered record's full data is slower (fetch from WORM) but
  never impossible — "tiered" must not mean "lost."

## Part B — Bootstrap Snapshotting

### Functional Requirements

- When a table is newly marked `enabled = true` (with `bootstrap_required =
  true`) in `_audit_config`, take a one-time consistent snapshot of its
  existing rows.
- Tag every bootstrap record with `actor_type = SYSTEM`, `is_bootstrap =
  true` on its batch.
- Run the bootstrap batch through the **same** Merkle-build-and-sign
  pipeline as live batches (Phase 5) before switching the table over to
  live binlog capture — no unsigned starting point for any table's
  history.

### Backend Components

- **Bootstrap Runner** — triggered by the config watcher (Phase 4) noticing
  a table needs bootstrapping; performs a consistent read (e.g. a
  `REPEATABLE READ`/consistent-snapshot transaction, or a read pinned to a
  specific binlog position with reconciliation against any concurrent
  writes) of the table's current rows, and feeds them into the batch
  pipeline as one or more `is_bootstrap = true` batches.
- Updates `_audit_config.bootstrap_status` (`not_started` → `in_progress` →
  `complete`) so the daemon knows when it's safe to rely on live capture
  alone for that table.

### Business Rules

- Live binlog capture for a table being bootstrapped must not be dropped
  during the bootstrap read — any writes happening concurrently with the
  snapshot must end up in either the bootstrap batch or the live stream,
  never both and never neither (reconcile via the binlog position the
  snapshot read was pinned to).
- Bootstrap is a one-time operation per table; re-enabling a previously
  disabled table does not re-bootstrap unless `bootstrap_required` is
  explicitly reset.

## Tasks

- [ ] Implement the retention tiering job with idempotent, atomic-per-batch
      tiering.
- [ ] Implement the bootstrap runner with consistent-snapshot reads.
- [ ] Wire bootstrap batches through the Phase 5 Merkle/signing pipeline.
- [ ] Implement `bootstrap_status` transitions in `_audit_config`.
- [ ] Test the concurrent-write-during-bootstrap edge case explicitly (no
      dropped or duplicated rows).

## Deliverables

- Scheduled tiering job, runnable on demand for testing and on a schedule
  in production.
- Bootstrap flow that takes a table from "newly registered" to "fully
  audited with a signed starting snapshot" with no manual data entry.

## Acceptance Criteria / Definition of Done

- [ ] Batches older than 90 days are tiered on schedule; their full data is
      retrievable from WORM after Postgres purge.
- [ ] A signed checkpoint remains retrievable and verifiable for a tiered
      batch exactly as it was before tiering.
- [ ] Registering a new table produces a Merkle-anchored bootstrap batch
      covering its existing rows before any live capture is trusted for
      that table.
- [ ] A write that happens *during* the bootstrap snapshot is captured
      exactly once (in bootstrap or live capture, not both, not neither).
