# Phase 10 — Testing & QA

**Goal:** Verify the whole system end-to-end before deployment, using real
ephemeral dependencies rather than mocked wire protocols.
**Estimated Duration:** 7 days (ongoing in parallel with earlier phases;
this phase is where it's consolidated and reviewed)
**Depends On:** All prior phases functionally complete
**Primary Owner:** You (solo project)

## Test Strategy Layers

### 1. Unit Tests (`go test`)
- Merkle tree construction and path extraction — correctness across tree
  sizes including edge cases (1 record, odd counts).
- Attribution correlation logic — attributed/tolerated-unattributed/
  alerting-unattributed cases.
- Batch close-trigger logic — time threshold, count threshold, whichever
  first.
- Permission guard — action x caller matrix, including negative cases.

### 2. Integration Tests (`testcontainers-go`)

Real ephemeral MySQL + Postgres, plus the real local-keyfile signer/
encryptor and the real local write-once archive directory (no containers
needed for either, since both are just local filesystem operations). Four
confirmed, distinct seams — this boundary is locked, not a proposal:

1. **Ingestion pipeline (primary seam, `cmd/daemon`)** — execute real
   transactions against MySQL (context row + data row together,
   unattributed changes, DDL, `_audit_config` changes) and assert against
   the daemon's actual output: Postgres rows, signed Merkle root, WORM
   checkpoint object, binlog checkpoint. Pipeline stages are not tested in
   isolation from each other.
2. **Retention tiering (`cmd/tiering`)** — run the tiering binary directly
   against seeded old batches; assert WORM contents and Postgres purge.
   Tested completely independently of the daemon, since it's a separate
   binary invoked on its own schedule.
3. **Verification (library-level)** — call the verification service
   directly with genuine and deliberately-tampered records (modified
   value, substituted signature); assert success/failure accordingly. No
   HTTP layer involved in this seam.
4. **Access API (`cmd/apiserver`, HTTP layer)** — assert
   filtering/pagination/RBAC enforcement against seeded data over real
   HTTP calls, including a rejected unauthorized call, and that the public
   verification feed serves the right keys/roots without internal auth.

### 3. Chaos / Resilience Tests
- Kill the daemon mid-batch (before close) and restart — assert no gap, no
  duplicate records, resumption exactly at the last committed checkpoint.
- Kill the daemon mid-bootstrap-snapshot and restart — assert the
  concurrent-write reconciliation (Phase 6) holds: no dropped/duplicated
  rows.
- Simulate a local signing failure (e.g., keyfile temporarily unreadable
  or wrong passphrase) — assert the batch is retried, not silently dropped
  or persisted unsigned.

### 4. Non-Functional Testing
- **Load test**: sustained write volume against MySQL (e.g. representative
  of Phase 0's expected transaction rate) — confirm batch thresholds hold
  up and signing/WORM-write latency stays within target.
- **Backup/restore test**: take a Postgres backup, restore to a fresh
  instance, confirm `audit_batches`/`audit_records` integrity and that
  in-flight verification still works against the restored data.

## Solo Self-Review (in place of a formal sign-off session)

No external stakeholder is needed for a personal project, but the review
itself is still worth doing deliberately rather than skipping it:

- [ ] Walk through a real dispute scenario end-to-end, yourself: pull a
      record, verify it, and confirm out loud (or in a note) that the
      guarantee actually holds the way you think it does.
- [ ] Walk through the unattributed-change alerting path for a
      critical-tier table and confirm the Discord/Telegram message actually
      arrives and looks distinct from a normal one.
- [ ] Note any issues found; fix blockers before rollout (Phase 12), and
      explicitly decide (don't just forget) what to defer.

## Tasks

- [ ] Set up `testcontainers-go` fixtures (MySQL, Postgres) plus a
      temp-directory-backed local signer/encryptor and archive store for
      tests — no containers needed for either.
- [ ] Write the unit tests listed above.
- [ ] Write the integration tests for the primary seam and the three
      secondary seams (tiering, verification, access API).
- [ ] Write the chaos/resilience tests.
- [ ] Run load and backup/restore tests and document results.
- [ ] Conduct the security/compliance sign-off session.

## Deliverables

- Full test suite runnable via a single command (e.g. `go test ./...` plus
  a tagged integration-test target).
- Load/chaos/backup-restore test report.
- Security/compliance sign-off document.

## Acceptance Criteria / Definition of Done

- [ ] All unit/integration tests pass in CI.
- [ ] Chaos tests confirm zero gap/duplication across a daemon
      kill-and-restart, including mid-bootstrap.
- [ ] Load test shows batch signing/archival latency within target under
      expected peak write volume (per Phase 0's expected volume).
- [ ] No open blocker/major issues from the security/compliance sign-off
      session.
