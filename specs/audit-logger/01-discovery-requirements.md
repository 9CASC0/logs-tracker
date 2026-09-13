# Phase 0 — Discovery & Requirements

**Goal:** Confirm exactly what the audit logger must do, and formally log
the decisions already reached, before treating anything as locked.
**Estimated Duration:** 2–3 days (mostly reconciliation — most decisions
below were already reached during design interview)
**Depends On:** none
**Primary Owner:** You (solo project)

## Objectives

- Record the decisions already made so later phases have a single source of
  truth to build against.
- Surface the handful of questions that are genuinely still open.
- Define success metrics so later phases have a target to hit.

## Decisions Already Reached (locked)

| # | Decision Area | Resolution |
|---|---|---|
| 1 | Interception mechanism | CDC via MySQL binlog, not app hooks/triggers/API middleware |
| 2 | Database engine | MySQL only for v1 |
| 3 | CDC tooling | Lightweight binlog reader (`go-mysql`), not Debezium/Kafka |
| 4 | Implementation language | Go |
| 5 | Attribution ("who") | Same-transaction context row, not session vars or app SDK calls |
| 6 | Correlation mechanism | Binlog transaction-boundary grouping (BEGIN/XID/COMMIT) |
| 7 | Storage destination | Hybrid: Postgres (hot) + WORM object storage (cold, tamper-evident) |
| 8 | Queryable store | PostgreSQL |
| 9 | Change granularity | Full before/after row snapshots, not field-level diffs only |
| 10 | Before-image capture | `binlog_row_image=FULL` on MySQL |
| 11 | Unattributed-change handling | Configurable per table (`_audit_config`) |
| 12 | Audit scope mechanism | Annotation-driven via config table, not naming convention/comments |
| 13 | Config table lifecycle | `_audit_config` maintained via migrations |
| 14 | Tamper evidence | Per-batch Merkle tree; only the root is signed |
| 15 | Key management | Local encrypted keyfile (Ed25519 signing + AES-256-GCM PII), OS keychain holds the unlock passphrase |
| 16 | Batch cadence | Hybrid: time OR count threshold, whichever first |
| 17 | Binlog position checkpointing | Committed transactionally in Postgres with the batch |
| 18 | Daemon HA | Single instance + process-supervisor restart (v1) |
| 19 | PII handling | Field-level encryption at rest via a local AES-256-GCM key (same keyfile as the signing key) |
| 20 | Retention/archival | Tiered move of full data to WORM after retention window, not just proofs |
| 21 | Retention window | 90 days hot in Postgres |
| 22 | Access pattern | Internal API (in-app views) + direct SQL (auditors/compliance) |
| 23 | Alerting | Multi-tier via one Discord/Telegram webhook: plain message (normal), @mention plus distinct marker (critical) |
| 24 | Schema evolution | Hot-reload on DDL + per-record schema version tagging |
| 25 | Config reload | Live, via the daemon watching `_audit_config`'s own binlog events |
| 26 | Bootstrap/backfill | One-time snapshot on table registration, Merkle-anchored |
| 27 | Daemon health observability | Explicitly deferred for v1 |
| 28 | DELETE/soft-delete representation | Explicit event-type tagging; soft-deletes are `UPDATE`s distinguished by changed columns |
| 29 | Verification exposure | Public: published public key + signed roots, independently verifiable |
| 30 | WORM storage provider | Local write-once directory (`checkpoints/` + `archives/`, write-then-chmod-read-only) — no cloud account needed at personal-project scale; `ArchiveStore` keeps a cloud provider swappable later |
| 31 | Batch thresholds | Locked v1 default: 60 seconds OR 5,000 events, whichever first; remains runtime-tunable, revisit once real MySQL write-volume data exists |
| 32 | Testing seam boundaries | Four confirmed seams: ingestion pipeline (`cmd/daemon`), retention tiering (`cmd/tiering`, now its own binary), verification (library-level), access API (HTTP-layer) |
| 33 | Issue tracker / triage labels | None connected; the versioned markdown docs in this repo (this phase plan plus `../global-audit-logger.md`) are the source of truth until a tracker is provided |
| 34 | Deployment ceremony (personal-project right-sizing) | Keep the full three-tier dev/staging/prod + CI/CD approval-gate setup, as a deliberate choice to practice proper deployment discipline even at personal scale |
| 35 | Rollout strategy (personal-project right-sizing) | Keep a staged, table-by-table rollout, reframed as a personal sanity check rather than formal risk management (no real user base to protect) |
| 36 | Testing depth (personal-project right-sizing) | Keep chaos/resilience and load testing (scaled to actual personal write volume); replace the formal security/compliance sign-off session with a solo self-review walkthrough |

## Open Questions (not yet resolved — confirm before the relevant phase starts)

Both previously-open questions are now resolved by context: this is a
personal project with no real large data volume.

- **Regulatory framework**: none applies. No jurisdiction-specific
  retention override is needed; the 90-day hot / archive-after policy
  stands as-is.
- **Expected write volume**: small/personal scale. The 60s-or-5,000-event
  batch default (decision 31) will realistically almost always close on
  the time threshold, not the count threshold — that's fine, and not worth
  further tuning unless usage patterns change materially. Load testing
  (Phase 10) should be scaled to this reality, not to enterprise peak
  volume.

No open questions remain that block any phase from starting.

## Functional Requirements Checklist

| # | Requirement | In/Out/Later |
|---|---|---|
| 1 | MySQL binlog-based CDC capture | In |
| 2 | Transaction-based attribution via context row | In |
| 3 | Per-table configurable unattributed-change policy | In |
| 4 | `_audit_config`-driven audit scope, migration-managed | In |
| 5 | Full before/after row snapshots | In |
| 6 | Explicit INSERT/UPDATE/DELETE event tagging | In |
| 7 | PII field encryption at rest (local AES-256-GCM) | In |
| 8 | Batched Merkle tree construction | In |
| 9 | Locally-signed batch roots | In |
| 10 | WORM checkpoint archival | In |
| 11 | Public key + signed root publication | In |
| 12 | 90-day Postgres hot retention | In |
| 13 | Tiered archival of full data to WORM after retention window | In |
| 14 | Bootstrap snapshot for newly-registered tables | In |
| 15 | Schema hot-reload + version tagging | In |
| 16 | Transactional binlog checkpointing | In |
| 17 | Internal read API | In |
| 18 | Direct read-only SQL access for auditors | In |
| 19 | Tiered alerting (Discord/Telegram webhook) | In |
| 20 | Verification routine (Merkle path + signature check) | In |
| 21 | Daemon HA / leader election | Later |
| 22 | Replication-lag / daemon health monitoring | Later |
| 23 | Multi-database-engine support (Postgres/Mongo sources) | Later |
| 24 | Sharded/multi-instance MySQL support | Later |
| 25 | Automatic PII discovery/classification | Later |
| 26 | Regulatory retention overrides | Later |

## Success Metrics (confirm numeric targets with security/compliance stakeholders)

- % of audited changes with a resolved actor (vs. `SYSTEM`/`UNATTRIBUTED`)
- Time from batch close to signed-and-archived checkpoint (target: seconds,
  not minutes)
- Time to answer a dispute (pull proof, verify signature, confirm Merkle
  path) — target: minutes, not hours
- Daemon crash-to-resume time and confirmation of zero gap/duplication
- Retention tiering job success rate (batches tiered on schedule vs. missed)
- False-positive rate on unattributed-change alerts (tune per-table policy
  if too noisy)
- Daemon uptime (informal target given no HA in v1 — define an acceptable
  restart frequency/downtime budget)

## Deliverables

- This decisions log, reviewed and agreed.
- Open-questions list with owners assigned to resolve each before its
  dependent phase starts.
- Success metrics with numeric targets filled in.

## Acceptance Criteria / Definition of Done

- [ ] All 29 locked decisions above reviewed and confirmed still accurate.
- [ ] Every open question has an owner and a "needed by" phase.
- [ ] Success metrics have numeric targets, not just descriptions.

## Notes

Unlike a from-scratch discovery phase, most of this phase already happened
via a structured design interview. Treat this file as the durable record of
that interview's outcome — update it if a later phase legitimately revisits
a decision, rather than letting the decision drift undocumented.
