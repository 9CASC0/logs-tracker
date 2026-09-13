# Phase 11 — Deployment & DevOps

**Goal:** Get the daemon and its dependencies running reliably in staging
and production, with a repeatable deployment process.
**Estimated Duration:** 4 days
**Depends On:** Phase 9 (security), Phase 10 (tests passing)
**Primary Owner:** You (solo project)

## Environments

| Env | Purpose | Postgres | WORM (local directory) | Signing/encryption keys |
|---|---|---|---|---|
| Local dev | Individual development | Local container | `./worm-dev/` on local disk | Dev keyfile + dev-only OS keychain entry |
| Staging | Pre-prod validation | Small managed instance | Separate path/volume from prod, e.g. `./worm-staging/` | Separate staging keyfile/passphrase from prod |
| Production | Live auditing of real MySQL traffic | Sized for real volume + backups | Dedicated path/volume, e.g. `./worm-prod/`, ideally on separate physical/logical storage from the OS disk | Production keyfile/passphrase, never shared with dev/staging |

## Containerization

- `Dockerfile` for `auditlogd` (the ingestion/batching/signing daemon).
- `Dockerfile` for the internal API server (separate binary, Phase 1's
  module layout).
- `Dockerfile` for the retention tiering job (separate binary, run as a
  scheduled task/cron, not a long-lived service).
- `docker-compose.yml` for local/staging parity: `mysql`, `postgres`,
  `auditlogd`, `apiserver`, and an on-demand `tiering` run. The local
  write-once archive directory and encrypted keyfile are bind-mounted
  volumes, not separate services — no `vault` or `minio` containers needed
  at any tier.

## CI/CD Pipeline (suggested stages)

1. **Lint** — `go vet` / `golangci-lint`.
2. **Test** — unit + `testcontainers-go` integration tests.
3. **Build** — Docker images for `auditlogd` and the API server.
4. **Chaos/Load** (staging-gated, not every PR) — kill-and-restart and load
   scenarios from Phase 10 run against a disposable staging-like stack.
5. **Deploy staging** — auto-deploy on merge to `main`/`develop`.
6. **Deploy production** — manual approval gate, deploy on tag/release.

## Database Operations

- `golang-migrate` migrations run as an explicit deploy step before the new
  daemon version starts consuming the binlog.
- Automated nightly Postgres backups in staging/prod; restore procedure
  tested (Phase 10) and documented.
- Connection pooling sized for the daemon's write load plus the API
  server's read load.

## Configuration & Secrets

- Environment variables/secrets injected via the deployment platform's
  secret store, not baked into images.
- Signing/encryption keyfiles and their unlock passphrases are separate
  per environment; rotated (new keypair generated, old public key kept for
  verifying old signatures) on any suspected exposure.

## Observability

- Structured logging (batch id, transaction id where relevant) — scrubbed
  of PII per Phase 9.
- `GET /health` endpoint on both `auditlogd` and the API server for
  orchestrator probes.
- Error tracking wired for both binaries.
- Dashboards/alerts on: batch signing latency, tiering job success/failure,
  Postgres connection pool saturation, API error rate.
- Explicitly **not** included yet: binlog replication-lag monitoring
  (Phase 0, deferred) — flagged here again as the natural place to add it
  later, since this phase is where the observability stack actually lives.

## Scaling Considerations (document now, implement when needed)

- Single `auditlogd` instance in v1 (Phase 0/1 decision) — no shared-state
  requirement to solve yet.
- If the API server needs to scale horizontally, it's read-only and
  stateless, so this is a non-issue — multiple replicas behind a load
  balancer work immediately.
- If MySQL write volume outgrows one daemon instance's throughput, revisit
  the `ChangeSource` adapter boundary (Phase 8) before considering
  sharding the daemon itself.

## Tasks

- [ ] Write `auditlogd` and API server Dockerfiles.
- [ ] Write `docker-compose.yml` for local/staging parity.
- [ ] Set up CI pipeline matching the stages above.
- [ ] Configure staging environment; deploy and smoke-test.
- [ ] Configure production environment (sizing, backups, TLS, secrets).
- [ ] Add health check endpoints + wire to orchestrator.
- [ ] Wire structured logging + error tracking.
- [ ] Document the deploy/rollback procedure in a `RUNBOOK.md`.

## Deliverables

- Working Docker images + compose file.
- CI pipeline green on a real PR.
- Staging environment live and matching production configuration.
- `RUNBOOK.md` covering deploy, rollback, and incident response basics.

## Acceptance Criteria / Definition of Done

- [ ] A fresh clone can bring up the full local stack via
      `docker-compose up` plus migrations, with one command.
- [ ] CI blocks merges on failing lint/tests.
- [ ] Staging deploy is automatic on merge; production deploy requires
      explicit approval.
- [ ] Rollback procedure has been tested at least once, not just written
      down.
