# Phase 9 — Security & Compliance Hardening

**Goal:** Harden the system to a standard appropriate for something that
exists specifically to be trusted under adversarial scrutiny.
**Estimated Duration:** 5 days
**Depends On:** Phase 3, and touches every prior phase's components
**Primary Owner:** You (solo project)

## Objectives

- Close any gaps left open by earlier phases.
- Ensure every access to audit data is authenticated, authorized, and
  itself accounted for.
- Confirm encryption in transit and at rest throughout.
- Document data retention and access-request handling.

## Checklist

### Secrets & Config
- [ ] The local keyfile's unlock passphrase is stored in the OS keychain,
      never in an environment variable, config file, or source control.
- [ ] The encrypted keyfile itself has restrictive file permissions (0600)
      and is excluded from backups that aren't themselves encrypted.
- [ ] Separate keyfile and passphrase per environment (dev/staging/prod) —
      a dev key must never be reused in production.

### Transport & Storage
- [ ] TLS enforced on daemon↔Postgres and API↔clients in staging/prod (no
      Vault/cloud-WORM hop to secure, since both are local).
- [ ] Postgres encryption at rest confirmed with the hosting provider
      (don't assume), if Postgres itself is hosted rather than local.
- [ ] The local write-once archive directory's read-only permissions are
      verified with an actual attempted-overwrite/attempted-delete test.
      Explicitly documented: this is **best-effort** immutability (blocks
      accidental overwrite and casual tampering), not a guarantee against a
      determined local root/administrator user — accepted for this
      project's threat model rather than a gap to close.

### AuthN/AuthZ
- [ ] Every `/audit/*` endpoint uses the Phase 3 permission guard, swept
      across all of Phase 7's routes.
- [ ] Only the daemon process can read the decrypted signing/PII keys in
      memory; the API server process (Phase 3's `Encryptor`-for-read path)
      is the only other process granted decrypt access, verified by
      checking which processes/users can read the keyfile.
- [ ] `auditor_readonly` and other direct-SQL grants reviewed for exactly
      the intended people/services (in a solo project, this is mainly a
      sanity check that no over-broad grant was left in place).

### Audit-of-the-Audit-System
- [ ] Access to `_audit_config` itself (who can register/deregister a
      table, change its policy or severity tier) is itself logged and
      reviewable — this system does not get a blind spot for its own
      configuration, even in a solo project (future-you benefits from this
      as much as a team would).
- [ ] Key usage (signing calls, decrypt calls) is logged by the daemon
      itself, since there's no separate Vault audit log to rely on —
      reviewable independently of the main pipeline logs.
- [ ] Changes to alert routing (Phase 7) are reviewed like any other
      security-relevant configuration change.

### Data Handling
- [ ] PII columns confirmed encrypted at rest per `_audit_config` for every
      table that should have them configured (spot-check against the
      source schema, not just the config file).
- [ ] Retention policy (90 days hot, WORM tiering, Phase 6) documented for
      compliance review; confirm no jurisdiction-specific override applies
      (Phase 0 open question).
- [ ] No PII/sensitive values appear in daemon logs at any log level used
      in production.
- [ ] Backups (Postgres) encrypted; restore tested at least once (Phase 11).

### Application Security
- [ ] Input validation on every internal API request (no raw untyped body
      access).
- [ ] No raw SQL string concatenation anywhere in the store layer — audited
      for injection risk.
- [ ] CORS/network policy restricts the internal API to known internal
      callers; the public verification feed (Phase 7) is the only
      intentionally public surface.
- [ ] Dependency vulnerability scan (`govulncheck`, `npm audit` if any JS
      tooling is involved) run and issues resolved or explicitly accepted
      before go-live.

## Deliverables

- Security checklist above completed with evidence per item.
- Documented retention & access-request policy.
- Dependency audit report with issues resolved or explicitly accepted.

## Acceptance Criteria / Definition of Done

- [ ] No secrets in source control (verified via a repo-wide scan).
- [ ] Every audit-data-touching endpoint requires auth + permission check
      (spot-checked across all routers).
- [ ] A test attempt to access the internal API without permission, or to
      write to Postgres via a role that shouldn't be able to, fails with
      `403`/permission-denied — not a silent success or `500`.
- [ ] `govulncheck` (and any other relevant scanner) shows no unresolved
      high/critical issues.
