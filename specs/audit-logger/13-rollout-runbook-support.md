# Phase 12 — Rollout, Runbook & Ongoing Support

**Goal:** Bring real audited tables online safely, get comfortable relying
on what you've built, and define what happens after launch.
**Estimated Duration:** 5 days for initial rollout, ongoing afterward
**Depends On:** Phase 10 (tests/review passed), Phase 11 (deployed to
production)
**Primary Owner:** You (solo project)

## Pre-Rollout Checklist

- [ ] Production environment deployed and smoke-tested (Phase 11).
- [ ] Security/compliance sign-off obtained (Phase 10).
- [ ] Backup/restore verified in production specifically.
- [ ] (Optional) a backup contact defined for rollout week, if you want a
      second set of eyes — not required for a solo project.
- [ ] Rollback plan confirmed (what happens if a table's rollout must be
      aborted mid-bootstrap).

## Onboarding Plan (in place of clinical training)

| Audience | Content | Format |
|---|---|---|
| You (operator) | Alert triage, verification tool usage, daemon runbook, direct SQL access patterns, `_audit_config` semantics, how to register a new table and what to expect from bootstrap | One combined quick-reference doc, since it's all the same person |
| Anyone you'd ever need to hand this off to (future collaborator, or future-you after months away) | Same content as above | The quick-reference doc doubles as onboarding |
| External verifiers (if anyone ever cares) | How to independently verify a record using only the published public key | Short public-facing doc |

- Provide a **one-page runbook for yourself**: "unattributed alert fired,
  now what" and "daemon is down, now what" — written down specifically so
  you don't have to re-derive it from these phase docs at 11pm.

## Cutover Strategy: Table-by-Table, Risk-Ordered

Rather than a single big-bang cutover, tables are registered into
`_audit_config` one at a time (or in small waves):

1. Register a **low-risk** table first (e.g. one with low write volume and
   no PII) — confirm bootstrap, live capture, batching, and signing all
   work correctly for real.
2. Expand to **medium-risk** tables, including at least one with configured
   PII encryption, to validate that path for real.
3. Onboard **critical-tier** tables (e.g. anything you've marked
   `critical` severity) last, once confidence is established — these are
   the tables where an unattributed change triggers the @mention-marked
   alert, so it's worth having the noise already tuned by this point.

## Go-Live Day Plan (per wave)

- [ ] Make sure you'll actually be around/paying attention during the
      wave's rollout window — there's no one else to catch a problem.
- [ ] Watch the bootstrap run to completion for the newly-registered
      table(s) before considering that wave complete.
- [ ] Monitor batch signing latency and alert volume actively for the first
      24–48 hours of each wave.
- [ ] Daily short check-in during week 1 of each wave to surface friction
      (e.g. alert noise from a legitimate but unattributed batch job).

## Post-Launch Support Plan

- **Week 1–2 per wave (hypercare):** near-immediate response to alerting
  noise or bootstrap issues; quick config tuning (e.g. flipping a table's
  policy from `alert` to `tolerate` if a legitimate system process keeps
  triggering it).
- **Ongoing:**
  - Personal response norm per alert severity (critical: check it right
    away; normal: fine to batch-review whenever you next look).
  - Periodic (e.g. yearly, or after any suspected exposure) review of
    whether to rotate the local signing/encryption keys.
  - Periodic review of `_audit_config` — are severity tiers still correct
    as tables and their sensitivity change?
  - Periodic review of the Phase 0 success metrics (attribution rate,
    dispute-resolution time, alert false-positive rate) — just to yourself,
    closing the loop back to Phase 0's targets.
  - Revisit the explicitly-deferred items (daemon HA, lag monitoring,
    multi-engine support) only if this project ever outgrows personal
    scale.

## Deliverables

- Per-audience onboarding materials (walkthroughs + quick references).
- Rollout runbook (checklist above, filled in with real dates/owners).
- Support SLA document.
- First post-launch metrics review scheduled.

## Acceptance Criteria / Definition of Done

- [ ] Every wave's tables complete bootstrap and reach stable live capture
      before the next wave starts.
- [ ] On-call and compliance personnel have completed onboarding before
      their first relevant alert/query.
- [ ] Hypercare period per wave completed with issues triaged and either
      resolved or explicitly scheduled.
- [ ] First scheduled metrics review against Phase 0 targets is on the
      calendar.
