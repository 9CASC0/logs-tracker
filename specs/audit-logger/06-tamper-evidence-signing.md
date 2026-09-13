# Phase 5 — Tamper Evidence: Batching, Merkle Trees, Signing & Verification

**Goal:** Turn a stream of snapshotted audit records into signed,
tamper-evident checkpoints, and provide a way to verify any single record
against one.
**Estimated Duration:** 8 days
**Depends On:** Phase 4
**Primary Owner:** You (solo project)

## Functional Requirements

- Buffer incoming audit records into a batch, closing the batch when either
  a time or event-count threshold is hit (whichever first).
- Build a Merkle tree over the batch's records and compute the root.
- Sign only the root via the local `Signer`; never write full record data
  anywhere near the key material.
- Persist the batch (metadata + records) to Postgres, and push a signed
  checkpoint object to WORM storage — both as part of the same logical
  "close batch" operation, including the transactional binlog-position
  commit from Phase 4.
- Provide a verification routine: given a record id, retrieve its batch's
  Merkle path and signature, and confirm the record was genuinely part of
  that signed snapshot.
- Apply the same batching-and-signing pipeline to bootstrap snapshots
  (Phase 6), so no table's history has an unsigned starting point.

## Components

- **Batch Buffer** — accumulates records for the currently-open batch;
  exposes the hybrid time/count close trigger.
- **Merkle Builder** — deterministic tree construction (fixed leaf
  ordering, e.g. by `merkle_leaf_index`/capture order) and Merkle-path
  extraction for a given leaf.
- **Local Signer** — implements the `Signer` interface (Phase 8) against a
  local Ed25519 keypair; the private key lives encrypted in a local
  keyfile, unlocked once at daemon startup via a passphrase from the OS
  keychain, and held only in memory thereafter. The daemon only ever calls
  `Sign` on a root hash.
- **WORM Writer** — implements the `ArchiveStore` interface (Phase 8) to
  push checkpoint objects.
- **Verification Service** — pure function: `(record, batch metadata,
  Merkle path, signature) -> valid/invalid`, usable both internally and as
  the basis for the public verification feed (Phase 7).

## Batch Configuration Example

```json
{
  "batch_max_interval_seconds": 60,
  "batch_max_events": 5000
}
```

Runtime-configurable, not hardcoded (Phase 1 decision) — tune after
observing real write volume.

## Verification Interface (illustrative)

```go
type Verifier interface {
    // VerifyRecord returns whether the record is provably part of its
    // batch's signed Merkle root, and the root/signature used to prove it.
    VerifyRecord(recordID string) (VerificationResult, error)
}

type VerificationResult struct {
    Valid       bool
    MerkleRoot  []byte
    Signature   []byte
    BatchID     string
    VerifiedAt  time.Time
}
```

## Dispute Resolution Flow (recap)

1. Look up the disputed record and its `batch_id`.
2. Fetch the batch's signed Merkle root, signature, and local key version
   (from Postgres if still hot, or from the WORM checkpoint object if
   tiered).
3. Recompute the Merkle path from the record up to the root.
4. Verify the signature against the published public key.
5. If both the path and signature check out, the record is provably
   unaltered and provably part of that exact snapshot.

## Tasks

- [ ] Implement the batch buffer with hybrid close-trigger logic.
- [ ] Implement Merkle tree construction and per-leaf path extraction.
- [ ] Implement the local keyfile-based `Signer` (Ed25519 sign/verify,
      encrypted-at-rest key, OS-keychain-held unlock passphrase).
- [ ] Implement the WORM checkpoint writer (via the `ArchiveStore`
      interface, Phase 8).
- [ ] Implement the verification service and its public interface.
- [ ] Wire batch-close to also commit the Phase 4 binlog-position
      checkpoint transactionally.
- [ ] Write deliberately-tampered test fixtures (modified before/after
      value, substituted signature, reordered leaves) and confirm
      verification correctly fails on each.

## Deliverables

- End-to-end path from "records queued for batch" to "signed checkpoint in
  WORM storage" and back to "verify a specific record."
- Verification service usable both as an internal library call and as the
  basis for Phase 7's public/verification API endpoints.

## Acceptance Criteria / Definition of Done

- [ ] A closed batch produces a Merkle root signed by the local key,
      retrievable from both Postgres and the WORM checkpoint object.
- [ ] Verifying a genuine record against its batch succeeds.
- [ ] Verifying a tampered record (any single changed byte in its snapshot)
      against the same batch fails.
- [ ] Verifying a genuine record against a substituted/invalid signature
      fails.
- [ ] Batch closing correctly commits the binlog checkpoint in the same
      transaction as the batch's Postgres write (crash between the two is
      impossible by construction, not just by convention).
