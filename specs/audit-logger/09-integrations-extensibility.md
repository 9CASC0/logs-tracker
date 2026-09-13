# Phase 8 — Integrations & Extensibility Seams

**Goal:** Make sure today's necessary simplifications (single MySQL source,
one WORM provider, two alert sinks) are one-class swaps later, not
rewrites.
**Estimated Duration:** 4 days
**Depends On:** Phase 6, Phase 7
**Primary Owner:** You (solo project)

## Design Principle

Each seam below is an **adapter interface** with a v1 implementation behind
it — the point is that a future integration is "write one class," not
"restructure the daemon."

## CDC Source Adapter

```go
type ChangeSource interface {
    Stream(ctx context.Context) (<-chan RawChangeEvent, error)
    Checkpoint() Position
    ResumeFrom(pos Position) error
}

type MySQLBinlogSource struct { /* go-mysql-backed implementation, v1 */ }
```

- v1 ships only `MySQLBinlogSource`. A future Postgres logical-replication
  or MongoDB change-stream source implements the same interface without
  touching the attribution/snapshot/batch/Merkle/signing stages downstream.

## WORM Archive Provider Adapter

```go
type ArchiveStore interface {
    PutCheckpoint(ctx context.Context, batchID string, data []byte) error
    PutArchive(ctx context.Context, batchID string, data []byte) error
    Get(ctx context.Context, objectKey string) ([]byte, error)
}
```

- v1 ships exactly **one** implementation: `LocalDirArchiveStore`, which
  writes to a local write-once directory and `chmod`s each object
  read-only (0444) immediately after writing. It's used, unmodified, in
  every environment (dev/staging/prod each just point at a different
  path) — no cloud account, no emulator container needed.
- A future `S3ArchiveStore` (or GCS/Azure equivalent) would be a second
  implementation of the same interface, only worth building if this ever
  needs cloud-grade Object Lock guarantees or off-machine durability that a
  personal project doesn't currently need.

## Signing & Encryption Key Adapter

```go
type Signer interface {
    Sign(ctx context.Context, digest []byte) (signature []byte, keyVersion string, err error)
    Verify(ctx context.Context, digest, signature []byte, keyVersion string) (bool, error)
    PublicKey(ctx context.Context, keyVersion string) ([]byte, error)
}

type Encryptor interface {
    Encrypt(ctx context.Context, plaintext []byte) (ciphertext []byte, keyVersion string, err error)
    Decrypt(ctx context.Context, ciphertext []byte, keyVersion string) ([]byte, error)
}
```

- v1 ships one implementation of each: `LocalKeyfileSigner` (Ed25519) and
  `LocalKeyfileEncryptor` (AES-256-GCM), both backed by the same encrypted
  local keyfile, unlocked at startup via an OS-keychain-held passphrase.
- A future `VaultSigner`/`VaultEncryptor` (or a cloud KMS equivalent) would
  be a second implementation of these same interfaces — only worth
  building if this project ever needs multi-user key custody, remote
  signing, or a formal key-rotation/audit story beyond what a solo
  developer needs.

## Alert Sink Adapter

```go
type AlertSink interface {
    Send(ctx context.Context, alert Alert) error
}

type DiscordWebhookSink struct{ /* v1 */ }
```

- v1 ships one sink: a Discord (or Telegram) webhook, with severity
  controlling presentation (plain message vs. @mention + distinct marker),
  not the destination.
- A future Slack/PagerDuty/SIEM integration (Splunk, Datadog Security,
  Elastic Security) would implement the same interface and register
  alongside the existing sink without changing the alerting rules table
  (Phase 7) — only worth adding if this project ever grows a real team or
  on-call rotation.

## Explicitly Not Built Now (documented extension points, not guesses)

| Future Need | Extension Point |
|---|---|
| Additional database engines | New `ChangeSource` implementation |
| Cloud WORM provider (e.g. S3 Object Lock) | New `ArchiveStore` implementation |
| Vault/KMS-backed signing or PII encryption | New `Signer`/`Encryptor` implementation |
| SIEM or on-call paging correlation | New `AlertSink` implementation |
| Daemon HA / leader election | Would sit around `ChangeSource.Checkpoint()`/`ResumeFrom()` — the interface already models position as explicit state for this reason |
| Multi-instance MySQL / sharding | Would mean multiple `ChangeSource` instances feeding one batching/signing pipeline — not designed in v1, but the adapter boundary is the right seam if it comes up |

## Tasks

- [ ] Define and implement the `ChangeSource`, `ArchiveStore`, and
      `AlertSink` interfaces.
- [ ] Confirm Phase 4/5/7 code depends only on these interfaces, not on
      `go-mysql`/the local filesystem details/Discord-or-Telegram
      specifics directly.
- [ ] Write the extension-point table (above) into permanent docs.

## Deliverables

- Three adapter interfaces in place, each with its v1 implementation.
- Confirmation (by code review, not just docs) that pipeline stages beyond
  Phase 4's ingestion don't leak provider-specific types.

## Acceptance Criteria / Definition of Done

- [ ] Swapping the WORM provider implementation requires changing one file,
      not touching Phase 5/6 logic.
- [ ] Swapping/adding an alert sink requires implementing one interface,
      not touching the Phase 7 rules table.
- [ ] A code reviewer unfamiliar with the specific provider choices can
      still understand the pipeline by reading the interfaces alone.
