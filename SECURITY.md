# Security Policy & Cryptographic Architecture

## Cryptographic Standards

The Global Audit Logger (`auditlogd`) adheres to modern, battle-tested cryptographic primitives:

| Component | Standard / Primitive | Purpose |
|---|---|---|
| **Asymmetric Signing** | Ed25519 (RFC 8032) | High-speed, deterministic digital signatures on Merkle roots. |
| **Merkle Tree** | RFC 6962 Domain Separation | Prevents second-preimage attacks: `0x00` leaf prefix, `0x01` interior node prefix. |
| **Key Derivation (KDF)** | Argon2id | Memory-hard key derivation to protect local keyfile against brute-force attacks. |
| **Field-Level Encryption** | AES-256-GCM | Authenticated encryption at rest for sensitive/PII columns before database write. |
| **WORM Archive Immutability**| OS Read-Only Flags (`0444`) | Best-effort immutability guarding against accidental overwrite or application bugs. |

---

## Threat Model & Security Guarantees

### 1. Insider Database Tampering
- **Threat**: A rogue DBA or attacker gaining access to the MySQL or PostgreSQL database modifies a row directly in SQL.
- **Defense**:
  - In MySQL: The change is captured directly via the binary log with `actor_type = UNATTRIBUTED`, immediately firing a high-priority alert.
  - In PostgreSQL: Modifying a recorded row in `audit_records` alters its cryptographic hash. When a dispute is verified, the recomputed Merkle root fails to match the Ed25519-signed root and WORM checkpoint. The alteration is mathematically proven and repudiated.

### 2. Private Key Compromise Resistance
- **Threat**: Attacker reads disk files to steal the signing private key.
- **Defense**: The signing private key is never stored in plaintext. It is encrypted in `keys.enc` using AES-256-GCM derived from an Argon2id passphrase. File permissions are restricted to `0600` (owner read/write only).

### 3. Untrusted Verifiers
- **Threat**: External auditors or regulators do not trust the company's internal software or database.
- **Defense**: Verification requires only the **published Ed25519 public key** and the Merkle proof. Verification can be performed using independent, zero-dependency tools (e.g. `cmd/verify` or public REST API) completely outside the organization's network.

---

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it confidentially:
- **Email**: security@auditlogd.internal (or submit a private security advisory on GitHub).
- Please allow reasonable time for remediation before public disclosure.
