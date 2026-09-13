package merkle

import (
	"context"
	"fmt"
	"time"

	"auditlogd/internal/signing"
)

// VerificationResult contains the cryptographic verification outcome for a record.
type VerificationResult struct {
	Valid          bool      `json:"valid"`
	RecordID       string    `json:"record_id"`
	BatchID        string    `json:"batch_id"`
	MerkleRoot     []byte    `json:"merkle_root"`
	MerkleRootHex  string    `json:"merkle_root_hex"`
	Signature      []byte    `json:"signature"`
	SignatureHex   string    `json:"signature_hex"`
	KeyVersion     string    `json:"key_version"`
	VerifiedAt     time.Time `json:"verified_at"`
	FailureReason  string    `json:"failure_reason,omitempty"`
}

// RecordFetcher interface allows the verifier to load record and batch information from Postgres or WORM.
type RecordFetcher interface {
	GetRecordForVerification(ctx context.Context, recordID string) (*RecordCanonicalPayload, *BatchVerificationData, error)
}

// BatchVerificationData holds batch-level cryptographic details needed to verify a record.
type BatchVerificationData struct {
	BatchID       string
	MerkleRoot    []byte
	Signature     []byte
	KeyVersion    string
	AllLeafHashes [][]byte
	Proof         []ProofNode
}

// Verifier provides cryptographic verification of audit records.
type Verifier interface {
	VerifyRecord(ctx context.Context, recordID string) (VerificationResult, error)
}

// RecordVerifier implements Verifier using a RecordFetcher and a Signer.
type RecordVerifier struct {
	fetcher RecordFetcher
	signer  signing.Signer
}

// NewRecordVerifier creates a RecordVerifier.
func NewRecordVerifier(fetcher RecordFetcher, signer signing.Signer) *RecordVerifier {
	return &RecordVerifier{
		fetcher: fetcher,
		signer:  signer,
	}
}

// VerifyRecord executes the full cryptographic dispute verification flow.
func (v *RecordVerifier) VerifyRecord(ctx context.Context, recordID string) (VerificationResult, error) {
	now := time.Now().UTC()
	result := VerificationResult{
		RecordID:   recordID,
		VerifiedAt: now,
		Valid:      false,
	}

	payload, batchData, err := v.fetcher.GetRecordForVerification(ctx, recordID)
	if err != nil {
		result.FailureReason = fmt.Sprintf("failed to fetch record data: %v", err)
		return result, err
	}

	result.BatchID = batchData.BatchID
	result.MerkleRoot = batchData.MerkleRoot
	result.MerkleRootHex = fmt.Sprintf("%x", batchData.MerkleRoot)
	result.Signature = batchData.Signature
	result.SignatureHex = fmt.Sprintf("%x", batchData.Signature)
	result.KeyVersion = batchData.KeyVersion

	// 1. Verify batch signature against the Merkle root
	sigValid, err := v.signer.Verify(ctx, batchData.MerkleRoot, batchData.Signature, batchData.KeyVersion)
	if err != nil || !sigValid {
		result.FailureReason = "invalid batch signature"
		return result, nil
	}

	// 2. Compute canonical leaf hash for the record
	leafHash, err := ComputeRecordLeafHash(*payload)
	if err != nil {
		result.FailureReason = fmt.Sprintf("failed to compute leaf hash: %v", err)
		return result, nil
	}

	// 3. Verify Merkle proof
	proof := batchData.Proof
	if len(proof) == 0 && len(batchData.AllLeafHashes) > 0 {
		// Reconstruct proof if full leaf hashes are provided
		tree, err := BuildTree(batchData.AllLeafHashes)
		if err != nil {
			result.FailureReason = fmt.Sprintf("failed to reconstruct tree: %v", err)
			return result, nil
		}
		proof, err = tree.GenerateProof(payload.MerkleLeafIndex)
		if err != nil {
			result.FailureReason = fmt.Sprintf("failed to generate proof: %v", err)
			return result, nil
		}
	}

	proofValid := VerifyProof(leafHash, proof, batchData.MerkleRoot)
	if !proofValid {
		result.FailureReason = "merkle proof verification failed (record does not match signed root)"
		return result, nil
	}

	result.Valid = true
	return result, nil
}
