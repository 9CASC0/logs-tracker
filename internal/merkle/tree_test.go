package merkle_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"auditlogd/internal/merkle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMerkleTreeConstruction(t *testing.T) {
	t.Run("empty leaves", func(t *testing.T) {
		tree, err := merkle.BuildTree(nil)
		require.NoError(t, err)
		assert.NotEmpty(t, tree.Root())
	})

	t.Run("single leaf", func(t *testing.T) {
		leaf := merkle.HashLeaf([]byte("single-record"))
		tree, err := merkle.BuildTree([][]byte{leaf})
		require.NoError(t, err)
		assert.Equal(t, leaf, tree.Root())

		proof, err := tree.GenerateProof(0)
		require.NoError(t, err)
		assert.Empty(t, proof)
		assert.True(t, merkle.VerifyProof(leaf, proof, tree.Root()))
	})

	t.Run("even number of leaves (4 leaves)", func(t *testing.T) {
		leaves := make([][]byte, 4)
		for i := 0; i < 4; i++ {
			leaves[i] = merkle.HashLeaf([]byte(fmt.Sprintf("record-%d", i)))
		}

		tree, err := merkle.BuildTree(leaves)
		require.NoError(t, err)
		assert.NotEmpty(t, tree.Root())

		for i := 0; i < 4; i++ {
			proof, err := tree.GenerateProof(i)
			require.NoError(t, err)
			assert.Len(t, proof, 2)
			assert.True(t, merkle.VerifyProof(leaves[i], proof, tree.Root()))
		}
	})

	t.Run("odd number of leaves (3 leaves)", func(t *testing.T) {
		leaves := make([][]byte, 3)
		for i := 0; i < 3; i++ {
			leaves[i] = merkle.HashLeaf([]byte(fmt.Sprintf("record-%d", i)))
		}

		tree, err := merkle.BuildTree(leaves)
		require.NoError(t, err)
		assert.NotEmpty(t, tree.Root())

		for i := 0; i < 3; i++ {
			proof, err := tree.GenerateProof(i)
			require.NoError(t, err)
			assert.True(t, merkle.VerifyProof(leaves[i], proof, tree.Root()))
		}
	})

	t.Run("large tree (100 leaves)", func(t *testing.T) {
		count := 100
		leaves := make([][]byte, count)
		for i := 0; i < count; i++ {
			leaves[i] = merkle.HashLeaf([]byte(fmt.Sprintf("large-record-%d", i)))
		}

		tree, err := merkle.BuildTree(leaves)
		require.NoError(t, err)

		for i := 0; i < count; i++ {
			proof, err := tree.GenerateProof(i)
			require.NoError(t, err)
			assert.True(t, merkle.VerifyProof(leaves[i], proof, tree.Root()))
		}
	})
}

func TestMerkleTamperDetection(t *testing.T) {
	leaves := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		leaves[i] = merkle.HashLeaf([]byte(fmt.Sprintf("genuine-record-%d", i)))
	}

	tree, err := merkle.BuildTree(leaves)
	require.NoError(t, err)

	proof, err := tree.GenerateProof(2)
	require.NoError(t, err)

	t.Run("tampered leaf data fails verification", func(t *testing.T) {
		tamperedLeaf := merkle.HashLeaf([]byte("tampered-record-2"))
		assert.False(t, merkle.VerifyProof(tamperedLeaf, proof, tree.Root()))
	})

	t.Run("tampered proof hash fails verification", func(t *testing.T) {
		corruptedProof := make([]merkle.ProofNode, len(proof))
		copy(corruptedProof, proof)
		corruptedProof[0].Hash = merkle.HashLeaf([]byte("bogus-hash"))

		assert.False(t, merkle.VerifyProof(leaves[2], corruptedProof, tree.Root()))
	})

	t.Run("substituted root fails verification", func(t *testing.T) {
		fakeRoot := merkle.HashLeaf([]byte("different-root"))
		assert.False(t, merkle.VerifyProof(leaves[2], proof, fakeRoot))
	})
}

// MockFetcher for Verifier tests
type mockFetcher struct {
	payload   *merkle.RecordCanonicalPayload
	batchData *merkle.BatchVerificationData
}

func (m *mockFetcher) GetRecordForVerification(ctx context.Context, recordID string) (*merkle.RecordCanonicalPayload, *merkle.BatchVerificationData, error) {
	return m.payload, m.batchData, nil
}

type mockSigner struct {
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
}

func (s *mockSigner) Sign(ctx context.Context, digest []byte) ([]byte, string, error) {
	return ed25519.Sign(s.privKey, digest), "v1", nil
}

func (s *mockSigner) Verify(ctx context.Context, digest, signature []byte, keyVersion string) (bool, error) {
	return ed25519.Verify(s.pubKey, digest, signature), nil
}

func (s *mockSigner) PublicKey(ctx context.Context, keyVersion string) ([]byte, error) {
	return s.pubKey, nil
}

func TestRecordVerifier(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer := &mockSigner{pubKey: pub, privKey: priv}

	payload := merkle.RecordCanonicalPayload{
		ID:              "rec-123",
		BatchID:         "batch-456",
		TableName:       "users",
		PrimaryKey:      json.RawMessage(`{"id": 1}`),
		EventType:       "UPDATE",
		BeforeImage:     json.RawMessage(`{"id": 1, "name": "Alice"}`),
		AfterImage:      json.RawMessage(`{"id": 1, "name": "Alice Cooper"}`),
		ActorType:       "USER",
		TransactionID:   "tx-001",
		SchemaVersion:   "v1",
		CommittedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		MerkleLeafIndex: 0,
	}

	leafHash, err := merkle.ComputeRecordLeafHash(payload)
	require.NoError(t, err)

	otherLeaf := merkle.HashLeaf([]byte("other-record"))
	tree, err := merkle.BuildTree([][]byte{leafHash, otherLeaf})
	require.NoError(t, err)

	sig, ver, err := signer.Sign(context.Background(), tree.Root())
	require.NoError(t, err)

	fetcher := &mockFetcher{
		payload: &payload,
		batchData: &merkle.BatchVerificationData{
			BatchID:       "batch-456",
			MerkleRoot:    tree.Root(),
			Signature:     sig,
			KeyVersion:    ver,
			AllLeafHashes: [][]byte{leafHash, otherLeaf},
		},
	}

	verifier := merkle.NewRecordVerifier(fetcher, signer)

	t.Run("genuine record verifies successfully", func(t *testing.T) {
		res, err := verifier.VerifyRecord(context.Background(), "rec-123")
		require.NoError(t, err)
		assert.True(t, res.Valid)
		assert.Equal(t, "batch-456", res.BatchID)
		assert.Equal(t, tree.Root(), res.MerkleRoot)
	})

	t.Run("tampered payload fails verification", func(t *testing.T) {
		tamperedPayload := payload
		tamperedPayload.AfterImage = json.RawMessage(`{"id": 1, "name": "Eve Attacker"}`)

		tamperedFetcher := &mockFetcher{
			payload:   &tamperedPayload,
			batchData: fetcher.batchData,
		}
		tamperedVerifier := merkle.NewRecordVerifier(tamperedFetcher, signer)

		res, err := tamperedVerifier.VerifyRecord(context.Background(), "rec-123")
		require.NoError(t, err)
		assert.False(t, res.Valid)
		assert.Contains(t, res.FailureReason, "merkle proof verification failed")
	})

	t.Run("substituted signature fails verification", func(t *testing.T) {
		badSigBatchData := *fetcher.batchData
		badSigBatchData.Signature = make([]byte, 64) // invalid signature bytes

		badFetcher := &mockFetcher{
			payload:   &payload,
			batchData: &badSigBatchData,
		}
		badVerifier := merkle.NewRecordVerifier(badFetcher, signer)

		res, err := badVerifier.VerifyRecord(context.Background(), "rec-123")
		require.NoError(t, err)
		assert.False(t, res.Valid)
		assert.Equal(t, "invalid batch signature", res.FailureReason)
	})
}
