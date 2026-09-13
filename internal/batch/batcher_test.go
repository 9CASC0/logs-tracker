package batch_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"auditlogd/internal/alerting"
	"auditlogd/internal/archive"
	"auditlogd/internal/batch"
	"auditlogd/internal/source"
	"auditlogd/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type dummySigner struct {
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
}

func (s *dummySigner) Sign(ctx context.Context, digest []byte) ([]byte, string, error) {
	return ed25519.Sign(s.privKey, digest), "v1", nil
}

func (s *dummySigner) Verify(ctx context.Context, digest, signature []byte, keyVersion string) (bool, error) {
	return ed25519.Verify(s.pubKey, digest, signature), nil
}

func (s *dummySigner) PublicKey(ctx context.Context, keyVersion string) ([]byte, error) {
	return s.pubKey, nil
}

func TestBatcher(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer := &dummySigner{pubKey: pub, privKey: priv}

	tempDir := t.TempDir()
	archStore, err := archive.NewLocalDirArchiveStore(tempDir)
	require.NoError(t, err)

	memStore := store.NewMemoryStore()
	dispatcher := alerting.NewDispatcher(time.Minute)

	t.Run("closes on count threshold", func(t *testing.T) {
		cfg := batch.Config{
			MaxInterval: 10 * time.Second,
			MaxEvents:   3, // threshold is 3
		}
		batcher := batch.NewBatcher(cfg, signer, memStore, archStore, dispatcher)

		var closedBatches []*store.Batch
		batcher.SetBatchClosedCallback(func(b *store.Batch) {
			closedBatches = append(closedBatches, b)
		})

		ctx := context.Background()
		pos := source.Position{File: "mysql-bin.000001", Position: 120}

		for i := 0; i < 3; i++ {
			rec := &store.Record{
				ID:          string(rune('a' + i)),
				TableName:   "items",
				PrimaryKey:  json.RawMessage(`{"id": 1}`),
				EventType:   "INSERT",
				AfterImage:  json.RawMessage(`{"val": 1}`),
				CommittedAt: time.Now().UTC(),
			}
			err := batcher.AddRecord(ctx, rec, pos)
			require.NoError(t, err)
		}

		assert.Len(t, closedBatches, 1)
		b := closedBatches[0]
		assert.Equal(t, 3, b.EventCount)
		assert.NotEmpty(t, b.MerkleRoot)
		assert.NotEmpty(t, b.Signature)
		assert.Equal(t, "signed", b.Status)

		// Verify checkpoint exists in WORM archive
		chkData, err := archStore.Get(ctx, *b.WORMObjectKey)
		require.NoError(t, err)
		assert.Contains(t, string(chkData), b.ID)
	})

	t.Run("closes on time interval", func(t *testing.T) {
		cfg := batch.Config{
			MaxInterval: 100 * time.Millisecond,
			MaxEvents:   100,
		}
		batcher := batch.NewBatcher(cfg, signer, memStore, archStore, dispatcher)

		var closedBatches []*store.Batch
		batcher.SetBatchClosedCallback(func(b *store.Batch) {
			closedBatches = append(closedBatches, b)
		})

		ctx := context.Background()
		rec := &store.Record{
			ID:          "rec-interval",
			TableName:   "items",
			PrimaryKey:  json.RawMessage(`{"id": 2}`),
			EventType:   "INSERT",
			AfterImage:  json.RawMessage(`{"val": 2}`),
			CommittedAt: time.Now().UTC(),
		}
		err := batcher.AddRecord(ctx, rec, source.Position{File: "mysql-bin.000001", Position: 200})
		require.NoError(t, err)

		// Wait for timer to fire
		time.Sleep(200 * time.Millisecond)

		assert.Len(t, closedBatches, 1)
		assert.Equal(t, 1, closedBatches[0].EventCount)
	})
}
