package tiering_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"auditlogd/internal/alerting"
	"auditlogd/internal/archive"
	"auditlogd/internal/store"
	"auditlogd/internal/tiering"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetentionTiering(t *testing.T) {
	tempDir := t.TempDir()
	archStore, err := archive.NewLocalDirArchiveStore(tempDir)
	require.NoError(t, err)

	memStore := store.NewMemoryStore()
	dispatcher := alerting.NewDispatcher(time.Minute)

	ctx := context.Background()

	// Seed old batch (100 days old) and recent batch (10 days old)
	oldBatchID := "batch-old-100"
	recentBatchID := "batch-recent-10"

	now := time.Now().UTC()
	oldTime := now.Add(-100 * 24 * time.Hour)
	recentTime := now.Add(-10 * 24 * time.Hour)

	oldBatch := &store.Batch{
		ID:         oldBatchID,
		StartedAt:  oldTime,
		ClosedAt:   oldTime,
		EventCount: 2,
		MerkleRoot: []byte("old-root"),
		Signature:  []byte("old-sig"),
		KeyVersion: "v1",
		Status:     "signed",
	}
	oldRecords := []*store.Record{
		{ID: "rec-old-1", BatchID: oldBatchID, TableName: "users", PrimaryKey: json.RawMessage(`{"id":1}`), EventType: "INSERT"},
		{ID: "rec-old-2", BatchID: oldBatchID, TableName: "users", PrimaryKey: json.RawMessage(`{"id":2}`), EventType: "UPDATE"},
	}
	err = memStore.CreateBatch(ctx, oldBatch, oldRecords)
	require.NoError(t, err)

	recentBatch := &store.Batch{
		ID:         recentBatchID,
		StartedAt:  recentTime,
		ClosedAt:   recentTime,
		EventCount: 1,
		MerkleRoot: []byte("recent-root"),
		Signature:  []byte("recent-sig"),
		KeyVersion: "v1",
		Status:     "signed",
	}
	recentRecords := []*store.Record{
		{ID: "rec-recent-1", BatchID: recentBatchID, TableName: "users", PrimaryKey: json.RawMessage(`{"id":3}`), EventType: "INSERT"},
	}
	err = memStore.CreateBatch(ctx, recentBatch, recentRecords)
	require.NoError(t, err)

	// Run tiering with 90 days retention window
	service := tiering.NewService(
		tiering.Config{RetentionWindow: 90 * 24 * time.Hour},
		memStore,
		archStore,
		dispatcher,
	)

	res, err := service.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, res.BatchesTiered)
	assert.Equal(t, 2, res.RecordsPurged)

	// 1. Check old batch status updated to 'archived'
	b, err := memStore.GetBatch(ctx, oldBatchID)
	require.NoError(t, err)
	assert.Equal(t, "archived", b.Status)
	assert.NotNil(t, b.WORMObjectKey)

	// 2. Check old records purged from hot store
	recordsInStore, err := memStore.GetRecordsByBatchID(ctx, oldBatchID)
	require.NoError(t, err)
	assert.Empty(t, recordsInStore)

	// 3. Check recent records remain untouched
	recentInStore, err := memStore.GetRecordsByBatchID(ctx, recentBatchID)
	require.NoError(t, err)
	assert.Len(t, recentInStore, 1)

	// 4. Check archive file exists in WORM storage with the full records
	archiveData, err := archStore.Get(ctx, *b.WORMObjectKey)
	require.NoError(t, err)
	assert.Contains(t, string(archiveData), "rec-old-1")
	assert.Contains(t, string(archiveData), "rec-old-2")

	// 5. Check WORM index entry exists
	wEntry, err := memStore.GetWORMIndex(ctx, oldBatchID)
	require.NoError(t, err)
	assert.Equal(t, oldBatchID, wEntry.BatchID)
	assert.Equal(t, *b.WORMObjectKey, wEntry.WORMObjectKey)

	// 6. Test idempotency: re-running does not re-tier already archived batch
	res2, err := service.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, res2.BatchesTiered)
}
