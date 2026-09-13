package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()

	batch := &Batch{
		ID:             "batch-101",
		StartedAt:      time.Now().Add(-time.Minute),
		ClosedAt:       time.Now(),
		EventCount:     2,
		MerkleRoot:     []byte("root-101"),
		Signature:      []byte("sig-101"),
		KeyVersion:     "k1",
		BinlogFile:     "mysql-bin.000001",
		BinlogPosition: 1234,
		Status:         "signed",
	}

	actor := "user-42"
	rec1 := &Record{
		ID:              "rec-1",
		BatchID:         batch.ID,
		TableName:       "orders",
		PrimaryKey:      json.RawMessage(`{"id": 1}`),
		EventType:       "INSERT",
		AfterImage:      json.RawMessage(`{"id": 1, "total": 100}`),
		ActorUserID:     &actor,
		ActorType:       "USER",
		TransactionID:   "tx-1",
		SchemaVersion:   "v1",
		CommittedAt:     time.Now().UTC(),
		MerkleLeafIndex: 1, // Deliberately out of order to verify sorting
	}

	rec0 := &Record{
		ID:              "rec-0",
		BatchID:         batch.ID,
		TableName:       "orders",
		PrimaryKey:      json.RawMessage(`{"id": 2}`),
		EventType:       "INSERT",
		AfterImage:      json.RawMessage(`{"id": 2, "total": 200}`),
		ActorUserID:     nil,
		ActorType:       "SYSTEM",
		TransactionID:   "tx-1",
		SchemaVersion:   "v1",
		CommittedAt:     time.Now().UTC(),
		MerkleLeafIndex: 0,
	}

	err := ms.CreateBatch(ctx, batch, []*Record{rec1, rec0})
	require.NoError(t, err)

	// Fetch batch
	fetchedBatch, err := ms.GetBatch(ctx, batch.ID)
	require.NoError(t, err)
	assert.Equal(t, batch.ID, fetchedBatch.ID)
	assert.Equal(t, "signed", fetchedBatch.Status)

	// Fetch single record
	fetchedRec, err := ms.GetRecord(ctx, "rec-1")
	require.NoError(t, err)
	assert.Equal(t, "rec-1", fetchedRec.ID)
	assert.Equal(t, "orders", fetchedRec.TableName)

	// Fetch records by batch ID - should be sorted by MerkleLeafIndex
	recs, err := ms.GetRecordsByBatchID(ctx, batch.ID)
	require.NoError(t, err)
	require.Len(t, recs, 2)
	assert.Equal(t, 0, recs[0].MerkleLeafIndex)
	assert.Equal(t, "rec-0", recs[0].ID)
	assert.Equal(t, 1, recs[1].MerkleLeafIndex)
	assert.Equal(t, "rec-1", recs[1].ID)

	// Verification payload fetch
	payload, bData, err := ms.GetRecordForVerification(ctx, "rec-1")
	require.NoError(t, err)
	assert.Equal(t, "rec-1", payload.ID)
	assert.Equal(t, 1, payload.MerkleLeafIndex)
	assert.Equal(t, batch.ID, bData.BatchID)
	assert.Len(t, bData.AllLeafHashes, 2)

	// Update batch status
	wormKey := "worm/2026/09/batch-101.jsonl"
	err = ms.UpdateBatchStatus(ctx, batch.ID, "archived", &wormKey)
	require.NoError(t, err)

	updatedBatch, err := ms.GetBatch(ctx, batch.ID)
	require.NoError(t, err)
	assert.Equal(t, "archived", updatedBatch.Status)
	require.NotNil(t, updatedBatch.WORMObjectKey)
	assert.Equal(t, wormKey, *updatedBatch.WORMObjectKey)

	// WORM Index
	indexEntry := &WORMIndexEntry{
		BatchID:       batch.ID,
		WORMObjectKey: wormKey,
		TieredAt:      time.Now(),
	}
	err = ms.InsertWORMIndex(ctx, indexEntry)
	require.NoError(t, err)

	fetchedIndex, err := ms.GetWORMIndex(ctx, batch.ID)
	require.NoError(t, err)
	assert.Equal(t, wormKey, fetchedIndex.WORMObjectKey)

	// Delete records by batch ID
	err = ms.DeleteRecordsByBatchID(ctx, batch.ID)
	require.NoError(t, err)

	recsAfterDelete, err := ms.GetRecordsByBatchID(ctx, batch.ID)
	require.NoError(t, err)
	assert.Empty(t, recsAfterDelete)
}
