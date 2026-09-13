package archive_test

import (
	"context"
	"path/filepath"
	"testing"

	"auditlogd/internal/archive"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalDirArchiveStore(t *testing.T) {
	tempDir := t.TempDir()
	store, err := archive.NewLocalDirArchiveStore(tempDir)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("put and get checkpoint", func(t *testing.T) {
		batchID := "batch-test-001"
		data := []byte(`{"batch_id": "batch-test-001", "merkle_root": "abcdef"}`)

		err := store.PutCheckpoint(ctx, batchID, data)
		require.NoError(t, err)

		// Read back
		retrieved, err := store.Get(ctx, filepath.Join("checkpoints", batchID+".json"))
		require.NoError(t, err)
		assert.Equal(t, data, retrieved)

		// Attempting to overwrite existing checkpoint must fail (immutability)
		err = store.PutCheckpoint(ctx, batchID, []byte("overwriting-content"))
		assert.ErrorIs(t, err, archive.ErrObjectExists)
	})

	t.Run("put and get archive", func(t *testing.T) {
		batchID := "batch-test-002"
		data := []byte("{\"record_id\": \"1\"}\n{\"record_id\": \"2\"}\n")

		err := store.PutArchive(ctx, batchID, data)
		require.NoError(t, err)

		// Read back
		retrieved, err := store.Get(ctx, filepath.Join("archives", batchID+".jsonl"))
		require.NoError(t, err)
		assert.Equal(t, data, retrieved)

		// Overwrite fails
		err = store.PutArchive(ctx, batchID, []byte("overwrite"))
		assert.ErrorIs(t, err, archive.ErrObjectExists)
	})

	t.Run("directory traversal prevented", func(t *testing.T) {
		_, err := store.Get(ctx, "../outside.txt")
		assert.ErrorIs(t, err, archive.ErrInvalidKey)
	})
}
