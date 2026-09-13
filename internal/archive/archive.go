package archive

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrObjectExists   = errors.New("archive object already exists and is immutable")
	ErrObjectNotFound = errors.New("archive object not found")
	ErrInvalidKey     = errors.New("invalid object key")
)

// ArchiveStore defines the interface for durable WORM storage.
type ArchiveStore interface {
	PutCheckpoint(ctx context.Context, batchID string, data []byte) error
	PutArchive(ctx context.Context, batchID string, data []byte) error
	Get(ctx context.Context, objectKey string) ([]byte, error)
	ListCheckpoints(ctx context.Context) ([]string, error)
}

// LocalDirArchiveStore implements ArchiveStore using a local write-once directory.
type LocalDirArchiveStore struct {
	baseDir string
}

// NewLocalDirArchiveStore creates and initializes the checkpoints/ and archives/ directories.
func NewLocalDirArchiveStore(baseDir string) (*LocalDirArchiveStore, error) {
	checkpointsDir := filepath.Join(baseDir, "checkpoints")
	archivesDir := filepath.Join(baseDir, "archives")

	if err := os.MkdirAll(checkpointsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create checkpoints directory: %w", err)
	}
	if err := os.MkdirAll(archivesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create archives directory: %w", err)
	}

	return &LocalDirArchiveStore{baseDir: baseDir}, nil
}

// PutCheckpoint writes a batch checkpoint file and marks it read-only (0444).
func (s *LocalDirArchiveStore) PutCheckpoint(ctx context.Context, batchID string, data []byte) error {
	filename := fmt.Sprintf("%s.json", batchID)
	relPath := filepath.Join("checkpoints", filename)
	return s.writeImmutable(relPath, data)
}

// PutArchive writes a tiered batch archive file (.jsonl) and marks it read-only (0444).
func (s *LocalDirArchiveStore) PutArchive(ctx context.Context, batchID string, data []byte) error {
	filename := fmt.Sprintf("%s.jsonl", batchID)
	relPath := filepath.Join("archives", filename)
	return s.writeImmutable(relPath, data)
}

// writeImmutable safely writes data to path and chmods it read-only (0444).
// Rejects if the object already exists.
func (s *LocalDirArchiveStore) writeImmutable(relPath string, data []byte) error {
	targetPath := filepath.Join(s.baseDir, relPath)

	// Check if already exists
	if _, err := os.Stat(targetPath); err == nil {
		return fmt.Errorf("%w: %s", ErrObjectExists, relPath)
	}

	// Write to temp file in same directory first
	dir := filepath.Dir(targetPath)
	tempFile, err := os.CreateTemp(dir, "worm-tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp archive file: %w", err)
	}
	tempName := tempFile.Name()

	cleanUp := true
	defer func() {
		if cleanUp {
			_ = os.Remove(tempName)
		}
	}()

	if _, err := tempFile.Write(data); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to write archive data: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to sync archive data: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Rename temp file to target path
	if err := os.Rename(tempName, targetPath); err != nil {
		return fmt.Errorf("failed to commit immutable archive object: %w", err)
	}
	cleanUp = false

	// Make read-only (best-effort immutability: 0444)
	if err := os.Chmod(targetPath, 0444); err != nil {
		return fmt.Errorf("failed to set read-only permissions on %s: %w", targetPath, err)
	}

	return nil
}

// Get reads an object by its relative key (e.g. "checkpoints/<batch_id>.json").
func (s *LocalDirArchiveStore) Get(ctx context.Context, objectKey string) ([]byte, error) {
	// Sanitize against directory traversal
	cleanKey := filepath.Clean(objectKey)
	if strings.Contains(cleanKey, "..") || filepath.IsAbs(cleanKey) {
		return nil, ErrInvalidKey
	}

	targetPath := filepath.Join(s.baseDir, cleanKey)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrObjectNotFound
		}
		return nil, fmt.Errorf("failed to read archive object: %w", err)
	}

	return data, nil
}

// ListCheckpoints returns all available checkpoint object keys.
func (s *LocalDirArchiveStore) ListCheckpoints(ctx context.Context) ([]string, error) {
	dir := filepath.Join(s.baseDir, "checkpoints")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoints dir: %w", err)
	}

	var keys []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			keys = append(keys, filepath.Join("checkpoints", entry.Name()))
		}
	}
	return keys, nil
}
