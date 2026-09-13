package batch

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"auditlogd/internal/alerting"
	"auditlogd/internal/archive"
	"auditlogd/internal/merkle"
	"auditlogd/internal/signing"
	"auditlogd/internal/source"
	"auditlogd/internal/store"
	"github.com/google/uuid"
)

// CheckpointObject represents the signed WORM checkpoint JSON artifact.
type CheckpointObject struct {
	BatchID        string    `json:"batch_id"`
	StartedAt      time.Time `json:"started_at"`
	ClosedAt       time.Time `json:"closed_at"`
	EventCount     int       `json:"event_count"`
	MerkleRoot     string    `json:"merkle_root"` // hex
	Signature      string    `json:"signature"`   // hex
	KeyVersion     string    `json:"key_version"`
	BinlogFile     string    `json:"binlog_file"`
	BinlogPosition uint32    `json:"binlog_position"`
	IsBootstrap    bool      `json:"is_bootstrap"`
	BootstrapTable string    `json:"bootstrap_table,omitempty"`
}

// Config holds runtime-tunable batch parameters.
type Config struct {
	MaxInterval time.Duration
	MaxEvents   int
}

// Batcher buffers records, builds Merkle trees, signs roots, and persists checkpoints.
type Batcher struct {
	mu             sync.Mutex
	cfg            Config
	signer         signing.Signer
	store          store.Store
	archiveStore   archive.ArchiveStore
	alertDispatcher *alerting.Dispatcher

	currentBatchID string
	startedAt      time.Time
	records        []*store.Record
	alertsQueue    []alerting.Alert
	lastPosition   source.Position
	timer          *time.Timer

	isBootstrap    bool
	bootstrapTable string

	onBatchClosed func(batch *store.Batch)
}

// NewBatcher initializes a batch buffer.
func NewBatcher(
	cfg Config,
	signer signing.Signer,
	st store.Store,
	arch archive.ArchiveStore,
	disp *alerting.Dispatcher,
) *Batcher {
	if cfg.MaxInterval <= 0 {
		cfg.MaxInterval = 60 * time.Second
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 5000
	}

	b := &Batcher{
		cfg:             cfg,
		signer:          signer,
		store:           st,
		archiveStore:    arch,
		alertDispatcher: disp,
		currentBatchID:  uuid.New().String(),
		startedAt:       time.Now().UTC(),
	}
	b.resetTimer()
	return b
}

// SetBatchClosedCallback registers a hook called whenever a batch is closed.
func (b *Batcher) SetBatchClosedCallback(fn func(batch *store.Batch)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.onBatchClosed = fn
}

// SetBootstrapMode configures the current batch buffer for a bootstrap snapshot.
func (b *Batcher) SetBootstrapMode(isBootstrap bool, tableName string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.isBootstrap = isBootstrap
	b.bootstrapTable = tableName
}

func (b *Batcher) resetTimer() {
	if b.timer != nil {
		b.timer.Stop()
	}
	b.timer = time.AfterFunc(b.cfg.MaxInterval, func() {
		_ = b.CloseCurrentBatch(context.Background())
	})
}

// AddRecord adds a record to the currently open batch and closes if count threshold is reached.
func (b *Batcher) AddRecord(ctx context.Context, record *store.Record, pos source.Position) error {
	b.mu.Lock()

	record.BatchID = b.currentBatchID
	record.MerkleLeafIndex = len(b.records)
	b.records = append(b.records, record)
	b.lastPosition = pos

	shouldClose := len(b.records) >= b.cfg.MaxEvents
	b.mu.Unlock()

	if shouldClose {
		return b.CloseCurrentBatch(ctx)
	}
	return nil
}

// QueueAlert adds an alert to be dispatched when the batch is closed.
func (b *Batcher) QueueAlert(alert alerting.Alert) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.alertsQueue = append(b.alertsQueue, alert)
}

// CloseCurrentBatch closes the current batch, builds Merkle tree, signs root, and persists.
func (b *Batcher) CloseCurrentBatch(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.records) == 0 {
		// Nothing to close, refresh start time and reset timer
		b.startedAt = time.Now().UTC()
		b.resetTimer()
		return nil
	}

	batchID := b.currentBatchID
	records := b.records
	closedAt := time.Now().UTC()
	startedAt := b.startedAt
	pos := b.lastPosition
	isBoot := b.isBootstrap
	bootTable := b.bootstrapTable
	alerts := b.alertsQueue

	// 1. Build Merkle tree over records
	var leafHashes [][]byte
	for _, rec := range records {
		p := merkle.RecordCanonicalPayload{
			ID:              rec.ID,
			BatchID:         rec.BatchID,
			TableName:       rec.TableName,
			PrimaryKey:      rec.PrimaryKey,
			EventType:       rec.EventType,
			BeforeImage:     rec.BeforeImage,
			AfterImage:      rec.AfterImage,
			ActorUserID:     rec.ActorUserID,
			ActorType:       rec.ActorType,
			TransactionID:   rec.TransactionID,
			SchemaVersion:   rec.SchemaVersion,
			CommittedAt:     rec.CommittedAt.UTC().Format(time.RFC3339Nano),
			MerkleLeafIndex: rec.MerkleLeafIndex,
		}
		lh, err := merkle.ComputeRecordLeafHash(p)
		if err != nil {
			return fmt.Errorf("failed to compute record leaf hash: %w", err)
		}
		leafHashes = append(leafHashes, lh)
	}

	tree, err := merkle.BuildTree(leafHashes)
	if err != nil {
		return fmt.Errorf("failed to build merkle tree: %w", err)
	}
	root := tree.Root()

	// 2. Sign only the Merkle root
	sig, keyVer, err := b.signer.Sign(ctx, root)
	if err != nil {
		return fmt.Errorf("failed to sign merkle root: %w", err)
	}

	wormKey := fmt.Sprintf("checkpoints/%s.json", batchID)

	var bootTablePtr *string
	if bootTable != "" {
		bootTablePtr = &bootTable
	}

	batchRecord := &store.Batch{
		ID:                 batchID,
		StartedAt:          startedAt,
		ClosedAt:           closedAt,
		EventCount:         len(records),
		MerkleRoot:         root,
		Signature:          sig,
		KeyVersion:         keyVer,
		BinlogFile:         pos.File,
		BinlogPosition:     pos.Position,
		Status:             "signed",
		WORMObjectKey:      &wormKey,
		IsBootstrap:        isBoot,
		BootstrapTableName: bootTablePtr,
	}

	// 3. Persist batch and records to store (Postgres)
	if err := b.store.CreateBatch(ctx, batchRecord, records); err != nil {
		return fmt.Errorf("failed to persist batch in store: %w", err)
	}

	// 4. Write signed checkpoint to WORM archive store
	chkObj := CheckpointObject{
		BatchID:        batchID,
		StartedAt:      startedAt,
		ClosedAt:       closedAt,
		EventCount:     len(records),
		MerkleRoot:     hex.EncodeToString(root),
		Signature:      hex.EncodeToString(sig),
		KeyVersion:     keyVer,
		BinlogFile:     pos.File,
		BinlogPosition: pos.Position,
		IsBootstrap:    isBoot,
		BootstrapTable: bootTable,
	}
	chkBytes, err := json.MarshalIndent(chkObj, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint object: %w", err)
	}

	if err := b.archiveStore.PutCheckpoint(ctx, batchID, chkBytes); err != nil {
		return fmt.Errorf("failed to write checkpoint to WORM storage: %w", err)
	}

	// 5. Fire queued alerts
	if b.alertDispatcher != nil {
		for _, a := range alerts {
			_, _ = b.alertDispatcher.Trigger(ctx, a.Trigger, a.Severity, a.TableName, a.RecordID, a.TransactionID, a.Message)
		}
	}

	if b.onBatchClosed != nil {
		b.onBatchClosed(batchRecord)
	}

	// Reset for next batch
	b.currentBatchID = uuid.New().String()
	b.startedAt = time.Now().UTC()
	b.records = nil
	b.alertsQueue = nil
	b.isBootstrap = false
	b.bootstrapTable = ""
	b.resetTimer()

	return nil
}

// Flush closes the currently open batch immediately.
func (b *Batcher) Flush(ctx context.Context) error {
	return b.CloseCurrentBatch(ctx)
}

// CurrentEventCount returns the number of records currently buffered in the active batch.
func (b *Batcher) CurrentEventCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.records)
}

// Close gracefully stops the batcher timer and flushes any pending records.
func (b *Batcher) Close(ctx context.Context) error {
	b.mu.Lock()
	if b.timer != nil {
		b.timer.Stop()
	}
	b.mu.Unlock()
	return b.CloseCurrentBatch(ctx)
}
