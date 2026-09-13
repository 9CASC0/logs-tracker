package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"auditlogd/internal/merkle"
)

var (
	ErrNotFound = errors.New("record not found")
)

// Store defines repository operations for the audit system.
type Store interface {
	CreateBatch(ctx context.Context, batch *Batch, records []*Record) error
	GetBatch(ctx context.Context, id string) (*Batch, error)
	UpdateBatchStatus(ctx context.Context, id string, status string, wormObjectKey *string) error
	GetLatestCheckpoint(ctx context.Context) (file string, pos uint32, err error)
	GetBatchesForTiering(ctx context.Context, olderThan time.Time) ([]*Batch, error)
	ListBatches(ctx context.Context, limit int, offset int) ([]*Batch, error)

	GetRecord(ctx context.Context, id string) (*Record, error)
	GetRecordsByBatchID(ctx context.Context, batchID string) ([]*Record, error)
	GetRecordsByTableAndPK(ctx context.Context, table string, primaryKey json.RawMessage, limit int, offset int) ([]*Record, error)
	DeleteRecordsByBatchID(ctx context.Context, batchID string) error

	InsertWORMIndex(ctx context.Context, entry *WORMIndexEntry) error
	GetWORMIndex(ctx context.Context, batchID string) (*WORMIndexEntry, error)

	GetRecordForVerification(ctx context.Context, recordID string) (*merkle.RecordCanonicalPayload, *merkle.BatchVerificationData, error)
}

// PostgresStore implements Store using a PostgreSQL database.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore creates a PostgresStore.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// CreateBatch persists a batch and its records transactionally.
func (s *PostgresStore) CreateBatch(ctx context.Context, batch *Batch, records []*Record) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	batchQuery := `
		INSERT INTO audit_batches (
			id, started_at, closed_at, event_count, merkle_root, signature,
			key_version, binlog_file, binlog_position, status, worm_object_key,
			is_bootstrap, bootstrap_table_name
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	_, err = tx.ExecContext(ctx, batchQuery,
		batch.ID, batch.StartedAt, batch.ClosedAt, batch.EventCount,
		batch.MerkleRoot, batch.Signature, batch.KeyVersion,
		batch.BinlogFile, batch.BinlogPosition, batch.Status,
		batch.WORMObjectKey, batch.IsBootstrap, batch.BootstrapTableName,
	)
	if err != nil {
		return fmt.Errorf("failed to insert audit_batches: %w", err)
	}

	recordQuery := `
		INSERT INTO audit_records (
			id, batch_id, table_name, primary_key, event_type,
			before_image, after_image, actor_user_id, actor_type,
			transaction_id, schema_version, committed_at, merkle_leaf_index
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	stmt, err := tx.PrepareContext(ctx, recordQuery)
	if err != nil {
		return fmt.Errorf("failed to prepare record insert stmt: %w", err)
	}
	defer stmt.Close()

	for _, r := range records {
		var beforeJSON, afterJSON *string
		if len(r.BeforeImage) > 0 {
			s := string(r.BeforeImage)
			beforeJSON = &s
		}
		if len(r.AfterImage) > 0 {
			s := string(r.AfterImage)
			afterJSON = &s
		}

		_, err = stmt.ExecContext(ctx,
			r.ID, r.BatchID, r.TableName, string(r.PrimaryKey), r.EventType,
			beforeJSON, afterJSON, r.ActorUserID, r.ActorType,
			r.TransactionID, r.SchemaVersion, r.CommittedAt, r.MerkleLeafIndex,
		)
		if err != nil {
			return fmt.Errorf("failed to insert audit_record (%s): %w", r.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}
	return nil
}

// GetBatch retrieves a batch by id.
func (s *PostgresStore) GetBatch(ctx context.Context, id string) (*Batch, error) {
	query := `
		SELECT id, started_at, closed_at, event_count, merkle_root, signature,
		       key_version, binlog_file, binlog_position, status, worm_object_key,
		       is_bootstrap, bootstrap_table_name
		FROM audit_batches WHERE id = $1
	`
	row := s.db.QueryRowContext(ctx, query, id)
	var b Batch
	err := row.Scan(
		&b.ID, &b.StartedAt, &b.ClosedAt, &b.EventCount, &b.MerkleRoot, &b.Signature,
		&b.KeyVersion, &b.BinlogFile, &b.BinlogPosition, &b.Status, &b.WORMObjectKey,
		&b.IsBootstrap, &b.BootstrapTableName,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get batch: %w", err)
	}
	return &b, nil
}

// UpdateBatchStatus updates the status and optional worm object key of a batch.
func (s *PostgresStore) UpdateBatchStatus(ctx context.Context, id string, status string, wormObjectKey *string) error {
	query := `UPDATE audit_batches SET status = $1, worm_object_key = COALESCE($2, worm_object_key) WHERE id = $3`
	res, err := s.db.ExecContext(ctx, query, status, wormObjectKey, id)
	if err != nil {
		return fmt.Errorf("failed to update batch status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetLatestCheckpoint returns the binlog coordinates of the most recent committed batch.
func (s *PostgresStore) GetLatestCheckpoint(ctx context.Context) (string, uint32, error) {
	query := `SELECT binlog_file, binlog_position FROM audit_batches ORDER BY closed_at DESC LIMIT 1`
	var file string
	var pos uint32
	err := s.db.QueryRowContext(ctx, query).Scan(&file, &pos)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", 0, nil
		}
		return "", 0, fmt.Errorf("failed to get latest checkpoint: %w", err)
	}
	return file, pos, nil
}

// GetBatchesForTiering returns signed batches older than the cutoff timestamp.
func (s *PostgresStore) GetBatchesForTiering(ctx context.Context, olderThan time.Time) ([]*Batch, error) {
	query := `
		SELECT id, started_at, closed_at, event_count, merkle_root, signature,
		       key_version, binlog_file, binlog_position, status, worm_object_key,
		       is_bootstrap, bootstrap_table_name
		FROM audit_batches
		WHERE status = 'signed' AND closed_at < $1
		ORDER BY closed_at ASC
	`
	rows, err := s.db.QueryContext(ctx, query, olderThan)
	if err != nil {
		return nil, fmt.Errorf("failed to query batches for tiering: %w", err)
	}
	defer rows.Close()

	var batches []*Batch
	for rows.Next() {
		var b Batch
		err := rows.Scan(
			&b.ID, &b.StartedAt, &b.ClosedAt, &b.EventCount, &b.MerkleRoot, &b.Signature,
			&b.KeyVersion, &b.BinlogFile, &b.BinlogPosition, &b.Status, &b.WORMObjectKey,
			&b.IsBootstrap, &b.BootstrapTableName,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan batch: %w", err)
		}
		batches = append(batches, &b)
	}
	return batches, nil
}

// ListBatches returns a paginated list of batches.
func (s *PostgresStore) ListBatches(ctx context.Context, limit int, offset int) ([]*Batch, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `
		SELECT id, started_at, closed_at, event_count, merkle_root, signature,
		       key_version, binlog_file, binlog_position, status, worm_object_key,
		       is_bootstrap, bootstrap_table_name
		FROM audit_batches
		ORDER BY closed_at DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list batches: %w", err)
	}
	defer rows.Close()

	var batches []*Batch
	for rows.Next() {
		var b Batch
		err := rows.Scan(
			&b.ID, &b.StartedAt, &b.ClosedAt, &b.EventCount, &b.MerkleRoot, &b.Signature,
			&b.KeyVersion, &b.BinlogFile, &b.BinlogPosition, &b.Status, &b.WORMObjectKey,
			&b.IsBootstrap, &b.BootstrapTableName,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan batch: %w", err)
		}
		batches = append(batches, &b)
	}
	return batches, nil
}

// GetRecord retrieves an audit record by id.
func (s *PostgresStore) GetRecord(ctx context.Context, id string) (*Record, error) {
	query := `
		SELECT id, batch_id, table_name, primary_key, event_type,
		       before_image, after_image, actor_user_id, actor_type,
		       transaction_id, schema_version, committed_at, merkle_leaf_index
		FROM audit_records WHERE id = $1
	`
	row := s.db.QueryRowContext(ctx, query, id)
	var r Record
	var pkStr string
	var beforeStr, afterStr sql.NullString

	err := row.Scan(
		&r.ID, &r.BatchID, &r.TableName, &pkStr, &r.EventType,
		&beforeStr, &afterStr, &r.ActorUserID, &r.ActorType,
		&r.TransactionID, &r.SchemaVersion, &r.CommittedAt, &r.MerkleLeafIndex,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get record: %w", err)
	}
	r.PrimaryKey = json.RawMessage(pkStr)
	if beforeStr.Valid {
		r.BeforeImage = json.RawMessage(beforeStr.String)
	}
	if afterStr.Valid {
		r.AfterImage = json.RawMessage(afterStr.String)
	}
	return &r, nil
}

// GetRecordsByBatchID returns all records for a batch ordered by merkle_leaf_index.
func (s *PostgresStore) GetRecordsByBatchID(ctx context.Context, batchID string) ([]*Record, error) {
	query := `
		SELECT id, batch_id, table_name, primary_key, event_type,
		       before_image, after_image, actor_user_id, actor_type,
		       transaction_id, schema_version, committed_at, merkle_leaf_index
		FROM audit_records WHERE batch_id = $1
		ORDER BY merkle_leaf_index ASC
	`
	rows, err := s.db.QueryContext(ctx, query, batchID)
	if err != nil {
		return nil, fmt.Errorf("failed to query records by batch: %w", err)
	}
	defer rows.Close()

	var records []*Record
	for rows.Next() {
		var r Record
		var pkStr string
		var beforeStr, afterStr sql.NullString
		err := rows.Scan(
			&r.ID, &r.BatchID, &r.TableName, &pkStr, &r.EventType,
			&beforeStr, &afterStr, &r.ActorUserID, &r.ActorType,
			&r.TransactionID, &r.SchemaVersion, &r.CommittedAt, &r.MerkleLeafIndex,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan record: %w", err)
		}
		r.PrimaryKey = json.RawMessage(pkStr)
		if beforeStr.Valid {
			r.BeforeImage = json.RawMessage(beforeStr.String)
		}
		if afterStr.Valid {
			r.AfterImage = json.RawMessage(afterStr.String)
		}
		records = append(records, &r)
	}
	return records, nil
}

// GetRecordsByTableAndPK queries history for a given record.
func (s *PostgresStore) GetRecordsByTableAndPK(ctx context.Context, table string, primaryKey json.RawMessage, limit int, offset int) ([]*Record, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `
		SELECT id, batch_id, table_name, primary_key, event_type,
		       before_image, after_image, actor_user_id, actor_type,
		       transaction_id, schema_version, committed_at, merkle_leaf_index
		FROM audit_records
		WHERE table_name = $1 AND primary_key = $2
		ORDER BY committed_at DESC
		LIMIT $3 OFFSET $4
	`
	rows, err := s.db.QueryContext(ctx, query, table, string(primaryKey), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query records by table and pk: %w", err)
	}
	defer rows.Close()

	var records []*Record
	for rows.Next() {
		var r Record
		var pkStr string
		var beforeStr, afterStr sql.NullString
		err := rows.Scan(
			&r.ID, &r.BatchID, &r.TableName, &pkStr, &r.EventType,
			&beforeStr, &afterStr, &r.ActorUserID, &r.ActorType,
			&r.TransactionID, &r.SchemaVersion, &r.CommittedAt, &r.MerkleLeafIndex,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan record: %w", err)
		}
		r.PrimaryKey = json.RawMessage(pkStr)
		if beforeStr.Valid {
			r.BeforeImage = json.RawMessage(beforeStr.String)
		}
		if afterStr.Valid {
			r.AfterImage = json.RawMessage(afterStr.String)
		}
		records = append(records, &r)
	}
	return records, nil
}

// DeleteRecordsByBatchID purges records from Postgres after archival.
func (s *PostgresStore) DeleteRecordsByBatchID(ctx context.Context, batchID string) error {
	query := `DELETE FROM audit_records WHERE batch_id = $1`
	_, err := s.db.ExecContext(ctx, query, batchID)
	if err != nil {
		return fmt.Errorf("failed to purge records for batch %s: %w", batchID, err)
	}
	return nil
}

// InsertWORMIndex records that a batch has been archived in WORM storage.
func (s *PostgresStore) InsertWORMIndex(ctx context.Context, entry *WORMIndexEntry) error {
	query := `
		INSERT INTO audit_worm_index (batch_id, worm_object_key, tiered_at, purged_from_postgres_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (batch_id) DO UPDATE SET
			worm_object_key = EXCLUDED.worm_object_key,
			tiered_at = EXCLUDED.tiered_at,
			purged_from_postgres_at = EXCLUDED.purged_from_postgres_at
	`
	_, err := s.db.ExecContext(ctx, query, entry.BatchID, entry.WORMObjectKey, entry.TieredAt, entry.PurgedFromPostgresAt)
	if err != nil {
		return fmt.Errorf("failed to insert audit_worm_index: %w", err)
	}
	return nil
}

// GetWORMIndex returns the WORM index metadata for a batch.
func (s *PostgresStore) GetWORMIndex(ctx context.Context, batchID string) (*WORMIndexEntry, error) {
	query := `SELECT batch_id, worm_object_key, tiered_at, purged_from_postgres_at FROM audit_worm_index WHERE batch_id = $1`
	var entry WORMIndexEntry
	err := s.db.QueryRowContext(ctx, query, batchID).Scan(
		&entry.BatchID, &entry.WORMObjectKey, &entry.TieredAt, &entry.PurgedFromPostgresAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get worm index: %w", err)
	}
	return &entry, nil
}

// GetRecordForVerification loads record and batch Merkle details to perform verification.
func (s *PostgresStore) GetRecordForVerification(ctx context.Context, recordID string) (*merkle.RecordCanonicalPayload, *merkle.BatchVerificationData, error) {
	rec, err := s.GetRecord(ctx, recordID)
	if err != nil {
		return nil, nil, err
	}

	batch, err := s.GetBatch(ctx, rec.BatchID)
	if err != nil {
		return nil, nil, err
	}

	allRecords, err := s.GetRecordsByBatchID(ctx, rec.BatchID)
	if err != nil {
		return nil, nil, err
	}

	var allLeaves [][]byte
	for _, r := range allRecords {
		p := merkle.RecordCanonicalPayload{
			ID:              r.ID,
			BatchID:         r.BatchID,
			TableName:       r.TableName,
			PrimaryKey:      r.PrimaryKey,
			EventType:       r.EventType,
			BeforeImage:     r.BeforeImage,
			AfterImage:      r.AfterImage,
			ActorUserID:     r.ActorUserID,
			ActorType:       r.ActorType,
			TransactionID:   r.TransactionID,
			SchemaVersion:   r.SchemaVersion,
			CommittedAt:     r.CommittedAt.UTC().Format(time.RFC3339Nano),
			MerkleLeafIndex: r.MerkleLeafIndex,
		}
		leafHash, err := merkle.ComputeRecordLeafHash(p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compute leaf hash for record %s: %w", r.ID, err)
		}
		allLeaves = append(allLeaves, leafHash)
	}

	canonicalPayload := &merkle.RecordCanonicalPayload{
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

	batchData := &merkle.BatchVerificationData{
		BatchID:       batch.ID,
		MerkleRoot:    batch.MerkleRoot,
		Signature:     batch.Signature,
		KeyVersion:    batch.KeyVersion,
		AllLeafHashes: allLeaves,
	}

	return canonicalPayload, batchData, nil
}

// MemoryStore provides a thread-safe in-memory Store implementation for unit tests and local mock testing.
type MemoryStore struct {
	mu        sync.RWMutex
	batches   map[string]*Batch
	records   map[string]*Record
	wormIndex map[string]*WORMIndexEntry
}

// NewMemoryStore creates an initialized MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		batches:   make(map[string]*Batch),
		records:   make(map[string]*Record),
		wormIndex: make(map[string]*WORMIndexEntry),
	}
}

func (m *MemoryStore) CreateBatch(ctx context.Context, batch *Batch, records []*Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	bCopy := *batch
	m.batches[batch.ID] = &bCopy
	for _, r := range records {
		rCopy := *r
		m.records[r.ID] = &rCopy
	}
	return nil
}

func (m *MemoryStore) GetBatch(ctx context.Context, id string) (*Batch, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	b, ok := m.batches[id]
	if !ok {
		return nil, ErrNotFound
	}
	bCopy := *b
	return &bCopy, nil
}

func (m *MemoryStore) UpdateBatchStatus(ctx context.Context, id string, status string, wormObjectKey *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	b, ok := m.batches[id]
	if !ok {
		return ErrNotFound
	}
	b.Status = status
	if wormObjectKey != nil {
		b.WORMObjectKey = wormObjectKey
	}
	return nil
}

func (m *MemoryStore) GetLatestCheckpoint(ctx context.Context) (string, uint32, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var latest *Batch
	for _, b := range m.batches {
		if latest == nil || b.ClosedAt.After(latest.ClosedAt) {
			latest = b
		}
	}
	if latest == nil {
		return "", 0, nil
	}
	return latest.BinlogFile, latest.BinlogPosition, nil
}

func (m *MemoryStore) GetBatchesForTiering(ctx context.Context, olderThan time.Time) ([]*Batch, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var res []*Batch
	for _, b := range m.batches {
		if b.Status == "signed" && b.ClosedAt.Before(olderThan) {
			bCopy := *b
			res = append(res, &bCopy)
		}
	}
	return res, nil
}

func (m *MemoryStore) ListBatches(ctx context.Context, limit int, offset int) ([]*Batch, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var res []*Batch
	for _, b := range m.batches {
		bCopy := *b
		res = append(res, &bCopy)
	}
	return res, nil
}

func (m *MemoryStore) GetRecord(ctx context.Context, id string) (*Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	r, ok := m.records[id]
	if !ok {
		return nil, ErrNotFound
	}
	rCopy := *r
	return &rCopy, nil
}

func (m *MemoryStore) GetRecordsByBatchID(ctx context.Context, batchID string) ([]*Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var res []*Record
	for _, r := range m.records {
		if r.BatchID == batchID {
			rCopy := *r
			res = append(res, &rCopy)
		}
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].MerkleLeafIndex < res[j].MerkleLeafIndex
	})
	return res, nil
}

func (m *MemoryStore) GetRecordsByTableAndPK(ctx context.Context, table string, primaryKey json.RawMessage, limit int, offset int) ([]*Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var res []*Record
	pkStr := string(primaryKey)
	for _, r := range m.records {
		if r.TableName == table && string(r.PrimaryKey) == pkStr {
			rCopy := *r
			res = append(res, &rCopy)
		}
	}
	return res, nil
}

func (m *MemoryStore) DeleteRecordsByBatchID(ctx context.Context, batchID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, r := range m.records {
		if r.BatchID == batchID {
			delete(m.records, id)
		}
	}
	return nil
}

func (m *MemoryStore) InsertWORMIndex(ctx context.Context, entry *WORMIndexEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	eCopy := *entry
	m.wormIndex[entry.BatchID] = &eCopy
	return nil
}

func (m *MemoryStore) GetWORMIndex(ctx context.Context, batchID string) (*WORMIndexEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.wormIndex[batchID]
	if !ok {
		return nil, ErrNotFound
	}
	eCopy := *entry
	return &eCopy, nil
}

func (m *MemoryStore) GetRecordForVerification(ctx context.Context, recordID string) (*merkle.RecordCanonicalPayload, *merkle.BatchVerificationData, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec, ok := m.records[recordID]
	if !ok {
		return nil, nil, ErrNotFound
	}

	batch, ok := m.batches[rec.BatchID]
	if !ok {
		return nil, nil, ErrNotFound
	}

	var allRecords []*Record
	for _, r := range m.records {
		if r.BatchID == rec.BatchID {
			allRecords = append(allRecords, r)
		}
	}
	sort.Slice(allRecords, func(i, j int) bool {
		return allRecords[i].MerkleLeafIndex < allRecords[j].MerkleLeafIndex
	})

	var allLeaves [][]byte
	for _, r := range allRecords {
		p := merkle.RecordCanonicalPayload{
			ID:              r.ID,
			BatchID:         r.BatchID,
			TableName:       r.TableName,
			PrimaryKey:      r.PrimaryKey,
			EventType:       r.EventType,
			BeforeImage:     r.BeforeImage,
			AfterImage:      r.AfterImage,
			ActorUserID:     r.ActorUserID,
			ActorType:       r.ActorType,
			TransactionID:   r.TransactionID,
			SchemaVersion:   r.SchemaVersion,
			CommittedAt:     r.CommittedAt.UTC().Format(time.RFC3339Nano),
			MerkleLeafIndex: r.MerkleLeafIndex,
		}
		leafHash, err := merkle.ComputeRecordLeafHash(p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compute leaf hash for record %s: %w", r.ID, err)
		}
		allLeaves = append(allLeaves, leafHash)
	}

	canonicalPayload := &merkle.RecordCanonicalPayload{
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

	batchData := &merkle.BatchVerificationData{
		BatchID:       batch.ID,
		MerkleRoot:    batch.MerkleRoot,
		Signature:     batch.Signature,
		KeyVersion:    batch.KeyVersion,
		AllLeafHashes: allLeaves,
	}

	return canonicalPayload, batchData, nil
}
