package store

import (
	"encoding/json"
	"time"
)

// Batch represents an audit_batches row.
type Batch struct {
	ID                 string    `json:"id"`
	StartedAt          time.Time `json:"started_at"`
	ClosedAt           time.Time `json:"closed_at"`
	EventCount         int       `json:"event_count"`
	MerkleRoot         []byte    `json:"merkle_root"`
	Signature          []byte    `json:"signature"`
	KeyVersion         string    `json:"key_version"`
	BinlogFile         string    `json:"binlog_file"`
	BinlogPosition     uint32    `json:"binlog_position"`
	Status             string    `json:"status"` // 'open', 'closed', 'signed', 'archived', 'purged'
	WORMObjectKey      *string   `json:"worm_object_key,omitempty"`
	IsBootstrap        bool      `json:"is_bootstrap"`
	BootstrapTableName *string   `json:"bootstrap_table_name,omitempty"`
}

// Record represents an audit_records row.
type Record struct {
	ID              string          `json:"id"`
	BatchID         string          `json:"batch_id"`
	TableName       string          `json:"table_name"`
	PrimaryKey      json.RawMessage `json:"primary_key"`
	EventType       string          `json:"event_type"` // 'INSERT', 'UPDATE', 'DELETE'
	BeforeImage     json.RawMessage `json:"before_image,omitempty"`
	AfterImage      json.RawMessage `json:"after_image,omitempty"`
	ActorUserID     *string         `json:"actor_user_id,omitempty"`
	ActorType       string          `json:"actor_type"` // 'USER', 'SYSTEM', 'UNATTRIBUTED'
	TransactionID   string          `json:"transaction_id"`
	SchemaVersion   string          `json:"schema_version"`
	CommittedAt     time.Time       `json:"committed_at"`
	MerkleLeafIndex int             `json:"merkle_leaf_index"`
}

// WORMIndexEntry represents an audit_worm_index row.
type WORMIndexEntry struct {
	BatchID              string     `json:"batch_id"`
	WORMObjectKey        string     `json:"worm_object_key"`
	TieredAt             time.Time  `json:"tiered_at"`
	PurgedFromPostgresAt *time.Time `json:"purged_from_postgres_at,omitempty"`
}
