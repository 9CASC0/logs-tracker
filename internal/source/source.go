package source

import (
	"context"
	"time"
)

// EventType represents the kind of database change.
type EventType string

const (
	EventTypeInsert EventType = "INSERT"
	EventTypeUpdate EventType = "UPDATE"
	EventTypeDelete EventType = "DELETE"
	EventTypeDDL    EventType = "DDL"
)

// Position models the binlog position coordinates.
type Position struct {
	File     string `json:"file"`
	Position uint32 `json:"position"`
	GTID     string `json:"gtid,omitempty"`
}

// RowChange captures a single row modification within a transaction.
type RowChange struct {
	Schema      string                 `json:"schema"`
	Table       string                 `json:"table"`
	Action      EventType              `json:"action"`
	BeforeImage map[string]interface{} `json:"before_image,omitempty"`
	AfterImage  map[string]interface{} `json:"after_image,omitempty"`
}

// Transaction represents a grouped set of row changes committed together.
type Transaction struct {
	TransactionID string      `json:"transaction_id"`
	Position      Position    `json:"position"`
	CommittedAt   time.Time   `json:"committed_at"`
	Changes       []RowChange `json:"changes"`
	DDLStatement  string      `json:"ddl_statement,omitempty"`
}

// ChangeSource is the adapter interface for CDC capture.
// Allows future sources (PostgreSQL logical replication, MongoDB change streams)
// to be swapped in without modifying downstream stages.
type ChangeSource interface {
	Stream(ctx context.Context) (<-chan Transaction, error)
	Checkpoint() Position
	ResumeFrom(pos Position) error
	Close() error
}
