package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"auditlogd/internal/source"
)

// TableConfig represents the audit configuration for a single table.
type TableConfig struct {
	TableName          string    `json:"table_name"`
	Enabled            bool      `json:"enabled"`
	UnattributedPolicy string    `json:"unattributed_policy"` // "tolerate", "alert"
	SeverityTier       string    `json:"severity_tier"`       // "normal", "critical"
	EncryptedColumns   []string  `json:"encrypted_columns"`
	BootstrapRequired  bool      `json:"bootstrap_required"`
	BootstrapStatus    string    `json:"bootstrap_status"` // "not_started", "in_progress", "complete"
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// Manager holds and updates audit table configurations in memory.
type Manager struct {
	mu     sync.RWMutex
	tables map[string]TableConfig
}

// NewManager initializes an empty configuration manager.
func NewManager() *Manager {
	return &Manager{
		tables: make(map[string]TableConfig),
	}
}

// SetTableConfig manually adds or updates a table configuration.
func (m *Manager) SetTableConfig(cfg TableConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tables[cfg.TableName] = cfg
}

// GetTableConfig retrieves the audit configuration for a table.
func (m *Manager) GetTableConfig(tableName string) (TableConfig, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg, ok := m.tables[tableName]
	return cfg, ok
}

// GetAllConfigs returns a copy of all active table configurations.
func (m *Manager) GetAllConfigs() []TableConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]TableConfig, 0, len(m.tables))
	for _, cfg := range m.tables {
		res = append(res, cfg)
	}
	return res
}

// IsAudited checks if a table is currently enabled for auditing.
func (m *Manager) IsAudited(tableName string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg, ok := m.tables[tableName]
	return ok && cfg.Enabled
}

// LoadFromDB initialises the in-memory cache by reading MySQL's _audit_config table.
func (m *Manager) LoadFromDB(ctx context.Context, db *sql.DB) error {
	query := `
		SELECT table_name, enabled, unattributed_policy, severity_tier,
		       encrypted_columns, bootstrap_required, bootstrap_status,
		       created_at, updated_at
		FROM _audit_config
	`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query _audit_config: %w", err)
	}
	defer rows.Close()

	m.mu.Lock()
	defer m.mu.Unlock()

	for rows.Next() {
		var cfg TableConfig
		var encColsRaw string
		err := rows.Scan(
			&cfg.TableName, &cfg.Enabled, &cfg.UnattributedPolicy, &cfg.SeverityTier,
			&encColsRaw, &cfg.BootstrapRequired, &cfg.BootstrapStatus,
			&cfg.CreatedAt, &cfg.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to scan _audit_config row: %w", err)
		}

		var cols []string
		if encColsRaw != "" {
			_ = json.Unmarshal([]byte(encColsRaw), &cols)
		}
		cfg.EncryptedColumns = cols
		m.tables[cfg.TableName] = cfg
	}

	return nil
}

// HandleBinlogEvent updates the config manager dynamically when CDC detects changes on _audit_config.
func (m *Manager) HandleBinlogEvent(change source.RowChange) error {
	if change.Table != "_audit_config" {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	switch change.Action {
	case source.EventTypeInsert, source.EventTypeUpdate:
		row := change.AfterImage
		if row == nil {
			return nil
		}
		cfg := parseConfigFromMap(row)
		m.tables[cfg.TableName] = cfg

	case source.EventTypeDelete:
		row := change.BeforeImage
		if row == nil {
			return nil
		}
		tableName, _ := row["table_name"].(string)
		if tableName != "" {
			delete(m.tables, tableName)
		}
	}

	return nil
}

// Helper to convert dynamic map to TableConfig.
func parseConfigFromMap(row map[string]interface{}) TableConfig {
	var cfg TableConfig
	if v, ok := row["table_name"].(string); ok {
		cfg.TableName = v
	}
	if v, ok := row["enabled"].(bool); ok {
		cfg.Enabled = v
	} else if v, ok := row["enabled"].(int64); ok {
		cfg.Enabled = v == 1
	}
	if v, ok := row["unattributed_policy"].(string); ok {
		cfg.UnattributedPolicy = v
	} else {
		cfg.UnattributedPolicy = "tolerate"
	}
	if v, ok := row["severity_tier"].(string); ok {
		cfg.SeverityTier = v
	} else {
		cfg.SeverityTier = "normal"
	}
	if v, ok := row["bootstrap_required"].(bool); ok {
		cfg.BootstrapRequired = v
	} else if v, ok := row["bootstrap_required"].(int64); ok {
		cfg.BootstrapRequired = v == 1
	}
	if v, ok := row["bootstrap_status"].(string); ok {
		cfg.BootstrapStatus = v
	} else {
		cfg.BootstrapStatus = "not_started"
	}

	// Parse encrypted_columns
	if rawCols, ok := row["encrypted_columns"]; ok {
		switch c := rawCols.(type) {
		case string:
			_ = json.Unmarshal([]byte(c), &cfg.EncryptedColumns)
		case []byte:
			_ = json.Unmarshal(c, &cfg.EncryptedColumns)
		case []interface{}:
			for _, item := range c {
				if s, ok := item.(string); ok {
					cfg.EncryptedColumns = append(cfg.EncryptedColumns, s)
				}
			}
		}
	}

	return cfg
}
