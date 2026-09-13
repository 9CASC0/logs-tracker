package config

import (
	"testing"
	"time"

	"auditlogd/internal/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigManager(t *testing.T) {
	mgr := NewManager()

	// Initially empty
	assert.False(t, mgr.IsAudited("users"))
	_, ok := mgr.GetTableConfig("users")
	assert.False(t, ok)

	// Set config manually
	cfg := TableConfig{
		TableName:          "users",
		Enabled:            true,
		UnattributedPolicy: "alert",
		SeverityTier:       "critical",
		EncryptedColumns:   []string{"email", "ssn"},
		BootstrapRequired:  false,
		BootstrapStatus:    "complete",
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	mgr.SetTableConfig(cfg)

	assert.True(t, mgr.IsAudited("users"))
	retrieved, ok := mgr.GetTableConfig("users")
	require.True(t, ok)
	assert.Equal(t, "critical", retrieved.SeverityTier)
	assert.Equal(t, []string{"email", "ssn"}, retrieved.EncryptedColumns)

	all := mgr.GetAllConfigs()
	assert.Len(t, all, 1)

	// Test dynamic hot-reload from CDC event on _audit_config
	changeEvt := source.RowChange{
		Table:  "_audit_config",
		Action: source.EventTypeInsert,
		AfterImage: map[string]interface{}{
			"table_name":          "payments",
			"enabled":             int64(1),
			"unattributed_policy": "alert",
			"severity_tier":       "critical",
			"encrypted_columns":   `["card_number", "cvv"]`,
			"bootstrap_required":  int64(1),
			"bootstrap_status":    "not_started",
		},
	}

	err := mgr.HandleBinlogEvent(changeEvt)
	require.NoError(t, err)

	assert.True(t, mgr.IsAudited("payments"))
	payCfg, ok := mgr.GetTableConfig("payments")
	require.True(t, ok)
	assert.True(t, payCfg.Enabled)
	assert.True(t, payCfg.BootstrapRequired)
	assert.Equal(t, []string{"card_number", "cvv"}, payCfg.EncryptedColumns)

	// Test disabling table via CDC update
	updateEvt := source.RowChange{
		Table:  "_audit_config",
		Action: source.EventTypeUpdate,
		AfterImage: map[string]interface{}{
			"table_name":          "payments",
			"enabled":             int64(0),
			"unattributed_policy": "tolerate",
			"severity_tier":       "normal",
			"encrypted_columns":   "[]",
		},
	}
	err = mgr.HandleBinlogEvent(updateEvt)
	require.NoError(t, err)

	assert.False(t, mgr.IsAudited("payments"))
	disabledCfg, ok := mgr.GetTableConfig("payments")
	require.True(t, ok)
	assert.False(t, disabledCfg.Enabled)

	// Test deleting table via CDC delete
	deleteEvt := source.RowChange{
		Table:  "_audit_config",
		Action: source.EventTypeDelete,
		BeforeImage: map[string]interface{}{
			"table_name": "payments",
		},
	}
	err = mgr.HandleBinlogEvent(deleteEvt)
	require.NoError(t, err)

	_, ok = mgr.GetTableConfig("payments")
	assert.False(t, ok)
}
