package attribution_test

import (
	"testing"
	"time"

	"auditlogd/internal/attribution"
	"auditlogd/internal/config"
	"auditlogd/internal/source"
	"github.com/stretchr/testify/assert"
)

func TestAttributionCorrelator(t *testing.T) {
	cfgMgr := config.NewManager()
	cfgMgr.SetTableConfig(config.TableConfig{
		TableName:          "orders",
		Enabled:            true,
		UnattributedPolicy: "tolerate",
		SeverityTier:       "normal",
	})
	cfgMgr.SetTableConfig(config.TableConfig{
		TableName:          "payments",
		Enabled:            true,
		UnattributedPolicy: "alert",
		SeverityTier:       "critical",
	})
	cfgMgr.SetTableConfig(config.TableConfig{
		TableName:          "audit_logs_internal",
		Enabled:            true,
		UnattributedPolicy: "alert",
		SeverityTier:       "normal",
	})

	correlator := attribution.NewCorrelator(cfgMgr)

	t.Run("transaction with context row is attributed to user", func(t *testing.T) {
		tx := source.Transaction{
			TransactionID: "tx-1",
			CommittedAt:   time.Now().UTC(),
			Changes: []source.RowChange{
				{
					Table:  "_audit_context",
					Action: source.EventTypeInsert,
					AfterImage: map[string]interface{}{
						"user_id":    "user-john-doe",
						"actor_type": "USER",
						"request_id": "req-999",
					},
				},
				{
					Table:  "payments",
					Action: source.EventTypeInsert,
					AfterImage: map[string]interface{}{
						"amount": 100.0,
					},
				},
			},
		}

		attr := correlator.CorrelateTransaction(tx, "payments")
		assert.False(t, attr.TriggerAlert)
		assert.Equal(t, "USER", attr.ActorType)
		assert.NotNil(t, attr.ActorUserID)
		assert.Equal(t, "user-john-doe", *attr.ActorUserID)
		assert.Equal(t, "req-999", attr.RequestID)
	})

	t.Run("unattributed change on tolerate table produces SYSTEM actor with no alert", func(t *testing.T) {
		tx := source.Transaction{
			TransactionID: "tx-2",
			CommittedAt:   time.Now().UTC(),
			Changes: []source.RowChange{
				{
					Table:  "orders",
					Action: source.EventTypeUpdate,
					AfterImage: map[string]interface{}{
						"status": "shipped",
					},
				},
			},
		}

		attr := correlator.CorrelateTransaction(tx, "orders")
		assert.False(t, attr.TriggerAlert)
		assert.Equal(t, "SYSTEM", attr.ActorType)
		assert.Nil(t, attr.ActorUserID)
	})

	t.Run("unattributed change on alert table (critical) flags UNATTRIBUTED actor and critical alert", func(t *testing.T) {
		tx := source.Transaction{
			TransactionID: "tx-3",
			CommittedAt:   time.Now().UTC(),
			Changes: []source.RowChange{
				{
					Table:  "payments",
					Action: source.EventTypeDelete,
					BeforeImage: map[string]interface{}{
						"id": 42,
					},
				},
			},
		}

		attr := correlator.CorrelateTransaction(tx, "payments")
		assert.True(t, attr.TriggerAlert)
		assert.Equal(t, "UNATTRIBUTED", attr.ActorType)
		assert.Nil(t, attr.ActorUserID)
		assert.Equal(t, "critical", attr.SeverityTier)
	})

	t.Run("unattributed change on alert table (normal) flags normal alert", func(t *testing.T) {
		tx := source.Transaction{
			TransactionID: "tx-4",
			CommittedAt:   time.Now().UTC(),
			Changes: []source.RowChange{
				{
					Table:  "audit_logs_internal",
					Action: source.EventTypeInsert,
					AfterImage: map[string]interface{}{
						"id": 1,
					},
				},
			},
		}

		attr := correlator.CorrelateTransaction(tx, "audit_logs_internal")
		assert.True(t, attr.TriggerAlert)
		assert.Equal(t, "UNATTRIBUTED", attr.ActorType)
		assert.Equal(t, "normal", attr.SeverityTier)
	})
}
