package alerting_test

import (
	"context"
	"testing"
	"time"

	"auditlogd/internal/alerting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlertDispatcherAndRateLimiting(t *testing.T) {
	dispatcher := alerting.NewDispatcher(50 * time.Millisecond)

	ctx := context.Background()

	t.Run("normal alert and critical alert recorded", func(t *testing.T) {
		a1, err := dispatcher.Trigger(ctx, "unattributed_change", "normal", "users", "rec-1", "tx-1", "Normal alert test")
		require.NoError(t, err)
		assert.NotNil(t, a1)
		assert.Equal(t, "normal", a1.Severity)

		a2, err := dispatcher.Trigger(ctx, "unattributed_change", "critical", "payments", "rec-2", "tx-2", "Critical alert test")
		require.NoError(t, err)
		assert.NotNil(t, a2)
		assert.Equal(t, "critical", a2.Severity)

		alerts := dispatcher.MemorySink().GetAlerts()
		assert.Len(t, alerts, 2)
	})

	t.Run("rate limiter suppresses duplicate within cooldown", func(t *testing.T) {
		// First alert for orders
		a1, err := dispatcher.Trigger(ctx, "unattributed_change", "normal", "orders", "rec-10", "tx-10", "Orders alert")
		require.NoError(t, err)
		assert.NotNil(t, a1)

		// Immediate duplicate for orders should be suppressed
		a2, err := dispatcher.Trigger(ctx, "unattributed_change", "normal", "orders", "rec-11", "tx-11", "Duplicate orders alert")
		require.NoError(t, err)
		assert.Nil(t, a2) // Suppressed

		// Wait for cooldown
		time.Sleep(60 * time.Millisecond)

		// Now alert should go through
		a3, err := dispatcher.Trigger(ctx, "unattributed_change", "normal", "orders", "rec-12", "tx-12", "Orders alert after cooldown")
		require.NoError(t, err)
		assert.NotNil(t, a3)
	})

	t.Run("alert acknowledgment", func(t *testing.T) {
		alerts := dispatcher.MemorySink().GetAlerts()
		require.NotEmpty(t, alerts)
		targetID := alerts[0].ID

		ok := dispatcher.MemorySink().Acknowledge(targetID)
		assert.True(t, ok)

		updatedAlerts := dispatcher.MemorySink().GetAlerts()
		for _, a := range updatedAlerts {
			if a.ID == targetID {
				assert.True(t, a.Acknowledged)
			}
		}
	})
}
