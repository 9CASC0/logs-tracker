package bootstrap

import (
	"context"
	"testing"
	"time"

	"auditlogd/internal/alerting"
	"auditlogd/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestBootstrapRunner_UnregisteredTable(t *testing.T) {
	ctx := context.Background()
	cfgMgr := config.NewManager()
	disp := alerting.NewDispatcher(time.Minute)

	runner := NewRunner(nil, cfgMgr, nil, nil, disp)

	err := runner.BootstrapTable(ctx, "non_existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not registered in audit config")
}
