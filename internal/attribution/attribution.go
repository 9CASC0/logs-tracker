package attribution

import (
	"fmt"

	"auditlogd/internal/config"
	"auditlogd/internal/source"
)

// ActorAttribution contains the resolved identity for changes in a transaction.
type ActorAttribution struct {
	ActorUserID  *string
	ActorType    string // "USER", "SYSTEM", "UNATTRIBUTED"
	RequestID    string
	TriggerAlert bool
	SeverityTier string // "normal", "critical"
	Reason       string
}

// Correlator correlates transaction changes with context rows and audit policy.
type Correlator struct {
	configMgr *config.Manager
}

// NewCorrelator creates an attribution correlator.
func NewCorrelator(configMgr *config.Manager) *Correlator {
	return &Correlator{
		configMgr: configMgr,
	}
}

// CorrelateTransaction inspects a transaction's row changes to determine actor attribution.
func (c *Correlator) CorrelateTransaction(tx source.Transaction, tableName string) ActorAttribution {
	// 1. Look for _audit_context row written in the same transaction
	for _, change := range tx.Changes {
		if change.Table == "_audit_context" && change.Action == source.EventTypeInsert {
			row := change.AfterImage
			if row != nil {
				userID, _ := row["user_id"].(string)
				actorType, _ := row["actor_type"].(string)
				if actorType == "" {
					actorType = "USER"
				}
				reqID, _ := row["request_id"].(string)

				if userID != "" {
					return ActorAttribution{
						ActorUserID:  &userID,
						ActorType:    actorType,
						RequestID:    reqID,
						TriggerAlert: false,
					}
				}
			}
		}
	}

	// 2. No context row found: evaluate table policy
	tableCfg, exists := c.configMgr.GetTableConfig(tableName)
	if !exists || tableCfg.UnattributedPolicy == "tolerate" {
		return ActorAttribution{
			ActorUserID:  nil,
			ActorType:    "SYSTEM",
			TriggerAlert: false,
			Reason:       "unattributed change tolerated by policy",
		}
	}

	// Policy is "alert"
	severity := tableCfg.SeverityTier
	if severity == "" {
		severity = "normal"
	}

	return ActorAttribution{
		ActorUserID:  nil,
		ActorType:    "UNATTRIBUTED",
		TriggerAlert: true,
		SeverityTier: severity,
		Reason:       fmt.Sprintf("unattributed change on strict table %s (severity: %s)", tableName, severity),
	}
}
