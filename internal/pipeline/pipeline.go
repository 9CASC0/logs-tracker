package pipeline

import (
	"context"
	"fmt"
	"log"

	"auditlogd/internal/alerting"
	"auditlogd/internal/attribution"
	"auditlogd/internal/batch"
	"auditlogd/internal/config"
	"auditlogd/internal/snapshot"
	"auditlogd/internal/source"
)

// Pipeline manages the continuous flow from CDC change source to batch persistence.
type Pipeline struct {
	source          source.ChangeSource
	configMgr       *config.Manager
	correlator      *attribution.Correlator
	snapshotBuilder *snapshot.Builder
	batcher         *batch.Batcher
	alertDispatcher *alerting.Dispatcher
}

// NewPipeline creates a configured Pipeline instance.
func NewPipeline(
	src source.ChangeSource,
	cfgMgr *config.Manager,
	corr *attribution.Correlator,
	snap *snapshot.Builder,
	b *batch.Batcher,
	disp *alerting.Dispatcher,
) *Pipeline {
	return &Pipeline{
		source:          src,
		configMgr:       cfgMgr,
		correlator:      corr,
		snapshotBuilder: snap,
		batcher:         b,
		alertDispatcher: disp,
	}
}

// ProcessTransaction handles a single committed transaction through the pipeline.
func (p *Pipeline) ProcessTransaction(ctx context.Context, tx source.Transaction) error {
	// 1. Process config changes first (live hot-reload of _audit_config)
	for _, change := range tx.Changes {
		if change.Table == "_audit_config" {
			if err := p.configMgr.HandleBinlogEvent(change); err != nil {
				log.Printf("[Pipeline] Error handling _audit_config update: %v", err)
			}
		}
	}

	// 2. Process audited table row changes
	for _, change := range tx.Changes {
		if change.Table == "_audit_config" || change.Table == "_audit_context" {
			continue // Internal management tables
		}

		tableCfg, audited := p.configMgr.GetTableConfig(change.Table)
		if !audited || !tableCfg.Enabled {
			continue // Table not currently in audit scope
		}

		// Correlate attribution
		attr := p.correlator.CorrelateTransaction(tx, change.Table)

		// Build snapshot record
		rec, err := p.snapshotBuilder.BuildRecord(
			ctx,
			change,
			tableCfg,
			attr,
			tx.TransactionID,
			tx.CommittedAt,
			p.batcher.CurrentEventCount(),
		)
		if err != nil {
			return fmt.Errorf("failed to build snapshot record: %w", err)
		}

		// If attribution policy mandates an alert, dispatch or queue it
		if attr.TriggerAlert && p.alertDispatcher != nil {
			alert, err := p.alertDispatcher.Trigger(
				ctx,
				"unattributed_change",
				attr.SeverityTier,
				change.Table,
				rec.ID,
				tx.TransactionID,
				attr.Reason,
			)
			if err != nil {
				log.Printf("[Pipeline] Warning: failed to dispatch alert: %v", err)
			} else if alert != nil {
				log.Printf("[Pipeline] Alert raised: [%s] table=%s record=%s reason=%s",
					alert.Severity, alert.TableName, alert.RecordID, alert.Message)
			}
		}

		// Queue record in current batch
		if err := p.batcher.AddRecord(ctx, rec, tx.Position); err != nil {
			return fmt.Errorf("failed to add record to batch: %w", err)
		}
	}

	return nil
}

// Run streams from the change source until the context is canceled.
func (p *Pipeline) Run(ctx context.Context) error {
	stream, err := p.source.Stream(ctx)
	if err != nil {
		return fmt.Errorf("failed to start change source stream: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return p.batcher.Close(context.Background())
		case tx, ok := <-stream:
			if !ok {
				return p.batcher.Close(context.Background())
			}
			if err := p.ProcessTransaction(ctx, tx); err != nil {
				log.Printf("[Pipeline] Error processing transaction %s: %v", tx.TransactionID, err)
			}
		}
	}
}
