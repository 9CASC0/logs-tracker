package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"auditlogd/internal/alerting"
	"auditlogd/internal/attribution"
	"auditlogd/internal/batch"
	"auditlogd/internal/config"
	"auditlogd/internal/snapshot"
	"auditlogd/internal/source"
)

// Runner manages initial bootstrap snapshotting for newly-registered tables.
type Runner struct {
	db              *sql.DB
	configMgr       *config.Manager
	snapshotBuilder *snapshot.Builder
	batcher         *batch.Batcher
	dispatcher      *alerting.Dispatcher
}

// NewRunner creates a bootstrap runner.
func NewRunner(
	db *sql.DB,
	configMgr *config.Manager,
	snap *snapshot.Builder,
	b *batch.Batcher,
	disp *alerting.Dispatcher,
) *Runner {
	return &Runner{
		db:              db,
		configMgr:       configMgr,
		snapshotBuilder: snap,
		batcher:         b,
		dispatcher:      disp,
	}
}

// BootstrapTable performs a one-time consistent snapshot of an audited table's existing rows.
func (r *Runner) BootstrapTable(ctx context.Context, tableName string) error {
	tableCfg, exists := r.configMgr.GetTableConfig(tableName)
	if !exists {
		return fmt.Errorf("table %s not registered in audit config", tableName)
	}

	log.Printf("[Bootstrap] Starting snapshot for table: %s", tableName)

	// 1. Update status to in_progress
	if err := r.updateBootstrapStatus(ctx, tableName, "in_progress"); err != nil {
		return fmt.Errorf("failed to update bootstrap status to in_progress: %w", err)
	}

	// 2. Perform consistent snapshot read
	// Use REPEATABLE READ transaction to ensure point-in-time consistency
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		r.reportFailure(ctx, tableName, err)
		return fmt.Errorf("failed to begin consistent read transaction: %w", err)
	}
	defer tx.Rollback()

	query := fmt.Sprintf("SELECT * FROM `%s`", tableName)
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		r.reportFailure(ctx, tableName, err)
		return fmt.Errorf("failed to query table %s for bootstrap: %w", tableName, err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		r.reportFailure(ctx, tableName, err)
		return fmt.Errorf("failed to get columns for table %s: %w", tableName, err)
	}

	// Configure batcher for bootstrap mode
	r.batcher.SetBootstrapMode(true, tableName)

	rowCount := 0
	for rows.Next() {
		columns := make([]interface{}, len(cols))
		columnPointers := make([]interface{}, len(cols))
		for i := range columns {
			columnPointers[i] = &columns[i]
		}

		if err := rows.Scan(columnPointers...); err != nil {
			r.reportFailure(ctx, tableName, err)
			return fmt.Errorf("failed to scan bootstrap row: %w", err)
		}

		afterMap := make(map[string]interface{}, len(cols))
		for i, colName := range cols {
			val := columns[i]
			if b, ok := val.([]byte); ok {
				afterMap[colName] = string(b)
			} else {
				afterMap[colName] = val
			}
		}

		change := source.RowChange{
			Table:      tableName,
			Action:     source.EventTypeInsert,
			AfterImage: afterMap,
		}

		attr := attribution.ActorAttribution{
			ActorUserID: nil,
			ActorType:   "SYSTEM",
		}

		rec, err := r.snapshotBuilder.BuildRecord(
			ctx,
			change,
			tableCfg,
			attr,
			fmt.Sprintf("bootstrap:%s", tableName),
			time.Now().UTC(),
			rowCount,
		)
		if err != nil {
			r.reportFailure(ctx, tableName, err)
			return fmt.Errorf("failed to build bootstrap record: %w", err)
		}

		// Queue record into batcher
		if err := r.batcher.AddRecord(ctx, rec, source.Position{File: "bootstrap", Position: 0}); err != nil {
			r.reportFailure(ctx, tableName, err)
			return fmt.Errorf("failed to add bootstrap record to batcher: %w", err)
		}
		rowCount++
	}

	// 3. Flush the bootstrap batch so it is Merkle-anchored and signed immediately
	if err := r.batcher.Flush(ctx); err != nil {
		r.reportFailure(ctx, tableName, err)
		return fmt.Errorf("failed to flush bootstrap batch: %w", err)
	}

	// 4. Update status to complete
	if err := r.updateBootstrapStatus(ctx, tableName, "complete"); err != nil {
		return fmt.Errorf("failed to update bootstrap status to complete: %w", err)
	}

	tableCfg.BootstrapStatus = "complete"
	r.configMgr.SetTableConfig(tableCfg)

	log.Printf("[Bootstrap] Completed snapshot for table %s: %d records anchored and signed", tableName, rowCount)
	return nil
}

func (r *Runner) updateBootstrapStatus(ctx context.Context, tableName string, status string) error {
	query := "UPDATE _audit_config SET bootstrap_status = ? WHERE table_name = ?"
	_, err := r.db.ExecContext(ctx, query, status, tableName)
	return err
}

func (r *Runner) reportFailure(ctx context.Context, tableName string, err error) {
	if r.dispatcher != nil {
		_, _ = r.dispatcher.Trigger(
			ctx,
			"bootstrap_run_failure",
			"normal",
			tableName,
			"",
			"",
			fmt.Sprintf("Bootstrap snapshot failed for table %s: %v", tableName, err),
		)
	}
}
