package tiering

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"auditlogd/internal/alerting"
	"auditlogd/internal/archive"
	"auditlogd/internal/store"
)

// Config configures retention tiering parameters.
type Config struct {
	RetentionWindow time.Duration // e.g. 90 * 24 * time.Hour
}

// Service executes the retention tiering job.
type Service struct {
	cfg        Config
	store      store.Store
	archive    archive.ArchiveStore
	dispatcher *alerting.Dispatcher
}

// NewService creates a tiering service.
func NewService(cfg Config, st store.Store, arch archive.ArchiveStore, disp *alerting.Dispatcher) *Service {
	if cfg.RetentionWindow <= 0 {
		cfg.RetentionWindow = 90 * 24 * time.Hour
	}
	return &Service{
		cfg:        cfg,
		store:      st,
		archive:    arch,
		dispatcher: disp,
	}
}

// TierResult summarizes the outcome of a tiering run.
type TierResult struct {
	BatchesTiered int
	RecordsPurged int
	Errors        []error
}

// RunOnce finds all batches older than the retention window, archives them to WORM, and purges Postgres records.
func (s *Service) RunOnce(ctx context.Context) (*TierResult, error) {
	cutoff := time.Now().UTC().Add(-s.cfg.RetentionWindow)
	batches, err := s.store.GetBatchesForTiering(ctx, cutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to query batches for tiering: %w", err)
	}

	result := &TierResult{}

	for _, b := range batches {
		records, err := s.store.GetRecordsByBatchID(ctx, b.ID)
		if err != nil {
			errWrap := fmt.Errorf("failed to get records for batch %s: %w", b.ID, err)
			result.Errors = append(result.Errors, errWrap)
			s.reportFailure(ctx, b.ID, errWrap)
			continue
		}

		// 1. Serialize records to JSONL format
		var buf bytes.Buffer
		for _, r := range records {
			rBytes, err := json.Marshal(r)
			if err != nil {
				errWrap := fmt.Errorf("failed to marshal record %s: %w", r.ID, err)
				result.Errors = append(result.Errors, errWrap)
				s.reportFailure(ctx, b.ID, errWrap)
				continue
			}
			buf.Write(rBytes)
			buf.WriteByte('\n')
		}

		// 2. Put archive object into WORM storage
		if err := s.archive.PutArchive(ctx, b.ID, buf.Bytes()); err != nil {
			errWrap := fmt.Errorf("failed to put archive for batch %s to WORM: %w", b.ID, err)
			result.Errors = append(result.Errors, errWrap)
			s.reportFailure(ctx, b.ID, errWrap)
			continue
		}

		// 3. Record in audit_worm_index
		archiveKey := fmt.Sprintf("archives/%s.jsonl", b.ID)
		now := time.Now().UTC()
		wormEntry := &store.WORMIndexEntry{
			BatchID:              b.ID,
			WORMObjectKey:        archiveKey,
			TieredAt:             now,
			PurgedFromPostgresAt: &now,
		}
		if err := s.store.InsertWORMIndex(ctx, wormEntry); err != nil {
			errWrap := fmt.Errorf("failed to insert worm index for batch %s: %w", b.ID, err)
			result.Errors = append(result.Errors, errWrap)
			s.reportFailure(ctx, b.ID, errWrap)
			continue
		}

		// 4. Purge records from Postgres hot store
		if err := s.store.DeleteRecordsByBatchID(ctx, b.ID); err != nil {
			errWrap := fmt.Errorf("failed to purge records for batch %s: %w", b.ID, err)
			result.Errors = append(result.Errors, errWrap)
			s.reportFailure(ctx, b.ID, errWrap)
			continue
		}

		// 5. Update batch status to 'archived'
		if err := s.store.UpdateBatchStatus(ctx, b.ID, "archived", &archiveKey); err != nil {
			errWrap := fmt.Errorf("failed to update batch status for %s: %w", b.ID, err)
			result.Errors = append(result.Errors, errWrap)
			s.reportFailure(ctx, b.ID, errWrap)
			continue
		}

		result.BatchesTiered++
		result.RecordsPurged += len(records)
		log.Printf("[Tiering] Successfully tiered batch %s (%d records) to %s", b.ID, len(records), archiveKey)
	}

	return result, nil
}

func (s *Service) reportFailure(ctx context.Context, batchID string, err error) {
	if s.dispatcher != nil {
		_, _ = s.dispatcher.Trigger(
			ctx,
			"tiering_job_failure",
			"critical",
			"audit_batches",
			batchID,
			"",
			fmt.Sprintf("Retention tiering job failed for batch %s: %v", batchID, err),
		)
	}
}
