package snapshot

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"auditlogd/internal/attribution"
	"auditlogd/internal/config"
	"auditlogd/internal/signing"
	"auditlogd/internal/source"
	"auditlogd/internal/store"
	"github.com/google/uuid"
)

// Builder constructs audit records from CDC row events, applying PII encryption and schema versioning.
type Builder struct {
	encryptor signing.Encryptor
}

// NewBuilder creates a snapshot builder.
func NewBuilder(encryptor signing.Encryptor) *Builder {
	return &Builder{
		encryptor: encryptor,
	}
}

// BuildRecord turns a row change and attribution into a persistable store.Record.
func (b *Builder) BuildRecord(
	ctx context.Context,
	change source.RowChange,
	tableCfg config.TableConfig,
	attr attribution.ActorAttribution,
	txID string,
	committedAt time.Time,
	leafIndex int,
) (*store.Record, error) {
	recordID := uuid.New().String()

	// 1. Process Before Image
	var beforeBytes []byte
	var err error
	if change.BeforeImage != nil && (change.Action == source.EventTypeUpdate || change.Action == source.EventTypeDelete) {
		processedBefore, err := b.processRow(ctx, change.BeforeImage, tableCfg.EncryptedColumns)
		if err != nil {
			return nil, fmt.Errorf("failed to process before image: %w", err)
		}
		beforeBytes, err = json.Marshal(processedBefore)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal before image: %w", err)
		}
	}

	// 2. Process After Image
	var afterBytes []byte
	if change.AfterImage != nil && (change.Action == source.EventTypeInsert || change.Action == source.EventTypeUpdate) {
		processedAfter, err := b.processRow(ctx, change.AfterImage, tableCfg.EncryptedColumns)
		if err != nil {
			return nil, fmt.Errorf("failed to process after image: %w", err)
		}
		afterBytes, err = json.Marshal(processedAfter)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal after image: %w", err)
		}
	}

	// 3. Extract Primary Key JSON
	pkBytes, err := extractPrimaryKey(change.BeforeImage, change.AfterImage)
	if err != nil {
		return nil, fmt.Errorf("failed to extract primary key: %w", err)
	}

	// 4. Compute Schema Version Hash
	schemaVer := computeSchemaVersion(change.BeforeImage, change.AfterImage)

	rec := &store.Record{
		ID:              recordID,
		TableName:       change.Table,
		PrimaryKey:      pkBytes,
		EventType:       string(change.Action),
		BeforeImage:     beforeBytes,
		AfterImage:      afterBytes,
		ActorUserID:     attr.ActorUserID,
		ActorType:       attr.ActorType,
		TransactionID:   txID,
		SchemaVersion:   schemaVer,
		CommittedAt:     committedAt,
		MerkleLeafIndex: leafIndex,
	}

	return rec, nil
}

// processRow copies a row map and encrypts any columns listed in encColumns.
func (b *Builder) processRow(ctx context.Context, row map[string]interface{}, encColumns []string) (map[string]interface{}, error) {
	encSet := make(map[string]struct{}, len(encColumns))
	for _, col := range encColumns {
		encSet[col] = struct{}{}
	}

	out := make(map[string]interface{}, len(row))
	for k, v := range row {
		if _, shouldEncrypt := encSet[k]; shouldEncrypt && v != nil && b.encryptor != nil {
			valBytes, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal column %s for encryption: %w", k, err)
			}
			ciphertext, ver, err := b.encryptor.Encrypt(ctx, valBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt column %s: %w", k, err)
			}
			// Encrypted field format: enc:<version>:<base64-ciphertext>
			out[k] = fmt.Sprintf("enc:%s:%s", ver, base64.StdEncoding.EncodeToString(ciphertext))
		} else {
			out[k] = v
		}
	}
	return out, nil
}

// extractPrimaryKey attempts to find primary key fields ('id', or table-specific key).
func extractPrimaryKey(before, after map[string]interface{}) ([]byte, error) {
	source := after
	if source == nil {
		source = before
	}
	if source == nil {
		return json.Marshal(map[string]interface{}{"id": "unknown"})
	}

	// Look for standard ID keys
	for _, candidate := range []string{"id", "ID", "uuid", "pk"} {
		if val, ok := source[candidate]; ok {
			return json.Marshal(map[string]interface{}{candidate: val})
		}
	}

	// Fallback: look for keys ending in _id
	for k, val := range source {
		if strings.HasSuffix(k, "_id") {
			return json.Marshal(map[string]interface{}{k: val})
		}
	}

	// Default fallback: first key sorted
	keys := make([]string, 0, len(source))
	for k := range source {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		k := keys[0]
		return json.Marshal(map[string]interface{}{k: source[k]})
	}

	return json.Marshal(map[string]interface{}{"row": "unknown"})
}

// computeSchemaVersion produces a deterministic hash over column names.
func computeSchemaVersion(before, after map[string]interface{}) string {
	source := after
	if source == nil {
		source = before
	}
	if source == nil {
		return "v0"
	}

	keys := make([]string, 0, len(source))
	for k := range source {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{';'})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
