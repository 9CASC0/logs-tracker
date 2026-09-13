package pipeline_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"auditlogd/internal/alerting"
	"auditlogd/internal/archive"
	"auditlogd/internal/attribution"
	"auditlogd/internal/batch"
	"auditlogd/internal/config"
	"auditlogd/internal/merkle"
	"auditlogd/internal/pipeline"
	"auditlogd/internal/snapshot"
	"auditlogd/internal/source"
	"auditlogd/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockChangeSource yields a slice of transactions then closes.
type MockChangeSource struct {
	txs     []source.Transaction
	current source.Position
}

func (s *MockChangeSource) Stream(ctx context.Context) (<-chan source.Transaction, error) {
	ch := make(chan source.Transaction, len(s.txs))
	for _, tx := range s.txs {
		ch <- tx
	}
	close(ch)
	return ch, nil
}

func (s *MockChangeSource) Checkpoint() source.Position {
	return s.current
}

func (s *MockChangeSource) ResumeFrom(pos source.Position) error {
	s.current = pos
	return nil
}

func (s *MockChangeSource) Close() error {
	return nil
}

type pipelineTestSigner struct {
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
}

func (s *pipelineTestSigner) Sign(ctx context.Context, digest []byte) ([]byte, string, error) {
	return ed25519.Sign(s.privKey, digest), "v1", nil
}

func (s *pipelineTestSigner) Verify(ctx context.Context, digest, signature []byte, keyVersion string) (bool, error) {
	return ed25519.Verify(s.pubKey, digest, signature), nil
}

func (s *pipelineTestSigner) PublicKey(ctx context.Context, keyVersion string) ([]byte, error) {
	return s.pubKey, nil
}

func (s *pipelineTestSigner) Encrypt(ctx context.Context, plaintext []byte) ([]byte, string, error) {
	return append([]byte("ENC_"), plaintext...), "v1", nil
}

func (s *pipelineTestSigner) Decrypt(ctx context.Context, ciphertext []byte, keyVersion string) ([]byte, error) {
	return ciphertext[4:], nil
}

func TestPrimarySeamIngestionPipeline(t *testing.T) {
	ctx := context.Background()

	// 1. Setup crypto & storage
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signerEnc := &pipelineTestSigner{pubKey: pub, privKey: priv}

	tempDir := t.TempDir()
	archStore, err := archive.NewLocalDirArchiveStore(tempDir)
	require.NoError(t, err)

	memStore := store.NewMemoryStore()
	dispatcher := alerting.NewDispatcher(time.Minute)

	// 2. Setup modules
	cfgMgr := config.NewManager()
	correlator := attribution.NewCorrelator(cfgMgr)
	snapBuilder := snapshot.NewBuilder(signerEnc)

	batcher := batch.NewBatcher(
		batch.Config{
			MaxInterval: 10 * time.Second,
			MaxEvents:   100, // manual flush for test
		},
		signerEnc,
		memStore,
		archStore,
		dispatcher,
	)

	// 3. Prepare synthetic transaction sequence
	tx1Config := source.Transaction{
		TransactionID: "tx-config",
		CommittedAt:   time.Now().UTC(),
		Position:      source.Position{File: "binlog.001", Position: 100},
		Changes: []source.RowChange{
			{
				Table:  "_audit_config",
				Action: source.EventTypeInsert,
				AfterImage: map[string]interface{}{
					"table_name":          "orders",
					"enabled":             true,
					"unattributed_policy": "tolerate",
					"severity_tier":       "normal",
				},
			},
			{
				Table:  "_audit_config",
				Action: source.EventTypeInsert,
				AfterImage: map[string]interface{}{
					"table_name":          "payments",
					"enabled":             true,
					"unattributed_policy": "alert",
					"severity_tier":       "critical",
					"encrypted_columns":   []interface{}{"card_number"},
				},
			},
		},
	}

	tx2Attributed := source.Transaction{
		TransactionID: "tx-attributed",
		CommittedAt:   time.Now().UTC(),
		Position:      source.Position{File: "binlog.001", Position: 200},
		Changes: []source.RowChange{
			{
				Table:  "_audit_context",
				Action: source.EventTypeInsert,
				AfterImage: map[string]interface{}{
					"user_id":    "usr-admin-1",
					"actor_type": "USER",
					"request_id": "req-xyz",
				},
			},
			{
				Table:  "orders",
				Action: source.EventTypeInsert,
				AfterImage: map[string]interface{}{
					"id":     101,
					"total":  150.0,
					"status": "pending",
				},
			},
		},
	}

	tx3UnattributedTolerated := source.Transaction{
		TransactionID: "tx-unattributed-tolerate",
		CommittedAt:   time.Now().UTC(),
		Position:      source.Position{File: "binlog.001", Position: 300},
		Changes: []source.RowChange{
			{
				Table:  "orders",
				Action: source.EventTypeUpdate,
				BeforeImage: map[string]interface{}{
					"id":     101,
					"status": "pending",
				},
				AfterImage: map[string]interface{}{
					"id":     101,
					"status": "shipped",
				},
			},
		},
	}

	tx4UnattributedAlerting := source.Transaction{
		TransactionID: "tx-unattributed-alert",
		CommittedAt:   time.Now().UTC(),
		Position:      source.Position{File: "binlog.001", Position: 400},
		Changes: []source.RowChange{
			{
				Table:  "payments",
				Action: source.EventTypeInsert,
				AfterImage: map[string]interface{}{
					"id":          501,
					"card_number": "1111-2222-3333-4444",
					"amount":      150.0,
				},
			},
		},
	}

	changeSource := &MockChangeSource{
		txs: []source.Transaction{
			tx1Config,
			tx2Attributed,
			tx3UnattributedTolerated,
			tx4UnattributedAlerting,
		},
	}

	pipe := pipeline.NewPipeline(changeSource, cfgMgr, correlator, snapBuilder, batcher, dispatcher)

	// 4. Run pipeline
	err = pipe.Run(ctx)
	require.NoError(t, err)

	// 5. Assertions on the Primary Seam Output

	// A. Config Manager dynamically updated from binlog
	assert.True(t, cfgMgr.IsAudited("orders"))
	assert.True(t, cfgMgr.IsAudited("payments"))

	// B. Batches created and committed
	batches, err := memStore.ListBatches(ctx, 10, 0)
	require.NoError(t, err)
	require.Len(t, batches, 1)

	b := batches[0]
	assert.Equal(t, 3, b.EventCount)
	assert.NotEmpty(t, b.MerkleRoot)
	assert.NotEmpty(t, b.Signature)
	assert.Equal(t, "signed", b.Status)
	assert.Equal(t, "binlog.001", b.BinlogFile)
	assert.Equal(t, uint32(400), b.BinlogPosition)

	// C. Records verified in store
	records, err := memStore.GetRecordsByBatchID(ctx, b.ID)
	require.NoError(t, err)
	require.Len(t, records, 3)

	// Record 1 (Attributed order)
	r1 := records[0]
	assert.Equal(t, "orders", r1.TableName)
	assert.Equal(t, "INSERT", r1.EventType)
	assert.Equal(t, "USER", r1.ActorType)
	require.NotNil(t, r1.ActorUserID)
	assert.Equal(t, "usr-admin-1", *r1.ActorUserID)

	// Record 2 (Tolerated order update)
	r2 := records[1]
	assert.Equal(t, "orders", r2.TableName)
	assert.Equal(t, "UPDATE", r2.EventType)
	assert.Equal(t, "SYSTEM", r2.ActorType)
	assert.Nil(t, r2.ActorUserID)

	// Record 3 (Unattributed critical payment)
	r3 := records[2]
	assert.Equal(t, "payments", r3.TableName)
	assert.Equal(t, "INSERT", r3.EventType)
	assert.Equal(t, "UNATTRIBUTED", r3.ActorType)
	assert.Nil(t, r3.ActorUserID)

	// Verify column encryption on card_number
	var payMap map[string]interface{}
	err = json.Unmarshal(r3.AfterImage, &payMap)
	require.NoError(t, err)
	assert.Contains(t, payMap["card_number"].(string), "enc:v1:")

	// D. WORM checkpoint object written
	chkData, err := archStore.Get(ctx, filepath.Join("checkpoints", b.ID+".json"))
	require.NoError(t, err)
	assert.Contains(t, string(chkData), b.ID)

	// E. Critical Alert dispatched
	alerts := dispatcher.MemorySink().GetAlerts()
	require.Len(t, alerts, 1)
	assert.Equal(t, "critical", alerts[0].Severity)
	assert.Equal(t, "payments", alerts[0].TableName)
	assert.Equal(t, r3.ID, alerts[0].RecordID)

	// F. Cryptographic Verification of the primary seam records
	verifier := merkle.NewRecordVerifier(memStore, signerEnc)
	for _, rec := range records {
		vRes, err := verifier.VerifyRecord(ctx, rec.ID)
		require.NoError(t, err)
		assert.True(t, vRes.Valid, "Record %s failed verification", rec.ID)
	}
}
