package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auditlogd/internal/alerting"
	"auditlogd/internal/api"
	"auditlogd/internal/config"
	"auditlogd/internal/merkle"
	"auditlogd/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testSignerEncryptor struct {
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
}

func (s *testSignerEncryptor) Sign(ctx context.Context, digest []byte) ([]byte, string, error) {
	return ed25519.Sign(s.privKey, digest), "v1", nil
}

func (s *testSignerEncryptor) Verify(ctx context.Context, digest, signature []byte, keyVersion string) (bool, error) {
	return ed25519.Verify(s.pubKey, digest, signature), nil
}

func (s *testSignerEncryptor) PublicKey(ctx context.Context, keyVersion string) ([]byte, error) {
	return s.pubKey, nil
}

func (s *testSignerEncryptor) Encrypt(ctx context.Context, plaintext []byte) ([]byte, string, error) {
	return append([]byte("ENC_"), plaintext...), "v1", nil
}

func (s *testSignerEncryptor) Decrypt(ctx context.Context, ciphertext []byte, keyVersion string) ([]byte, error) {
	return bytes.TrimPrefix(ciphertext, []byte("ENC_")), nil
}

func setupAPITest(t *testing.T) (*httptest.Server, *store.MemoryStore, *config.Manager, *testSignerEncryptor) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	se := &testSignerEncryptor{pubKey: pub, privKey: priv}
	memStore := store.NewMemoryStore()
	cfgMgr := config.NewManager()
	verifier := merkle.NewRecordVerifier(memStore, se)
	memSink := alerting.NewMemorySink()

	handler := api.NewHandler(memStore, cfgMgr, verifier, se, se, memSink)

	validator := api.NewStaticTokenValidator(map[string][]api.Permission{
		"admin-token": api.RolePermissions["admin"],
		"app-token":   api.RolePermissions["app_service"],
	})

	server := api.NewServer(handler, validator)
	ts := httptest.NewServer(server.Handler())
	t.Cleanup(ts.Close)

	return ts, memStore, cfgMgr, se
}

func TestAPIEndpoints(t *testing.T) {
	ts, memStore, cfgMgr, se := setupAPITest(t)
	ctx := context.Background()

	// Seed config
	cfgMgr.SetTableConfig(config.TableConfig{
		TableName: "users",
		Enabled:   true,
	})

	batchID := "batch-api-1"
	recordID := "rec-api-1"
	fixedTime := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	secretEnc := base64.StdEncoding.EncodeToString([]byte("ENC_supersecret"))
	afterImg := json.RawMessage(`{"id":42,"name":"Bob","secret":"enc:v1:` + secretEnc + `"}`)

	payload := merkle.RecordCanonicalPayload{
		ID:              recordID,
		BatchID:         batchID,
		TableName:       "users",
		PrimaryKey:      json.RawMessage(`{"id":"42"}`),
		EventType:       "INSERT",
		AfterImage:      afterImg,
		ActorType:       "USER",
		TransactionID:   "tx-100",
		SchemaVersion:   "v1",
		CommittedAt:     fixedTime.Format(time.RFC3339Nano),
		MerkleLeafIndex: 0,
	}
	leafHash, err := merkle.ComputeRecordLeafHash(payload)
	require.NoError(t, err)

	tree, err := merkle.BuildTree([][]byte{leafHash})
	require.NoError(t, err)

	sig, ver, err := se.Sign(ctx, tree.Root())
	require.NoError(t, err)

	batch := &store.Batch{
		ID:         batchID,
		StartedAt:  fixedTime,
		ClosedAt:   fixedTime,
		EventCount: 1,
		MerkleRoot: tree.Root(),
		Signature:  sig,
		KeyVersion: ver,
		Status:     "signed",
	}

	record := &store.Record{
		ID:              recordID,
		BatchID:         batchID,
		TableName:       "users",
		PrimaryKey:      json.RawMessage(`{"id":"42"}`),
		EventType:       "INSERT",
		AfterImage:      afterImg,
		ActorType:       "USER",
		TransactionID:   "tx-100",
		SchemaVersion:   "v1",
		CommittedAt:     fixedTime,
		MerkleLeafIndex: 0,
	}

	err = memStore.CreateBatch(ctx, batch, []*store.Record{record})
	require.NoError(t, err)

	t.Run("GET /health (unauthenticated)", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("GET /audit/records without auth fails with 401", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/audit/records?table=users&primary_key=42")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("GET /audit/records with wrong token fails with 403", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/audit/records?table=users&primary_key=42", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("GET /audit/records with valid token succeeds", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/audit/records?table=users&primary_key=42", nil)
		req.Header.Set("Authorization", "Bearer app-token")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var env api.ResponseEnvelope
		err = json.NewDecoder(resp.Body).Decode(&env)
		require.NoError(t, err)
		assert.NotNil(t, env.Data)
	})

	t.Run("GET /audit/records/{id} with decryption", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/audit/records/"+recordID+"?decrypt=true", nil)
		req.Header.Set("Authorization", "Bearer app-token")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var rec store.Record
		err = json.NewDecoder(resp.Body).Decode(&rec)
		require.NoError(t, err)
		assert.Contains(t, string(rec.AfterImage), "supersecret")
	})

	t.Run("GET /audit/records/{id}/verify verifies authentically", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/audit/records/"+recordID+"/verify", nil)
		req.Header.Set("Authorization", "Bearer app-token")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var res merkle.VerificationResult
		err = json.NewDecoder(resp.Body).Decode(&res)
		require.NoError(t, err)
		assert.True(t, res.Valid)
		assert.Equal(t, batchID, res.BatchID)
	})

	t.Run("GET /audit/batches/{id}", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/audit/batches/"+batchID, nil)
		req.Header.Set("Authorization", "Bearer admin-token")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var bMap map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&bMap)
		require.NoError(t, err)
		assert.Equal(t, batchID, bMap["id"])
	})

	t.Run("Public Verification: GET /public/verification/keys", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/public/verification/keys")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var kMap map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&kMap)
		require.NoError(t, err)
		assert.NotNil(t, kMap["active_key"])
	})

	t.Run("Public Verification: GET /public/verification/roots", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/public/verification/roots")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var env api.ResponseEnvelope
		err = json.NewDecoder(resp.Body).Decode(&env)
		require.NoError(t, err)
		assert.NotNil(t, env.Data)
	})

	t.Run("Public Verification: POST /public/verification/verify", func(t *testing.T) {
		verifyReq := map[string]interface{}{
			"record":             payload,
			"proof":              []merkle.ProofNode{},
			"merkle_root_hex":    hex.EncodeToString(tree.Root()),
			"signature_hex":      hex.EncodeToString(sig),
			"key_version":        ver,
			"public_key_base64":  base64.StdEncoding.EncodeToString(se.pubKey),
		}
		body, _ := json.Marshal(verifyReq)

		resp, err := http.Post(ts.URL+"/public/verification/verify", "application/json", bytes.NewReader(body))
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var vRes map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&vRes)
		require.NoError(t, err)
		assert.Equal(t, true, vRes["valid"])
	})
}
