package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"auditlogd/internal/alerting"
	"auditlogd/internal/config"
	"auditlogd/internal/merkle"
	"auditlogd/internal/signing"
	"auditlogd/internal/store"
)

// ResponseEnvelope wraps paginated list responses.
type ResponseEnvelope struct {
	Data interface{} `json:"data"`
	Meta interface{} `json:"meta,omitempty"`
}

// ErrorEnvelope standardizes error responses.
type ErrorEnvelope struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorEnvelope{
		Error: ErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}

// Handler holds dependencies for API endpoints.
type Handler struct {
	store      store.Store
	configMgr  *config.Manager
	verifier   merkle.Verifier
	signer     signing.Signer
	encryptor  signing.Encryptor
	memorySink *alerting.MemorySink
}

// NewHandler creates an API Handler.
func NewHandler(
	st store.Store,
	cfg *config.Manager,
	ver merkle.Verifier,
	s signing.Signer,
	enc signing.Encryptor,
	memSink *alerting.MemorySink,
) *Handler {
	return &Handler{
		store:      st,
		configMgr:  cfg,
		verifier:   ver,
		signer:     s,
		encryptor:  enc,
		memorySink: memSink,
	}
}

// HealthHandler returns system health status.
func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// GetRecordsHandler returns audit records filtered by table and primary_key.
func (h *Handler) GetRecordsHandler(w http.ResponseWriter, r *http.Request) {
	table := r.URL.Query().Get("table")
	pkStr := r.URL.Query().Get("primary_key")

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 50
	}

	if table == "" || pkStr == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Both 'table' and 'primary_key' parameters are required")
		return
	}

	var pkJSON json.RawMessage
	if strings.HasPrefix(pkStr, "{") {
		pkJSON = json.RawMessage(pkStr)
	} else {
		// Treat as simple id
		pkJSON = json.RawMessage(fmt.Sprintf(`{"id":"%s"}`, pkStr))
	}

	records, err := h.store.GetRecordsByTableAndPK(r.Context(), table, pkJSON, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, ResponseEnvelope{
		Data: records,
		Meta: map[string]interface{}{
			"count":  len(records),
			"limit":  limit,
			"offset": offset,
		},
	})
}

// GetRecordDetailHandler returns a single audit record, with optional decryption.
func (h *Handler) GetRecordDetailHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 3 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Record ID required in path")
		return
	}
	recordID := pathParts[2]

	rec, err := h.store.GetRecord(r.Context(), recordID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Record not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	decryptParam := r.URL.Query().Get("decrypt") == "true"
	if decryptParam && h.encryptor != nil {
		rec = h.decryptRecordFields(r.Context(), rec)
	}

	writeJSON(w, http.StatusOK, rec)
}

func (h *Handler) decryptRecordFields(ctx context.Context, rec *store.Record) *store.Record {
	recCopy := *rec
	if len(recCopy.BeforeImage) > 0 {
		var before map[string]interface{}
		if err := json.Unmarshal(recCopy.BeforeImage, &before); err == nil {
			h.decryptMap(ctx, before)
			b, _ := json.Marshal(before)
			recCopy.BeforeImage = b
		}
	}
	if len(recCopy.AfterImage) > 0 {
		var after map[string]interface{}
		if err := json.Unmarshal(recCopy.AfterImage, &after); err == nil {
			h.decryptMap(ctx, after)
			b, _ := json.Marshal(after)
			recCopy.AfterImage = b
		}
	}
	return &recCopy
}

func (h *Handler) decryptMap(ctx context.Context, data map[string]interface{}) {
	for k, v := range data {
		str, ok := v.(string)
		if !ok || !strings.HasPrefix(str, "enc:") {
			continue
		}
		parts := strings.SplitN(str, ":", 3)
		if len(parts) != 3 {
			continue
		}
		version := parts[1]
		cipherBytes, err := base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			continue
		}
		plain, err := h.encryptor.Decrypt(ctx, cipherBytes, version)
		if err != nil {
			continue
		}
		var parsed interface{}
		if err := json.Unmarshal(plain, &parsed); err == nil {
			data[k] = parsed
		} else {
			data[k] = string(plain)
		}
	}
}

// VerifyRecordHandler verifies a record's authenticity against its signed Merkle batch.
func (h *Handler) VerifyRecordHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 3 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Record ID required in path")
		return
	}
	recordID := pathParts[2]

	res, err := h.verifier.VerifyRecord(r.Context(), recordID)
	if err != nil {
		writeError(w, http.StatusNotFound, "VERIFICATION_ERROR", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, res)
}

// GetBatchHandler returns batch metadata by ID.
func (h *Handler) GetBatchHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 3 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Batch ID required in path")
		return
	}
	batchID := pathParts[2]

	batch, err := h.store.GetBatch(r.Context(), batchID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Batch not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	resp := map[string]interface{}{
		"id":               batch.ID,
		"started_at":       batch.StartedAt.Format(time.RFC3339),
		"closed_at":        batch.ClosedAt.Format(time.RFC3339),
		"event_count":      batch.EventCount,
		"merkle_root":      hex.EncodeToString(batch.MerkleRoot),
		"signature":        hex.EncodeToString(batch.Signature),
		"key_version":      batch.KeyVersion,
		"binlog_file":      batch.BinlogFile,
		"binlog_position":  batch.BinlogPosition,
		"status":           batch.Status,
		"worm_object_key":  batch.WORMObjectKey,
		"is_bootstrap":     batch.IsBootstrap,
	}

	writeJSON(w, http.StatusOK, resp)
}

// GetConfigHandler returns all registered audit configurations.
func (h *Handler) GetConfigHandler(w http.ResponseWriter, r *http.Request) {
	configs := h.configMgr.GetAllConfigs()
	writeJSON(w, http.StatusOK, ResponseEnvelope{
		Data: configs,
		Meta: map[string]interface{}{"count": len(configs)},
	})
}

// AcknowledgeAlertHandler marks an alert as acknowledged.
func (h *Handler) AcknowledgeAlertHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(pathParts) < 3 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Alert ID required in path")
		return
	}
	alertID := pathParts[2]

	if h.memorySink == nil || !h.memorySink.Acknowledge(alertID) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Alert not found or already acknowledged")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "acknowledged",
		"alert_id": alertID,
	})
}

// --- Public Verification Feed Handlers (Unauthenticated) ---

// PublicKeysHandler returns the public signing keys.
func (h *Handler) PublicKeysHandler(w http.ResponseWriter, r *http.Request) {
	pubKey, err := h.signer.PublicKey(r.Context(), "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve public key")
		return
	}

	resp := map[string]interface{}{
		"active_key": map[string]interface{}{
			"type":       "Ed25519",
			"key_base64": base64.StdEncoding.EncodeToString(pubKey),
			"key_hex":    hex.EncodeToString(pubKey),
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

// PublicRootsHandler returns historical signed roots and time ranges.
func (h *Handler) PublicRootsHandler(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 100
	}

	batches, err := h.store.ListBatches(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	type PublicRootEntry struct {
		BatchID       string `json:"batch_id"`
		StartedAt     string `json:"started_at"`
		ClosedAt      string `json:"closed_at"`
		EventCount    int    `json:"event_count"`
		MerkleRootHex string `json:"merkle_root_hex"`
		SignatureHex  string `json:"signature_hex"`
		KeyVersion    string `json:"key_version"`
	}

	entries := make([]PublicRootEntry, 0, len(batches))
	for _, b := range batches {
		entries = append(entries, PublicRootEntry{
			BatchID:       b.ID,
			StartedAt:     b.StartedAt.Format(time.RFC3339),
			ClosedAt:      b.ClosedAt.Format(time.RFC3339),
			EventCount:    b.EventCount,
			MerkleRootHex: hex.EncodeToString(b.MerkleRoot),
			SignatureHex:  hex.EncodeToString(b.Signature),
			KeyVersion:    b.KeyVersion,
		})
	}

	writeJSON(w, http.StatusOK, ResponseEnvelope{
		Data: entries,
		Meta: map[string]interface{}{"count": len(entries), "limit": limit, "offset": offset},
	})
}

// PublicVerifyProofHandler verifies an independently provided record proof and signature.
func (h *Handler) PublicVerifyProofHandler(w http.ResponseWriter, r *http.Request) {
	type VerifyRequest struct {
		RecordCanonical merkle.RecordCanonicalPayload `json:"record"`
		Proof           []merkle.ProofNode            `json:"proof"`
		MerkleRootHex   string                        `json:"merkle_root_hex"`
		SignatureHex    string                        `json:"signature_hex"`
		KeyVersion      string                        `json:"key_version"`
		PublicKeyBase64 string                        `json:"public_key_base64,omitempty"`
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid json payload: "+err.Error())
		return
	}

	expectedRoot, err := hex.DecodeString(req.MerkleRootHex)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid merkle_root_hex")
		return
	}
	signature, err := hex.DecodeString(req.SignatureHex)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid signature_hex")
		return
	}

	// 1. Verify signature
	var pubKey ed25519.PublicKey
	if req.PublicKeyBase64 != "" {
		pkBytes, err := base64.StdEncoding.DecodeString(req.PublicKeyBase64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid public_key_base64")
			return
		}
		pubKey = ed25519.PublicKey(pkBytes)
	} else {
		pkBytes, err := h.signer.PublicKey(r.Context(), req.KeyVersion)
		if err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Public key not found for version: "+req.KeyVersion)
			return
		}
		pubKey = ed25519.PublicKey(pkBytes)
	}

	sigValid := ed25519.Verify(pubKey, expectedRoot, signature)
	if !sigValid {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"valid":          false,
			"failure_reason": "invalid digital signature",
		})
		return
	}

	// 2. Compute record leaf hash
	leafHash, err := merkle.ComputeRecordLeafHash(req.RecordCanonical)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"valid":          false,
			"failure_reason": "failed to compute leaf hash: " + err.Error(),
		})
		return
	}

	// 3. Verify Merkle proof
	proofValid := merkle.VerifyProof(leafHash, req.Proof, expectedRoot)
	if !proofValid {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"valid":          false,
			"failure_reason": "merkle proof does not match expected root",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":       true,
		"verified_at": time.Now().UTC().Format(time.RFC3339),
	})
}
