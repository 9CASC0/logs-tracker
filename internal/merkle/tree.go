package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

var (
	ErrEmptyTree       = errors.New("cannot build merkle tree from empty leaves")
	ErrIndexOutOfRange = errors.New("leaf index out of range")
)

// RecordCanonicalPayload represents the normalized, deterministic JSON payload for Merkle hashing.
type RecordCanonicalPayload struct {
	ID              string          `json:"id"`
	BatchID         string          `json:"batch_id"`
	TableName       string          `json:"table_name"`
	PrimaryKey      json.RawMessage `json:"primary_key"`
	EventType       string          `json:"event_type"`
	BeforeImage     json.RawMessage `json:"before_image,omitempty"`
	AfterImage      json.RawMessage `json:"after_image,omitempty"`
	ActorUserID     *string         `json:"actor_user_id,omitempty"`
	ActorType       string          `json:"actor_type"`
	TransactionID   string          `json:"transaction_id"`
	SchemaVersion   string          `json:"schema_version"`
	CommittedAt     string          `json:"committed_at"` // RFC3339Nano
	MerkleLeafIndex int             `json:"merkle_leaf_index"`
}

// ProofNode represents one step in a Merkle authentication path.
type ProofNode struct {
	Hash   []byte `json:"hash"`
	IsLeft bool   `json:"is_left"` // true if sibling is left of current node
}

// Tree represents a Merkle tree constructed over batch records.
type Tree struct {
	leaves [][]byte
	levels [][][]byte
	root   []byte
}

// HashLeaf computes the RFC 6962 leaf hash: SHA-256(0x00 || data).
func HashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// HashInterior computes the RFC 6962 interior node hash: SHA-256(0x01 || left || right).
func HashInterior(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// ComputeRecordLeafHash produces the deterministic leaf hash for a record.
func ComputeRecordLeafHash(payload RecordCanonicalPayload) ([]byte, error) {
	// Normalize timestamps to UTC RFC3339Nano
	if t, err := time.Parse(time.RFC3339Nano, payload.CommittedAt); err == nil {
		payload.CommittedAt = t.UTC().Format(time.RFC3339Nano)
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal canonical payload: %w", err)
	}
	return HashLeaf(data), nil
}

// BuildTree builds a deterministic Merkle tree from an ordered slice of leaf hashes.
func BuildTree(leafHashes [][]byte) (*Tree, error) {
	if len(leafHashes) == 0 {
		emptyRoot := sha256.Sum256([]byte{})
		return &Tree{
			leaves: nil,
			levels: [][][]byte{{emptyRoot[:]}},
			root:   emptyRoot[:],
		}, nil
	}

	// Copy leaves to preserve ordering
	leaves := make([][]byte, len(leafHashes))
	for i, l := range leafHashes {
		leaves[i] = make([]byte, len(l))
		copy(leaves[i], l)
	}

	var levels [][][]byte
	levels = append(levels, leaves)

	current := leaves
	for len(current) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				parent := HashInterior(current[i], current[i+1])
				nextLevel = append(nextLevel, parent)
			} else {
				// Odd count: promote lone node to next level
				nextLevel = append(nextLevel, current[i])
			}
		}
		levels = append(levels, nextLevel)
		current = nextLevel
	}

	return &Tree{
		leaves: leaves,
		levels: levels,
		root:   current[0],
	}, nil
}

// Root returns the Merkle tree root hash.
func (t *Tree) Root() []byte {
	return t.root
}

// RootHex returns the root hash encoded as hexadecimal.
func (t *Tree) RootHex() string {
	return hex.EncodeToString(t.root)
}

// GenerateProof produces the authentication path for a leaf at index leafIndex.
func (t *Tree) GenerateProof(leafIndex int) ([]ProofNode, error) {
	if leafIndex < 0 || leafIndex >= len(t.leaves) {
		return nil, ErrIndexOutOfRange
	}

	var proof []ProofNode
	idx := leafIndex

	for levelIdx := 0; levelIdx < len(t.levels)-1; levelIdx++ {
		level := t.levels[levelIdx]
		var siblingIdx int
		var isLeft bool

		if idx%2 == 0 {
			// Current is left node, sibling is right
			siblingIdx = idx + 1
			isLeft = false
		} else {
			// Current is right node, sibling is left
			siblingIdx = idx - 1
			isLeft = true
		}

		if siblingIdx < len(level) {
			proof = append(proof, ProofNode{
				Hash:   level[siblingIdx],
				IsLeft: isLeft,
			})
		}
		// Move to parent index in next level
		idx = idx / 2
	}

	return proof, nil
}

// VerifyProof verifies that leafHash is included in a Merkle tree with expectedRoot using proof.
func VerifyProof(leafHash []byte, proof []ProofNode, expectedRoot []byte) bool {
	current := leafHash

	for _, node := range proof {
		if node.IsLeft {
			current = HashInterior(node.Hash, current)
		} else {
			current = HashInterior(current, node.Hash)
		}
	}

	if len(current) != len(expectedRoot) {
		return false
	}
	for i := range current {
		if current[i] != expectedRoot[i] {
			return false
		}
	}
	return true
}

// CanonicalSortMap returns JSON bytes for map with sorted keys for deterministic hashing.
func CanonicalJSON(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make(map[string]interface{}, len(val))
		for _, k := range keys {
			ordered[k] = val[k]
		}
		return json.Marshal(ordered)
	default:
		return json.Marshal(v)
	}
}
