package signing

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidPassphrase = errors.New("invalid passphrase or corrupted keyfile")
	ErrKeyNotFound       = errors.New("key version not found")
	ErrDecryptionFailed  = errors.New("decryption failed")
)

// Signer defines the interface for cryptographic signing and verification.
type Signer interface {
	Sign(ctx context.Context, digest []byte) (signature []byte, keyVersion string, err error)
	Verify(ctx context.Context, digest, signature []byte, keyVersion string) (bool, error)
	PublicKey(ctx context.Context, keyVersion string) ([]byte, error)
}

// Encryptor defines the interface for PII field-level encryption at rest.
type Encryptor interface {
	Encrypt(ctx context.Context, plaintext []byte) (ciphertext []byte, keyVersion string, err error)
	Decrypt(ctx context.Context, ciphertext []byte, keyVersion string) ([]byte, error)
}

// KeyfileEnvelope is the encrypted-at-rest container on disk.
type KeyfileEnvelope struct {
	Salt       string `json:"salt"`       // base64
	Nonce      string `json:"nonce"`      // base64
	Ciphertext string `json:"ciphertext"` // base64
}

// KeyfilePayload is the plaintext secrets structure protected in memory.
type KeyfilePayload struct {
	Version              string            `json:"version"`
	Ed25519PrivateKey    string            `json:"ed25519_private_key"` // base64
	Ed25519PublicKey     string            `json:"ed25519_public_key"`  // base64
	AES256Key            string            `json:"aes256_key"`          // base64
	HistoricalPublicKeys map[string]string `json:"historical_public_keys,omitempty"`
}

// LocalKeyManager implements both Signer and Encryptor backed by a local encrypted keyfile.
type LocalKeyManager struct {
	version              string
	privateKey           ed25519.PrivateKey
	publicKey            ed25519.PublicKey
	aesKey               []byte
	historicalPublicKeys map[string]ed25519.PublicKey
}

// Argon2id parameters
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
)

// GenerateAndSaveKeyfile creates a new keypair and AES key, encrypts with passphrase, and saves to filePath (0600).
func GenerateAndSaveKeyfile(filePath string, passphrase string, version string) (*LocalKeyManager, error) {
	if version == "" {
		version = "v1"
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 keypair: %w", err)
	}

	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	payload := KeyfilePayload{
		Version:              version,
		Ed25519PrivateKey:    base64.StdEncoding.EncodeToString(privKey),
		Ed25519PublicKey:     base64.StdEncoding.EncodeToString(pubKey),
		AES256Key:            base64.StdEncoding.EncodeToString(aesKey),
		HistoricalPublicKeys: make(map[string]string),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	kdfKey := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	block, err := aes.NewCipher(kdfKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, payloadJSON, nil)

	envelope := KeyfileEnvelope{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	envelopeJSON, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal keyfile envelope: %w", err)
	}

	// Restrictive file permissions (0600: read/write owner only)
	if err := os.WriteFile(filePath, envelopeJSON, 0600); err != nil {
		return nil, fmt.Errorf("failed to write keyfile: %w", err)
	}

	return &LocalKeyManager{
		version:              version,
		privateKey:           privKey,
		publicKey:            pubKey,
		aesKey:               aesKey,
		historicalPublicKeys: make(map[string]ed25519.PublicKey),
	}, nil
}

// LoadKeyfile reads and decrypts an encrypted keyfile using the passphrase.
func LoadKeyfile(filePath string, passphrase string) (*LocalKeyManager, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyfile: %w", err)
	}

	var envelope KeyfileEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("invalid keyfile format: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(envelope.Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt in keyfile: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce in keyfile: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext in keyfile: %w", err)
	}

	kdfKey := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	block, err := aes.NewCipher(kdfKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrInvalidPassphrase
	}

	var payload KeyfilePayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("corrupted keyfile payload: %w", err)
	}

	privKeyBytes, err := base64.StdEncoding.DecodeString(payload.Ed25519PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key in keyfile: %w", err)
	}
	pubKeyBytes, err := base64.StdEncoding.DecodeString(payload.Ed25519PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key in keyfile: %w", err)
	}
	aesBytes, err := base64.StdEncoding.DecodeString(payload.AES256Key)
	if err != nil {
		return nil, fmt.Errorf("invalid AES key in keyfile: %w", err)
	}

	histMap := make(map[string]ed25519.PublicKey)
	for ver, b64Pub := range payload.HistoricalPublicKeys {
		pBytes, err := base64.StdEncoding.DecodeString(b64Pub)
		if err == nil {
			histMap[ver] = ed25519.PublicKey(pBytes)
		}
	}

	return &LocalKeyManager{
		version:              payload.Version,
		privateKey:           ed25519.PrivateKey(privKeyBytes),
		publicKey:            ed25519.PublicKey(pubKeyBytes),
		aesKey:               aesBytes,
		historicalPublicKeys: histMap,
	}, nil
}

// Sign signs a digest using the Ed25519 private key.
func (m *LocalKeyManager) Sign(ctx context.Context, digest []byte) ([]byte, string, error) {
	if len(m.privateKey) == 0 {
		return nil, "", errors.New("private key not available")
	}
	sig := ed25519.Sign(m.privateKey, digest)
	return sig, m.version, nil
}

// Verify verifies an Ed25519 signature against the digest and key version.
func (m *LocalKeyManager) Verify(ctx context.Context, digest, signature []byte, keyVersion string) (bool, error) {
	var pubKey ed25519.PublicKey
	if keyVersion == m.version {
		pubKey = m.publicKey
	} else if hist, ok := m.historicalPublicKeys[keyVersion]; ok {
		pubKey = hist
	} else {
		return false, fmt.Errorf("%w: %s", ErrKeyNotFound, keyVersion)
	}

	valid := ed25519.Verify(pubKey, digest, signature)
	return valid, nil
}

// PublicKey returns the raw public key bytes for a given key version.
func (m *LocalKeyManager) PublicKey(ctx context.Context, keyVersion string) ([]byte, error) {
	if keyVersion == "" || keyVersion == m.version {
		return m.publicKey, nil
	}
	if hist, ok := m.historicalPublicKeys[keyVersion]; ok {
		return hist, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyVersion)
}

// CurrentVersion returns the active key version.
func (m *LocalKeyManager) CurrentVersion() string {
	return m.version
}

// Encrypt encrypts plaintext using AES-256-GCM.
func (m *LocalKeyManager) Encrypt(ctx context.Context, plaintext []byte) ([]byte, string, error) {
	block, err := aes.NewCipher(m.aesKey)
	if err != nil {
		return nil, "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, m.version, nil
}

// Decrypt decrypts AES-256-GCM ciphertext.
func (m *LocalKeyManager) Decrypt(ctx context.Context, ciphertext []byte, keyVersion string) ([]byte, error) {
	if keyVersion != m.version {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyVersion)
	}

	block, err := aes.NewCipher(m.aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrDecryptionFailed
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}
