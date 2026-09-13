package signing_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"auditlogd/internal/signing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalKeyfileManager(t *testing.T) {
	tempDir := t.TempDir()
	keyfilePath := filepath.Join(tempDir, "keys.enc")
	passphrase := "super-secure-passphrase-123"

	t.Run("generate and load keyfile", func(t *testing.T) {
		mgr, err := signing.GenerateAndSaveKeyfile(keyfilePath, passphrase, "v1")
		require.NoError(t, err)
		assert.Equal(t, "v1", mgr.CurrentVersion())

		// Verify file permissions (0600 on unix, readable by user on windows)
		info, err := os.Stat(keyfilePath)
		require.NoError(t, err)
		assert.False(t, info.IsDir())

		// Load with valid passphrase
		loaded, err := signing.LoadKeyfile(keyfilePath, passphrase)
		require.NoError(t, err)
		assert.Equal(t, "v1", loaded.CurrentVersion())

		// Load with wrong passphrase fails
		_, err = signing.LoadKeyfile(keyfilePath, "wrong-passphrase")
		assert.ErrorIs(t, err, signing.ErrInvalidPassphrase)
	})

	t.Run("signing and verification", func(t *testing.T) {
		mgr, err := signing.LoadKeyfile(keyfilePath, passphrase)
		require.NoError(t, err)

		digest := []byte("32-byte-hash-of-merkle-root-val")
		sig, ver, err := mgr.Sign(context.Background(), digest)
		require.NoError(t, err)
		assert.Equal(t, "v1", ver)
		assert.Len(t, sig, 64)

		// Verify authentic signature
		valid, err := mgr.Verify(context.Background(), digest, sig, "v1")
		require.NoError(t, err)
		assert.True(t, valid)

		// Verify tampered digest fails
		tamperedDigest := []byte("tampered-hash-of-root-000000000")
		valid, err = mgr.Verify(context.Background(), tamperedDigest, sig, "v1")
		require.NoError(t, err)
		assert.False(t, valid)

		// Verify wrong key version returns error
		_, err = mgr.Verify(context.Background(), digest, sig, "v999")
		assert.ErrorIs(t, err, signing.ErrKeyNotFound)
	})

	t.Run("aes-256-gcm pii encryption and decryption", func(t *testing.T) {
		mgr, err := signing.LoadKeyfile(keyfilePath, passphrase)
		require.NoError(t, err)

		plaintext := []byte("secret-ssn-123-45-6789")
		ciphertext, ver, err := mgr.Encrypt(context.Background(), plaintext)
		require.NoError(t, err)
		assert.Equal(t, "v1", ver)
		assert.NotEqual(t, plaintext, ciphertext)

		decrypted, err := mgr.Decrypt(context.Background(), ciphertext, "v1")
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)

		// Corrupted ciphertext fails
		corrupted := make([]byte, len(ciphertext))
		copy(corrupted, ciphertext)
		corrupted[len(corrupted)-1] ^= 0xFF
		_, err = mgr.Decrypt(context.Background(), corrupted, "v1")
		assert.ErrorIs(t, err, signing.ErrDecryptionFailed)
	})
}
