package snapshot_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"auditlogd/internal/attribution"
	"auditlogd/internal/config"
	"auditlogd/internal/snapshot"
	"auditlogd/internal/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockEncryptor struct{}

func (m *mockEncryptor) Encrypt(ctx context.Context, plaintext []byte) ([]byte, string, error) {
	return []byte("enc_" + string(plaintext)), "v1", nil
}

func (m *mockEncryptor) Decrypt(ctx context.Context, ciphertext []byte, keyVersion string) ([]byte, error) {
	str := string(ciphertext)
	return []byte(strings.TrimPrefix(str, "enc_")), nil
}

func TestSnapshotBuilder(t *testing.T) {
	enc := &mockEncryptor{}
	builder := snapshot.NewBuilder(enc)

	tableCfg := config.TableConfig{
		TableName:        "customers",
		EncryptedColumns: []string{"ssn", "credit_card"},
	}

	attr := attribution.ActorAttribution{
		ActorType: "USER",
	}

	t.Run("INSERT with encrypted columns", func(t *testing.T) {
		change := source.RowChange{
			Table:  "customers",
			Action: source.EventTypeInsert,
			AfterImage: map[string]interface{}{
				"id":          101,
				"name":        "John",
				"ssn":         "123-45-6789",
				"credit_card": "4111-2222-3333-4444",
			},
		}

		rec, err := builder.BuildRecord(context.Background(), change, tableCfg, attr, "tx-1", time.Now().UTC(), 0)
		require.NoError(t, err)

		assert.Equal(t, "customers", rec.TableName)
		assert.Equal(t, "INSERT", rec.EventType)
		assert.Nil(t, rec.BeforeImage)
		assert.NotNil(t, rec.AfterImage)

		var afterMap map[string]interface{}
		err = json.Unmarshal(rec.AfterImage, &afterMap)
		require.NoError(t, err)

		// Sensitive columns must be encrypted
		assert.Contains(t, afterMap["ssn"].(string), "enc:v1:")
		assert.Contains(t, afterMap["credit_card"].(string), "enc:v1:")
		// Non-sensitive columns must remain plaintext
		assert.Equal(t, "John", afterMap["name"])

		assert.NotEmpty(t, rec.SchemaVersion)
		assert.JSONEq(t, `{"id": 101}`, string(rec.PrimaryKey))
	})

	t.Run("UPDATE with before and after images", func(t *testing.T) {
		change := source.RowChange{
			Table:  "customers",
			Action: source.EventTypeUpdate,
			BeforeImage: map[string]interface{}{
				"id":   101,
				"name": "John",
			},
			AfterImage: map[string]interface{}{
				"id":   101,
				"name": "Jonathan",
			},
		}

		rec, err := builder.BuildRecord(context.Background(), change, tableCfg, attr, "tx-2", time.Now().UTC(), 1)
		require.NoError(t, err)

		assert.Equal(t, "UPDATE", rec.EventType)
		assert.NotNil(t, rec.BeforeImage)
		assert.NotNil(t, rec.AfterImage)
	})

	t.Run("DELETE with tombstone before image only", func(t *testing.T) {
		change := source.RowChange{
			Table:  "customers",
			Action: source.EventTypeDelete,
			BeforeImage: map[string]interface{}{
				"id":   101,
				"name": "Jonathan",
			},
		}

		rec, err := builder.BuildRecord(context.Background(), change, tableCfg, attr, "tx-3", time.Now().UTC(), 2)
		require.NoError(t, err)

		assert.Equal(t, "DELETE", rec.EventType)
		assert.NotNil(t, rec.BeforeImage)
		assert.Nil(t, rec.AfterImage)
	})
}
