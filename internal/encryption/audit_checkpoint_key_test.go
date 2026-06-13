package encryption

import (
	"bytes"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditCheckpointKey_DerivedAndStable(t *testing.T) {
	svc, _ := newTestService(t, "test-passphrase-for-unit-tests")

	key, ver, ok := svc.AuditCheckpointKey()
	require.True(t, ok, "an enabled+initialised service must yield a checkpoint key")
	assert.Len(t, key, 32, "checkpoint key is 32 bytes")
	assert.NotEmpty(t, ver, "key version is reported")

	// Deterministic for the same DEK.
	key2, ver2, ok2 := svc.AuditCheckpointKey()
	require.True(t, ok2)
	assert.True(t, bytes.Equal(key, key2), "derivation is stable for a fixed DEK")
	assert.Equal(t, ver, ver2)

	// Domain separation: the checkpoint key is not the raw DEK.
	dek := svc.keyManager.GetDEK()
	assert.False(t, bytes.Equal(key, dek), "checkpoint key must be HKDF-derived, not the DEK itself")
}

func TestAuditCheckpointKey_UnavailableWhenDisabled(t *testing.T) {
	// Encryption disabled → no DEK → no checkpoint key.
	svc := NewService(&config.EncryptionConfig{Enabled: false}, t.TempDir())
	_, _, ok := svc.AuditCheckpointKey()
	assert.False(t, ok, "a disabled service has no signing key")

	// Enabled but not initialised → also unavailable.
	svc2 := NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	_, _, ok2 := svc2.AuditCheckpointKey()
	assert.False(t, ok2, "an uninitialised service has no DEK yet")
}
