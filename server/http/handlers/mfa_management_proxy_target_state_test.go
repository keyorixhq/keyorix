// mfa_management_proxy_target_state_test.go — setTestAuthEncryptor, shared by
// every test in this package that exercises an MFA proxy handler needing an
// enabled auth encryptor. (UpsertMFASecretProxy itself -- the G80 overnight
// campaign, Tier 1 Group A fix #4 this file originally covered -- was deleted:
// G80 liveness sweep found no live caller; see docs/g80-remediation-notes.md.)
package handlers

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/stretchr/testify/require"
)

// setTestAuthEncryptor wires a real, enabled auth encryptor onto cs, mirroring
// internal/core/mfa_test.go's newMFATestCore setup but callable from outside
// the core package (exported API only).
func setTestAuthEncryptor(t *testing.T, cs *core.KeyorixCore) {
	t.Helper()
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("g80-test-passphrase"))
	cs.SetAuthEncryptor(enc)
}
