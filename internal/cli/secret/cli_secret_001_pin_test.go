// cli_secret_001_pin_test.go — permanent regression pin for cli-secret-001
// (CRITICAL): `keyorix secret update`'s embedded-mode path used to call a bare
// storage/core constructor instead of common.InitializeCoreService(), which
// silently bypassed at-rest AES-256-GCM secret-value encryption even when
// storage.encryption.enabled was true. Fixed in commit 76dbc529 (PR #1395) —
// see update.go:68-76's #G66 comment for the fix itself.
//
// This test proves the fix by driving the REAL CLI entrypoint (runUpdate) end
// to end against a real embedded config with encryption enabled, then reading
// the stored SecretVersion row back through the RAW storage layer (bypassing
// core's decryption) to assert the persisted bytes are genuinely ciphertext,
// not the plaintext value runUpdate was asked to write.
package secret

import (
	"context"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCliSecret001_UpdateEmbeddedMode_EncryptsAtRest(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	// Embedded mode: no remote server/token configured, so runUpdate takes the
	// direct-storage branch under test rather than runUpdateRemote.
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "some-test-passphrase")

	cfg := "storage:\n" +
		"  type: local\n" +
		"  database:\n" +
		"    path: ./secrets.db\n" +
		"  encryption:\n" +
		"    enabled: true\n" +
		"    dek_path: ./dek.bin\n" +
		"    salt_path: ./salt.bin\n"
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(cfg), 0o600))

	ctx := context.Background()

	// Seed a project/environment/secret via the same embedded core service
	// runUpdate itself uses, so the fixture and the code under test share one
	// wired encryptor (and the same KEK-derivation lock) instead of racing two.
	svc, err := common.InitializeCoreService()
	require.NoError(t, err, "embedded core service (encryption enabled) must initialize cleanly")

	proj, err := svc.CreateProject(ctx, "cli-secret-001-proj", "")
	require.NoError(t, err)
	envs, err := svc.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs, "a new project must have a default environment")

	const plaintextV1 = "cli-secret-001-original-value"
	secret, err := svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          "cli-secret-001-target",
		Value:         []byte(plaintextV1),
		Type:          "generic",
		ProjectID:     proj.ID,
		EnvironmentID: envs[0].ID,
		CreatedBy:     "cli-secret-001-test",
	})
	require.NoError(t, err)

	// Drive the REAL CLI entrypoint for `secret update --value`, matching this
	// package's convention (save/restore package-level flag vars via
	// t.Cleanup, see secret_s24_test.go).
	origID, origValue, origFromFile, origInteractive := updateID, updateValue, updateFromFile, updateInteractive
	origType, origMaxReads, origExpiration, origClearExp := updateType, updateMaxReads, updateExpiration, updateClearExp
	t.Cleanup(func() {
		updateID = origID
		updateValue = origValue
		updateFromFile = origFromFile
		updateInteractive = origInteractive
		updateType = origType
		updateMaxReads = origMaxReads
		updateExpiration = origExpiration
		updateClearExp = origClearExp
	})

	const plaintextV2 = "cli-secret-001-updated-value-must-not-appear-in-plaintext"
	updateID = secret.ID
	updateValue = plaintextV2
	updateFromFile = ""
	updateInteractive = false
	updateType = ""
	updateMaxReads = -1
	updateExpiration = ""
	updateClearExp = false

	require.NoError(t, runUpdate(updateCmd, nil))

	// Read the new version back through the RAW storage layer — NOT through
	// service.GetSecretValue/core's decryption path — so the assertion sees
	// exactly what got persisted, not what core hands back after decrypting.
	rawStorage, err := common.InitializeStorage()
	require.NoError(t, err)

	versions, err := rawStorage.GetSecretVersions(ctx, secret.ID)
	require.NoError(t, err)
	require.Len(t, versions, 2, "create + update must produce two stored versions")

	latest := versions[0] // GetSecretVersions returns newest-first
	assert.Equal(t, 2, latest.VersionNumber)

	// The bug under test: a bypassed-encryption write stores the literal
	// plaintext bytes in EncryptedValue. Assert that never happens.
	assert.NotEqual(t, []byte(plaintextV2), latest.EncryptedValue,
		"stored EncryptedValue must not be the literal plaintext runUpdate was asked to write")
	assert.NotContains(t, string(latest.EncryptedValue), plaintextV2,
		"ciphertext must not contain the plaintext value as a substring")

	// And the positive assertion: the row is marked as genuinely encrypted with
	// the expected at-rest algorithm (ADR-004 envelope AES-256-GCM), not the
	// empty "{}" plaintext marker written when no encryptor is wired.
	require.NotEmpty(t, latest.EncryptionMetadata)
	assert.Contains(t, string(latest.EncryptionMetadata), `"algorithm":"AES-256-GCM"`,
		"EncryptionMetadata must record the AES-256-GCM envelope, not an empty/plaintext marker")
}
