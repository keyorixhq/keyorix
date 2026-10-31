package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// CONFIG-TRUTH-1 item 1 (#3830): the bootstrap token and the Vault connector token
// are answered from config.Load's *_FILE boot snapshot (SECRETENV-REVIEW-1 F5/F6),
// not by re-opening the file. Before the fix both called secretenv.Lookup, so a file
// swapped or removed after Load -- after the permission check judged it -- supplied
// the token.

const snapshotBootstrapToken = "judged-bootstrap-token-0123456789abcdef0123456789"

// loadWithSecretFiles writes a minimal config (plus extra YAML), points each
// <name>_FILE at a 0600 file holding the value, clears the plain variable, and
// loads the config so the snapshot holds them. It returns the file paths.
func loadWithSecretFiles(t *testing.T, extraYAML string, secrets map[string]string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	paths := map[string]string{}
	for name, value := range secrets {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(value+"\n"), 0o600))
		t.Setenv(name, "")
		t.Setenv(name+"_FILE", p)
		paths[name] = p
	}
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("environment: test\n"+extraYAML), 0o600))
	_, err := config.Load(cfgPath)
	require.NoError(t, err)
	return paths
}

func swapSecretFile(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".new"
	require.NoError(t, os.WriteFile(tmp, []byte(content+"\n"), 0o600))
	require.NoError(t, os.Rename(tmp, path))
}

func TestResolveBootstrapToken_AnsweredFromBootSnapshot(t *testing.T) {
	t.Run("file removed after Load: token still found", func(t *testing.T) {
		paths := loadWithSecretFiles(t, "", map[string]string{"KEYORIX_BOOTSTRAP_TOKEN": snapshotBootstrapToken})
		require.NoError(t, os.Remove(paths["KEYORIX_BOOTSTRAP_TOKEN"]))
		got, err := resolveBootstrapToken()
		require.NoError(t, err, "the snapshot holds the judged bytes; a vanished file must not fail or empty the token")
		assert.Equal(t, snapshotBootstrapToken, got)
	})
	t.Run("file swapped after Load: judged token, not the swapped one", func(t *testing.T) {
		paths := loadWithSecretFiles(t, "", map[string]string{"KEYORIX_BOOTSTRAP_TOKEN": snapshotBootstrapToken})
		swapSecretFile(t, paths["KEYORIX_BOOTSTRAP_TOKEN"], "swapped-bootstrap-token-fedcba9876543210fedcba98765")
		got, err := resolveBootstrapToken()
		require.NoError(t, err)
		assert.Equal(t, snapshotBootstrapToken, got, "a file changed after boot must not be re-read")
	})
}

func vaultConnectorYAML(tokenEnv string) string {
	return "connect:\n  enabled: true\n  connectors:\n    - name: v\n      type: vault\n      address: https://vault.invalid:8200\n      scope: platform\n      token_env: " + tokenEnv + "\n"
}

func TestResolveVaultToken_AnsweredFromBootSnapshot(t *testing.T) {
	const judged = "hvs.judged-vault-token"
	t.Run("file removed after Load: token still found", func(t *testing.T) {
		paths := loadWithSecretFiles(t, vaultConnectorYAML("KX_CT1_VAULT_TOK"), map[string]string{"KX_CT1_VAULT_TOK": judged})
		require.NoError(t, os.Remove(paths["KX_CT1_VAULT_TOK"]))
		got, err := resolveVaultToken("KX_CT1_VAULT_TOK")
		require.NoError(t, err)
		assert.Equal(t, judged, got)
	})
	t.Run("file swapped after Load: judged token, not the swapped one", func(t *testing.T) {
		paths := loadWithSecretFiles(t, vaultConnectorYAML("KX_CT1_VAULT_TOK"), map[string]string{"KX_CT1_VAULT_TOK": judged})
		swapSecretFile(t, paths["KX_CT1_VAULT_TOK"], "hvs.swapped")
		got, err := resolveVaultToken("KX_CT1_VAULT_TOK")
		require.NoError(t, err)
		assert.Equal(t, judged, got)
	})
	t.Run("default VAULT_TOKEN name", func(t *testing.T) {
		paths := loadWithSecretFiles(t, "connect:\n  enabled: true\n  connectors:\n    - name: v\n      type: vault\n      address: https://vault.invalid:8200\n      scope: platform\n", map[string]string{"VAULT_TOKEN": judged})
		require.NoError(t, os.Remove(paths["VAULT_TOKEN"]))
		got, err := resolveVaultToken("")
		require.NoError(t, err)
		assert.Equal(t, judged, got)
	})
}
