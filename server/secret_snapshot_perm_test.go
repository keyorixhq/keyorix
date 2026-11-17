package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// #3830: a bootstrap-token or Vault-token file wider than 0600 is refused by the
// same permission policy as every other *_FILE secret, judged on the descriptor
// the boot snapshot read (not on a fresh stat of the path).
func TestTokenSecretFiles_WiderThan0600Refused(t *testing.T) {
	strict := func(t *testing.T, yaml string, name string, mode os.FileMode) *config.Config {
		t.Helper()
		// The mode is set before Load: the snapshot judges a file once, when it
		// first reads it, so a later chmod would not be re-judged.
		dir := t.TempDir()
		secretPath := dir + "/token"
		require.NoError(t, os.WriteFile(secretPath, []byte(snapshotBootstrapToken+"\n"), 0o600))
		require.NoError(t, os.Chmod(secretPath, mode))
		t.Setenv(name, "")
		t.Setenv(name+"_FILE", secretPath)
		cfgPath := dir + "/keyorix.yaml"
		require.NoError(t, os.WriteFile(cfgPath, []byte("environment: test\n"+yaml), 0o600))
		cfg, err := config.Load(cfgPath)
		require.NoError(t, err)
		cfg.Security.EnableFilePermissionCheck = true
		cfg.Security.EnableFilePermissionCheckImplicitDefault = false
		cfg.Security.EnableFilePermissionCheckUpgradeGrace = false
		cfg.Security.AllowUnsafeFilePermissions = false
		return cfg
	}
	cases := []struct{ label, yaml, name string }{
		{"bootstrap token", "", "KEYORIX_BOOTSTRAP_TOKEN"},
		{"default vault token", "connect:\n  enabled: true\n  connectors:\n    - name: v\n      type: vault\n      address: https://vault.invalid:8200\n      scope: platform\n", "VAULT_TOKEN"},
		{"named vault token", vaultConnectorYAML("KX_PERM_VAULT_TOK"), "KX_PERM_VAULT_TOK"},
	}
	for _, c := range cases {
		t.Run(c.label+" 0644 refused", func(t *testing.T) {
			cfg := strict(t, c.yaml, c.name, 0o644)
			_, err := cfg.EnforceSecretFilePermissions()
			require.Error(t, err)
			assert.Contains(t, err.Error(), c.name+"_FILE")
		})
		t.Run(c.label+" 0640 refused", func(t *testing.T) {
			cfg := strict(t, c.yaml, c.name, 0o640)
			_, err := cfg.EnforceSecretFilePermissions()
			require.Error(t, err)
		})
		t.Run(c.label+" 0600 accepted", func(t *testing.T) {
			cfg := strict(t, c.yaml, c.name, 0o600)
			_, err := cfg.EnforceSecretFilePermissions()
			require.NoError(t, err)
		})
	}
}
