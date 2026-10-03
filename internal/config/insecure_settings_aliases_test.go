package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// A config file using ONLY the deprecated old keys must decode exactly as if
// it had used the current insecure_ names — the whole point of "deprecated
// alias, warns when used" is that behavior is unchanged, only visibility
// changes. Exercises one setting from each of the four YAML shapes this
// mechanism has to handle: top-level security.*, security.login_lockout.*
// (nested struct), audit_checkpoints.* (its own top-level block), and
// sso.providers[].* (inside a YAML sequence).
func TestLoad_DeprecatedAliases_OldKeysStillWork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	body := `
security:
  allow_unsafe_file_permissions: true
  login_lockout:
    disabled: true
audit_checkpoints:
  disabled: true
sso:
  providers:
    - name: okta
      type: saml
      trust_asserted_email: true
      saml:
        allow_idp_initiated: false
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	cfg, err := Load(path)
	require.NoError(t, err)

	assert.True(t, cfg.Security.AllowUnsafeFilePermissions)
	assert.True(t, cfg.Security.LoginLockout.Disabled)
	assert.True(t, cfg.AuditCheckpoints.Disabled)
	require.Len(t, cfg.SSO.Providers, 1)
	assert.True(t, cfg.SSO.Providers[0].TrustAssertedEmail)
	require.NotNil(t, cfg.SSO.Providers[0].SAML)
	assert.False(t, cfg.SSO.Providers[0].SAML.AllowIDPInitiated)

	// 5, not 4: the test body sets saml.allow_idp_initiated explicitly (to
	// false) as well as the other 4 old keys above it -- "present" triggers
	// the warning regardless of the value, same as every other alias here.
	assert.Len(t, cfg.DeprecatedSettingWarnings, 5, "one warning per deprecated key found: %v", cfg.DeprecatedSettingWarnings)
	for _, w := range cfg.DeprecatedSettingWarnings {
		assert.Contains(t, w, "deprecated")
	}
}

// The current insecure_ names work exactly as before (no behavior change for
// an operator who already migrated), and produce zero deprecation warnings.
func TestLoad_DeprecatedAliases_NewKeysProduceNoWarnings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	body := `
security:
  insecure_allow_unsafe_file_permissions: true
  login_lockout:
    insecure_disable_login_lockout: true
audit_checkpoints:
  insecure_disable_audit_checkpoints: true
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	cfg, err := Load(path)
	require.NoError(t, err)

	assert.True(t, cfg.Security.AllowUnsafeFilePermissions)
	assert.True(t, cfg.Security.LoginLockout.Disabled)
	assert.True(t, cfg.AuditCheckpoints.Disabled)
	assert.Empty(t, cfg.DeprecatedSettingWarnings)
}

// When BOTH the deprecated old key and its replacement are set, the new key
// wins (not an arbitrary last-one-wins from map iteration order) and a
// specific "both set" warning fires — silently ignoring one of two
// conflicting values would be exactly the kind of silent weakening ADR-112
// exists to prevent.
func TestLoad_DeprecatedAliases_BothSetNewKeyWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	body := `
security:
  allow_unsafe_file_permissions: true
  insecure_allow_unsafe_file_permissions: false
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	cfg, err := Load(path)
	require.NoError(t, err)

	assert.False(t, cfg.Security.AllowUnsafeFilePermissions, "the explicit insecure_ key must win over the deprecated alias")
	require.Len(t, cfg.DeprecatedSettingWarnings, 1)
	assert.Contains(t, cfg.DeprecatedSettingWarnings[0], "both")
}

// A config file that mentions neither the old nor the new key for any
// registered alias produces zero warnings and leaves every renamed field at
// its ordinary zero-value default — resolveDeprecatedAliases must be a
// strict no-op on a document it has nothing to do with, not just "no error."
func TestLoad_DeprecatedAliases_NoneUsedIsANoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	require.NoError(t, os.WriteFile(path, []byte("locale:\n  language: en\n"), 0600))
	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Empty(t, cfg.DeprecatedSettingWarnings)
	assert.False(t, cfg.Security.AllowUnsafeFilePermissions)
}

// RED-proof target for resolveDeprecatedAliases itself: an old key that
// Load's strict KnownFields(true) decoder would otherwise reject outright as
// an unrecognized field (since the struct field's yaml tag was renamed) must
// never reach that decoder un-rewritten. Calling resolveDeprecatedAliases
// directly isolates this from Load's other behavior.
func TestResolveDeprecatedAliases_RewritesOldKeyToNewName(t *testing.T) {
	data := []byte("security:\n  allow_unsafe_file_permissions: true\n")
	rewritten, warnings := resolveDeprecatedAliases(data)
	require.Len(t, warnings, 1)

	var raw struct {
		Security map[string]interface{} `yaml:"security"`
	}
	require.NoError(t, yaml.Unmarshal(rewritten, &raw))
	_, oldStillPresent := raw.Security["allow_unsafe_file_permissions"]
	assert.False(t, oldStillPresent, "the old key must not survive the rewrite")
	newVal, newPresent := raw.Security["insecure_allow_unsafe_file_permissions"]
	require.True(t, newPresent, "the new key must be present after the rewrite")
	assert.Equal(t, true, newVal)
}
