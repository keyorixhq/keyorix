package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeADR112TestConfig writes body to a temp config file and loads it via the
// real Load() entry point — not a hand-built Config{} — so these tests exercise
// the exact same yaml.Unmarshal + explicitSecurityKeys path a real deployment's
// config file goes through.
func writeADR112TestConfig(t *testing.T, body string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	cfg, err := Load(path)
	require.NoError(t, err)
	return cfg
}

// ADR-112: a config file with no security: block at all (the common shape for a
// genuinely fresh install that hasn't touched this section) must resolve both
// EnableFilePermissionCheck and RequireMFA to true, and mark both as implicit
// defaults — "fresh installs are secure from the first start" with zero
// operator action.
func TestLoad_ADR112_AbsentSecurityBlockResolvesSecureByDefault(t *testing.T) {
	cfg := writeADR112TestConfig(t, "locale:\n  language: en\n")

	assert.True(t, cfg.Security.EnableFilePermissionCheck, "enable_file_permission_check must default true")
	assert.True(t, cfg.Security.EnableFilePermissionCheckImplicitDefault, "absent key must be marked as an implicit default")
	assert.True(t, cfg.Security.RequireMFA, "require_mfa must default true")
	assert.True(t, cfg.Security.RequireMFAImplicitDefault, "absent key must be marked as an implicit default")
}

// A security: block that exists but never mentions either key — e.g. a config
// that only sets login_lockout — must behave identically to an absent block
// entirely: explicitSecurityKeys only sees keys that are actually present.
func TestLoad_ADR112_SecurityBlockPresentButKeysAbsentStillResolvesSecure(t *testing.T) {
	cfg := writeADR112TestConfig(t, "security:\n  login_lockout:\n    disabled: true\n")

	assert.True(t, cfg.Security.EnableFilePermissionCheck)
	assert.True(t, cfg.Security.EnableFilePermissionCheckImplicitDefault)
	assert.True(t, cfg.Security.RequireMFA)
	assert.True(t, cfg.Security.RequireMFAImplicitDefault)
}

// An operator who explicitly wrote `false` for either key gets exactly that
// value, with ImplicitDefault=false — ADR-112 never overrides a deliberate
// choice, it only changes what happens when the key was never mentioned at all.
func TestLoad_ADR112_ExplicitFalseIsHonoredAndNotMarkedImplicit(t *testing.T) {
	cfg := writeADR112TestConfig(t, "security:\n  enable_file_permission_check: false\n  require_mfa: false\n")

	assert.False(t, cfg.Security.EnableFilePermissionCheck)
	assert.False(t, cfg.Security.EnableFilePermissionCheckImplicitDefault)
	assert.False(t, cfg.Security.RequireMFA)
	assert.False(t, cfg.Security.RequireMFAImplicitDefault)
}

// An operator who explicitly wrote `true` (today's existing opt-in shape) keeps
// getting true, now also correctly NOT marked as an implicit default, so no
// grace-period softening applies to them (see server's enforceKeyFilePermissions
// coverage).
func TestLoad_ADR112_ExplicitTrueIsHonoredAndNotMarkedImplicit(t *testing.T) {
	cfg := writeADR112TestConfig(t, "security:\n  enable_file_permission_check: true\n  require_mfa: true\n")

	assert.True(t, cfg.Security.EnableFilePermissionCheck)
	assert.False(t, cfg.Security.EnableFilePermissionCheckImplicitDefault)
	assert.True(t, cfg.Security.RequireMFA)
	assert.False(t, cfg.Security.RequireMFAImplicitDefault)
}

// Setting only one of the two keys must not mark the other as implicit — each
// key's explicitness is tracked independently.
func TestLoad_ADR112_PartialSecurityBlockTracksEachKeyIndependently(t *testing.T) {
	cfg := writeADR112TestConfig(t, "security:\n  require_mfa: false\n")

	assert.True(t, cfg.Security.EnableFilePermissionCheck)
	assert.True(t, cfg.Security.EnableFilePermissionCheckImplicitDefault, "untouched key must stay an implicit default")
	assert.False(t, cfg.Security.RequireMFA)
	assert.False(t, cfg.Security.RequireMFAImplicitDefault, "explicitly-set key must not be marked implicit")
}

// A *Config built by hand (any caller that bypasses Load — test fixtures across
// this repo, any future one-off caller) must leave ImplicitDefault at Go's false
// zero value, so a hand-set EnableFilePermissionCheck/RequireMFA: true is read
// as deliberate, not as having "inherited the default" and eligible for the
// grace-period softening in server/main.go. This is the premise the whole
// false-by-default (rather than an "...Explicit" true-by-default) field design
// depends on.
func TestSecurityConfig_HandBuiltZeroValueIsNotImplicitDefault(t *testing.T) {
	var sc SecurityConfig
	assert.False(t, sc.EnableFilePermissionCheckImplicitDefault)
	assert.False(t, sc.RequireMFAImplicitDefault)

	sc.EnableFilePermissionCheck = true
	sc.RequireMFA = true
	assert.False(t, sc.EnableFilePermissionCheckImplicitDefault, "hand-set true must not read as an implicit default")
	assert.False(t, sc.RequireMFAImplicitDefault, "hand-set true must not read as an implicit default")
}

// Red-proof for explicitSecurityKeys itself: a value explicitly set to false
// must be indistinguishable from "absent" by the typed decode alone (both are
// the Go bool zero value) — this is the premise the whole ADR-112 mechanism
// depends on, and the reason Load() cannot just flip the struct field's default.
func TestExplicitSecurityKeys_DistinguishesAbsentFromExplicitFalse(t *testing.T) {
	absent, err := explicitSecurityKeys([]byte("locale:\n  language: en\n"))
	require.NoError(t, err)
	assert.False(t, absent["enable_file_permission_check"])

	explicit, err := explicitSecurityKeys([]byte("security:\n  enable_file_permission_check: false\n"))
	require.NoError(t, err)
	assert.True(t, explicit["enable_file_permission_check"])
}
