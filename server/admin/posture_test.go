package admin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// writeSecureBaselineConfig writes a self-contained, secure-compliant config
// file into dir and chdirs the test there (so config.ResolvedPath("") -- used
// internally by collectFilePermissionPosture -- resolves to it), then loads
// and returns it exactly the way runAdminValidate does. Modeled on
// configs/test.yaml's minimal shape, with every security-relevant field
// flipped to its compliant value instead of that fixture's deliberate
// everything-disabled posture.
func writeSecureBaselineConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	yaml := `
locale:
  language: en
  fallback_language: en

storage:
  type: local
  database:
    path: "posture.db"
  encryption:
    enabled: false

security:
  enable_file_permission_check: true
  insecure_allow_unsafe_file_permissions: false
  require_transport_tls: false
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yaml), 0600))
	cfg, err := config.Load("")
	require.NoError(t, err)
	// loadConfig (admin.go) always does this before any admin command touches
	// storage -- this helper bypasses loadConfig to control the YAML directly,
	// so it must replicate that one side effect, or a storage call that
	// localizes an error message panics with "i18n not initialized".
	require.NoError(t, i18n.Initialize(cfg))
	// Simulate a server that has booted at least once (the realistic target
	// of a posture check -- an operator does not run this against a config
	// whose database has never been created): without this, the database
	// file genuinely does not exist yet, and collectFilePermissionPosture's
	// ValidateStartup call would report a false permission deviation for a
	// file that simply hasn't been created, not one with a real problem.
	require.NoError(t, withUsableStorage(cfg, func(corestorage.Storage) error { return nil }))
	return cfg
}

// TestShippedProductionTemplates_ReportZeroConfigOnlyDeviations verifies the
// task's own "default install must report zero" requirement against the
// REAL shipped templates (server/config/production.yaml and web-enabled.yaml)
// -- not just a synthetic fixture built to match. Scoped to the three
// config-only collectors (insecure-settings registry, file-permission-check
// toggle, TLS): the other collectors either need disk-resident key material
// these templates reference by absolute host paths that don't exist on this
// machine (key-file-set-consistency, KEK age) or need a live database
// (admin-MFA, break-glass-review) -- both already covered on their own terms
// by the collector-level and end-to-end tests above.
func TestShippedProductionTemplates_ReportZeroConfigOnlyDeviations(t *testing.T) {
	for _, path := range []string{"../config/production.yaml", "../config/web-enabled.yaml"} {
		t.Run(path, func(t *testing.T) {
			// config.Load's traversal guard rejects a ".." path outright (it
			// reads rooted at the application directory) -- copy the real
			// template into a temp dir and chdir there so Load("") resolves
			// to the genuine, unmodified file content under its own name.
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			dir := t.TempDir()
			t.Chdir(dir)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), raw, 0600))
			cfg, err := config.Load("")
			require.NoError(t, err)

			report := &postureReport{}
			collectInsecureSettingsPosture(cfg, report)
			collectTLSPosture(cfg, report)
			if !cfg.Security.EnableFilePermissionCheck {
				report.deviate("file-permissions", "security.enable_file_permission_check is disabled")
			}

			assert.Empty(t, report.deviations, "%s must report zero config-only deviations, got: %+v", path, report.deviations)
		})
	}
}

func TestRunAdminValidatePosture_SecureBaselineConfigReportsZeroDeviations(t *testing.T) {
	cfg := writeSecureBaselineConfig(t)

	err := runAdminValidatePosture(cfg)
	require.NoError(t, err, "a config with every secure-baseline setting compliant, no admins, and no break-glass history must report zero deviations")
}

func TestRunAdminValidatePosture_AdminWithoutMFAIsADeviationAndNonZeroExit(t *testing.T) {
	cfg := writeSecureBaselineConfig(t)

	err := withUsableStorage(cfg, func(store corestorage.Storage) error {
		ctx := context.Background()
		user, err := store.CreateUser(ctx, &models.User{
			Username: "root", UsernameFolded: "root", Email: "root@x.io", EmailFolded: "root@x.io",
			IsActive: true, AccountState: core.AccountActive,
		})
		if err != nil {
			return err
		}
		roleName, err := identity.NewFoldedName("admin")
		if err != nil {
			return err
		}
		role, err := store.CreateRole(ctx, roleName, "install administrator")
		if err != nil {
			return err
		}
		return store.AssignRole(ctx, user.ID, role.ID, corestorage.Scope{})
	})
	require.NoError(t, err)

	err = runAdminValidatePosture(cfg)
	require.Error(t, err, "an admin-tier holder with no MFA must be a counted deviation")
}

func TestCollectInsecureSettingsPosture_InEffectSettingIsADeviation(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AllowUnsafeFilePermissions = true
	cfg.Security.EnableFilePermissionCheck = true

	report := &postureReport{}
	collectInsecureSettingsPosture(cfg, report)

	require.Len(t, report.deviations, 1)
	assert.Equal(t, "insecure-setting", report.deviations[0].category)
	assert.Contains(t, report.deviations[0].detail, "security.insecure_allow_unsafe_file_permissions")
}

func TestCollectInsecureSettingsPosture_NeedsAndreiEntryIsInformationalNotADeviation(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.EnableFilePermissionCheck = true
	// production.yaml ships this exact shape deliberately (TLS terminated by a
	// fronting reverse proxy) -- the registry's own NEEDS ANDREI entry for this
	// flag's polarity-inverted rename must never surface as a counted deviation,
	// or the shipped production template would never report zero.
	cfg.Security.RequireTransportTLS = false

	report := &postureReport{}
	collectInsecureSettingsPosture(cfg, report)

	assert.Empty(t, report.deviations, "a NEEDS ANDREI registry entry must never count toward the exit code")
	found := false
	for _, line := range report.informational {
		if strings.Contains(line, "pending decision") && strings.Contains(line, "insecure_allow_cleartext_transport") {
			found = true
		}
	}
	assert.True(t, found, "expected the NEEDS ANDREI entry to appear in the informational list, got: %v", report.informational)
}

func TestCollectFilePermissionPosture_ExplicitlyDisabledIsADeviation(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.EnableFilePermissionCheck = false

	report := &postureReport{}
	collectFilePermissionPosture(cfg, report)

	require.Len(t, report.deviations, 1)
	assert.Equal(t, "file-permissions", report.deviations[0].category)
	assert.Contains(t, report.deviations[0].detail, "enable_file_permission_check is disabled")
}

func TestCollectTLSPosture_CleartextWithoutRequireIsInformationalOnly(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.HTTP.Enabled = true
	cfg.Server.HTTP.TLS.Enabled = false
	cfg.Security.RequireTransportTLS = false

	report := &postureReport{}
	collectTLSPosture(cfg, report)

	assert.Empty(t, report.deviations, "production.yaml ships cleartext-by-design (reverse-proxy TLS termination); this must not be a deviation")
	assert.NotEmpty(t, report.informational)
}

func TestCollectTLSPosture_CleartextWithRequireTLSIsADeviation(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.HTTP.Enabled = true
	cfg.Server.HTTP.TLS.Enabled = false
	cfg.Security.RequireTransportTLS = true

	report := &postureReport{}
	collectTLSPosture(cfg, report)

	require.Len(t, report.deviations, 1)
	assert.Equal(t, "tls", report.deviations[0].category)
}

func TestCollectTLSPosture_TLSEnabledDisabledListenerSkipped(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.HTTP.Enabled = false
	cfg.Server.GRPC.Enabled = true
	cfg.Server.GRPC.TLS.Enabled = true

	report := &postureReport{}
	collectTLSPosture(cfg, report)

	assert.Empty(t, report.deviations)
	require.Len(t, report.informational, 1, "a disabled listener contributes nothing; the enabled+TLS one is informational only")
}
