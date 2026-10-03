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
  allow_unsafe_file_permissions: false
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

// TestShippedProductionTemplates_ReportOnlyKnownShippedDefaultDeviations runs
// the config-only collectors over the REAL shipped templates
// (server/config/production.yaml and web-enabled.yaml), not a synthetic
// fixture built to match.
//
// Its assertion CHANGED with this PR's blocker fix, and the change is the
// point. It used to require zero deviations, which is what made excluding a
// whole class of settings from the count look necessary -- the exclusion
// existed to keep this test green. But the templates genuinely do not match
// the secure baseline: they ship TLS terminated by a fronting reverse proxy
// (so security.require_transport_tls is false) and no metrics token (so
// /metrics is unauthenticated). Hiding that to protect a green test is how the
// report came to answer "no deviations found" for an install with encryption
// at rest switched off.
//
// So the property asserted is the one that is actually true and actually
// worth guarding:
//
//  1. NO deviation from a shipped template may have origin "explicit" -- a
//     template must never ASK for a weakening.
//  2. Its shipped-default deviations are exactly a known, named list. A new
//     one appearing means someone weakened a shipped template, which is a real
//     finding and fails here; one disappearing means a default got hardened,
//     which is this ADR's goal and fails here too so the list is updated.
//
// Scoped to the config-only collectors (insecure-settings registry,
// file-permission-check toggle, TLS): the others need disk-resident key
// material these templates reference by absolute host paths that do not exist
// on this machine, or a live database.
func TestShippedProductionTemplates_ReportOnlyKnownShippedDefaultDeviations(t *testing.T) {
	// The exact weakenings the shipped templates accept today, each a
	// deliberate, documented choice -- and each still counted toward the exit
	// code, because the fix for a weak DEFAULT is to change the default (the
	// rest of ADR-112), not to stop reporting it.
	knownShippedDefaults := []string{
		// TLS terminated by a fronting reverse proxy.
		"security.insecure_allow_cleartext_transport",
		// No metrics token shipped; the templates document locking /metrics
		// down at the network layer.
		"server.insecure_allow_unauthenticated_metrics",
	}
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

			var explicit, shipped []string
			for _, d := range report.deviations {
				if d.origin == originExplicit {
					explicit = append(explicit, d.detail)
					continue
				}
				shipped = append(shipped, d.detail)
			}
			assert.Empty(t, explicit,
				"%s must never EXPLICITLY ask for a weakening; a shipped template requesting one is a real finding, got: %v",
				path, explicit)

			for _, want := range knownShippedDefaults {
				found := false
				for _, got := range shipped {
					if strings.Contains(got, want) {
						found = true
					}
				}
				assert.True(t, found,
					"%s no longer reports %s as a shipped-default deviation. If the default was HARDENED, that is "+
						"the goal — remove it from knownShippedDefaults. If it stopped being reported, that is the "+
						"#2478 blocker coming back.", path, want)
			}
			assert.Len(t, shipped, len(knownShippedDefaults),
				"%s reports a shipped-default deviation that is not in knownShippedDefaults — a shipped template "+
					"was weakened, or a new registry entry covers something these templates leave open. Got: %v",
				path, shipped)
		})
	}
}

// TestRunAdminValidatePosture_BaselineFixtureReportsOnlyKnownShippedDefaults
// is the end-to-end counterpart of the templates test above, and its assertion
// changed with this PR's blocker fix for the same reason.
//
// It used to require ZERO deviations from writeSecureBaselineConfig's fixture.
// That fixture is not actually hardened -- it disables encryption at rest
// deliberately (so the test needs no on-disk key material) and leaves
// require_transport_tls, the metrics token and API rate limiting at their
// shipped defaults. It only read as "zero" because the excluded class hid
// exactly those four. Asserting zero again would mean re-adding the exclusion.
//
// So: no deviation may be EXPLICIT, and every deviation must be one of the
// four the fixture knowingly accepts.
// TestCollectInsecureSettingsPosture_FullyHardenedConfigReportsZero below is
// what proves zero is still reachable at all.
func TestRunAdminValidatePosture_BaselineFixtureReportsOnlyKnownShippedDefaults(t *testing.T) {
	cfg := writeSecureBaselineConfig(t)

	report := &postureReport{}
	collectInsecureSettingsPosture(cfg, report)

	accepted := []string{
		"security.insecure_allow_cleartext_transport",            // fixture sets require_transport_tls: false
		"storage.encryption.insecure_disable_encryption_at_rest", // fixture disables encryption (no key material needed)
		"server.insecure_allow_unauthenticated_metrics",          // no metrics token shipped
		"server.insecure_disable_api_ratelimit",                  // rate limiting ships off
	}
	for _, d := range report.deviations {
		assert.Equal(t, originShippedDefault, d.origin,
			"the fixture must not EXPLICITLY ask for a weakening: %s", d.detail)
		matched := false
		for _, a := range accepted {
			if strings.Contains(d.detail, a) {
				matched = true
			}
		}
		assert.True(t, matched, "unexpected deviation from the baseline fixture: %s", d.detail)
	}
	assert.Len(t, report.deviations, len(accepted),
		"a deviation the fixture knowingly accepts stopped being reported — that is the #2478 blocker returning. Got: %+v",
		report.deviations)
}

// TestCollectInsecureSettingsPosture_FullyHardenedConfigReportsZero is the
// calibration that stops "count everything" degenerating into "always report
// something". If the report can never come back clean, an operator has no way
// to tell a hardened install from an unhardened one and the exit code stops
// meaning anything.
//
// Built by hardening every setting the registry reads, then asserting the
// registry itself sees nothing in effect -- derived from the registry rather
// than a hand-listed set, so a new entry whose secure state this config does
// not reach fails here and has to be considered.
func TestCollectInsecureSettingsPosture_FullyHardenedConfigReportsZero(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.RequireTransportTLS = true
	cfg.Security.EnableFilePermissionCheck = true
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Database.SSLMode = "require"
	cfg.Membership.ValidationMode = "allowlist"
	cfg.Server.HTTP.MetricsToken = "set"
	cfg.Server.GRPC.MetricsToken = "set"
	cfg.Server.HTTP.MaxRequestBodyBytes = 1 << 20
	cfg.Server.GRPC.MaxRequestBodyBytes = 1 << 20
	cfg.Server.HTTP.RateLimit.Enabled = true
	cfg.Server.GRPC.RateLimit.Enabled = true
	cfg.CredentialDelivery.Mode = "smtp"
	cfg.CredentialDelivery.SMTP.TLS = "starttls"
	cfg.Notifications.Email.TLS = "starttls"

	report := &postureReport{}
	collectInsecureSettingsPosture(cfg, report)

	assert.Empty(t, report.deviations,
		"a fully hardened config must report zero — otherwise the exit code can never distinguish a hardened "+
			"install from an unhardened one. Still in effect: %+v", report.deviations)
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

	// Asserts PRESENCE, not that this is the only deviation. A zero-value
	// Config has several other weakenings in effect (encryption off, TLS not
	// required, rate limiting off, ...) and since this PR's fix every one of
	// them counts -- so a Len(deviations, 1) assertion here would be asserting
	// the very exclusion the blocker fix removed.
	var found *postureDeviation
	for i := range report.deviations {
		if strings.Contains(report.deviations[i].detail, "security.insecure_allow_unsafe_file_permissions") {
			found = &report.deviations[i]
		}
	}
	require.NotNil(t, found, "expected the in-effect setting among the deviations, got: %v", report.deviations)
	assert.Equal(t, "insecure-setting", found.category)
	assert.Equal(t, originExplicit, found.origin, "the config file asked for this one, so it is not a shipped default")
}

// TestCollectInsecureSettingsPosture_EncryptionAtRestDisabledIsACountedDeviation
// is the red/green for this PR's blocker. It replaces
// TestCollectInsecureSettingsPosture_NeedsAndreiEntryIsInformationalNotADeviation,
// which asserted the OPPOSITE and is the test that locked the false all-clear
// in: it required that an entry whose Describe contains "NEEDS ANDREI" never
// counts toward the exit code.
//
// Encryption at rest is the starkest member of that excluded set. With it off,
// every secret value is stored in plaintext -- and nothing else in the report
// catches it, because collectKeyFileSetPosture early-returns when encryption
// is disabled (correctly: there is then no key material to check). So the old
// shape printed "No deviations found." and exited 0 for an install storing
// every secret in the clear.
//
// RED on the pre-fix body (`if strings.Contains(s.Describe, needsAndreiMarker)
// { report.info(...); continue }`): zero deviations, one informational line.
func TestCollectInsecureSettingsPosture_EncryptionAtRestDisabledIsACountedDeviation(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.EnableFilePermissionCheck = true
	cfg.Storage.Encryption.Enabled = false // secrets stored unencrypted at rest

	report := &postureReport{}
	collectInsecureSettingsPosture(cfg, report)

	var found *postureDeviation
	for i := range report.deviations {
		if strings.Contains(report.deviations[i].detail, "insecure_disable_encryption_at_rest") {
			found = &report.deviations[i]
		}
	}
	require.NotNil(t, found,
		"encryption-at-rest disabled must be a COUNTED deviation, not informational: nothing else in the "+
			"report catches it (collectKeyFileSetPosture early-returns when encryption is off), so excluding "+
			"it means an install storing every secret in plaintext prints \"No deviations found.\" and exits 0. "+
			"Got deviations=%v informational=%v", report.deviations, report.informational)
	assert.Equal(t, "insecure-setting", found.category)

	for _, line := range report.informational {
		assert.NotContains(t, line, "insecure_disable_encryption_at_rest",
			"it must not ALSO be reported as informational — that is how the old shape read as covered")
	}
}

// TestCollectInsecureSettingsPosture_EveryPreviouslyExcludedEntryNowCounts is
// the family-wide half: the old marker match covered thirteen entries, so
// fixing only the one above would leave twelve. This drives a config in which
// each of the previously-excluded settings is in effect and asserts that each
// one lands in deviations rather than informational, keyed off the registry
// itself so a future entry cannot quietly rejoin the excluded set.
//
// RED on the pre-fix body: every one of them is informational and
// report.deviations is empty.
func TestCollectInsecureSettingsPosture_EveryPreviouslyExcludedEntryNowCounts(t *testing.T) {
	// The exact shape the old marker match excluded: a zero-value config, where
	// every polarity-inverted and sentinel-valued weakening is in its weak
	// state (encryption off, TLS not required, ssl_mode unset, no metrics
	// token, rate limiting off, ...).
	cfg := &config.Config{}

	report := &postureReport{}
	collectInsecureSettingsPosture(cfg, report)

	var expected []string
	for _, s := range config.InsecureSettingsRegistry {
		if s.InEffect(cfg) && strings.Contains(s.Describe, "NEEDS ANDREI") {
			expected = append(expected, s.Name)
		}
	}
	require.NotEmpty(t, expected, "test premise broken: expected the zero-value config to put several awaiting-decision settings in effect")

	counted := make(map[string]bool, len(report.deviations))
	for _, d := range report.deviations {
		for _, name := range expected {
			if strings.Contains(d.detail, name) {
				counted[name] = true
			}
		}
	}
	for _, name := range expected {
		assert.True(t, counted[name],
			"%s is in effect and must be a COUNTED deviation — an unsettled insecure_ NAME is not a reason "+
				"to stop reporting what the setting DOES (#2478 blocker)", name)
	}
	assert.Empty(t, report.informational,
		"no in-effect weakening may be downgraded to informational, got: %v", report.informational)
}

// A weakening that is merely the current shipped default is still counted, and
// says so. This is the companion that stops the blocker fix being undone by a
// different route: an exclusion re-added as "origin shipped-default means do
// not count" would pass every test above and reopen the same hole.
func TestCollectInsecureSettingsPosture_ShippedDefaultIsLabelledButStillCounted(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.EnableFilePermissionCheck = true
	cfg.Security.RequireTransportTLS = false // production.yaml's deliberate proxy-fronted shape

	report := &postureReport{}
	collectInsecureSettingsPosture(cfg, report)

	var found *postureDeviation
	for i := range report.deviations {
		if strings.Contains(report.deviations[i].detail, "insecure_allow_cleartext_transport") {
			found = &report.deviations[i]
		}
	}
	require.NotNil(t, found, "a cleartext-transport opt-out must still be counted, got: %v", report.deviations)
	assert.Equal(t, originShippedDefault, found.origin,
		"it must be LABELLED as a shipped default so an operator can tell it from a deliberate change")
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
	// Nothing at all: a disabled listener contributes nothing, and an enabled
	// listener WITH TLS has nothing to report either. (The tls_mode
	// informational line this used to expect is behind a TODO(FIX-4) in
	// collectTLSPosture -- the field is not in this PR's base chain. Restore
	// the Len(informational, 1) assertion with it.)
	assert.Empty(t, report.informational, "an enabled+TLS listener and a disabled listener both contribute nothing")
}
