package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// Tests for the coordinator's 2026-10-08 review of e45164f0 (items #1-#5).
// Unlike writeSecureBaselineConfig these never chdir into the config's
// directory: the posture report must validate the file it was GIVEN, so each
// test runs from an unrelated, empty working directory.

// writePostureFixture writes yamlBody as keyorix.yaml (mode perm) plus an
// existing, 0600 SQLite file into a fresh dir, chdirs to a DIFFERENT empty
// dir, and returns the config's absolute path and the loaded config.
func writePostureFixture(t *testing.T, yamlBody string, perm os.FileMode) (string, *config.Config) {
	t.Helper()
	t.Setenv("KEYORIX_CONFIG_PATH", "")
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "posture.db")
	require.NoError(t, os.WriteFile(dbPath, nil, 0600))
	body := strings.ReplaceAll(yamlBody, "{{DIR}}", dir)
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0600))
	require.NoError(t, os.Chmod(cfgPath, perm))
	t.Chdir(t.TempDir())
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, i18n.Initialize(cfg))
	return cfgPath, cfg
}

const postureFixtureYAML = `
locale:
  language: en
  fallback_language: en
storage:
  type: local
  database:
    path: "{{DIR}}/posture.db"
  encryption:
    enabled: false
security:
  enable_file_permission_check: true
  allow_unsafe_file_permissions: false
  require_transport_tls: true
`

func deviationsIn(report *postureReport, category string) []postureDeviation {
	var out []postureDeviation
	for _, d := range report.deviations {
		if d.category == category {
			out = append(out, d)
		}
	}
	return out
}

// #3: --config must be the file validated. RED when the collector resolves
// config.ResolvedPath("") instead: from an unrelated working directory that
// finds no keyorix.yaml, and the "failed to load" result is reported as
// permission/encryption/database deviations of a config nobody asked about.
func TestCollectFilePermissionPosture_ValidatesTheConfigItWasGiven(t *testing.T) {
	cfgPath, cfg := writePostureFixture(t, postureFixtureYAML, 0600)

	report := &postureReport{}
	collectFilePermissionPosture(cfg, cfgPath, report)

	assert.Empty(t, report.deviations,
		"a clean config at an explicit --config path must validate clean from any working directory; got %+v",
		report.deviations)
}

// #2 (allow_unsafe_file_permissions: false): ValidateStartup stops at the
// failed permission check, so encryption and database never ran. Exactly ONE
// deviation is real. RED on e45164f0: three deviations, two for checks that
// never ran.
func TestCollectFilePermissionPosture_UnreachedChecksAreNotDeviations(t *testing.T) {
	cfgPath, cfg := writePostureFixture(t, postureFixtureYAML, 0644) // world-readable config

	report := &postureReport{}
	collectFilePermissionPosture(cfg, cfgPath, report)

	require.Len(t, report.deviations, 1, "only the check that ran and failed is a deviation; got %+v", report.deviations)
	assert.Equal(t, "file-permissions", report.deviations[0].category)
	assert.Contains(t, report.deviations[0].detail, "unresolved issues", "the deviation must carry what the check actually found")

	var notEvaluated bool
	for _, line := range report.informational {
		if strings.Contains(line, "database validation") && strings.Contains(line, "not evaluated") {
			notEvaluated = true
		}
	}
	assert.True(t, notEvaluated, "the unreached database check must be SAID to be unevaluated, not silently dropped; info=%v",
		report.informational)
}

// #2 (allow_unsafe_file_permissions: true): the permission check RAN and
// FOUND a problem; validation carried on because it is tolerated. The
// deviation must carry what it found. RED on e45164f0: the finding went to
// result.Warnings, which was never read, so it printed "not evaluated".
func TestCollectFilePermissionPosture_ToleratedPermissionIssueIsReportedWithItsCause(t *testing.T) {
	yaml := strings.Replace(postureFixtureYAML, "allow_unsafe_file_permissions: false", "allow_unsafe_file_permissions: true", 1)
	cfgPath, cfg := writePostureFixture(t, yaml, 0644)

	report := &postureReport{}
	collectFilePermissionPosture(cfg, cfgPath, report)

	perms := deviationsIn(report, "file-permissions")
	require.Len(t, perms, 1, "got %+v", report.deviations)
	assert.NotContains(t, perms[0].detail, "not evaluated", "the check ran; it must not be reported as unevaluated")
	assert.Contains(t, perms[0].detail, "unresolved issues", "what the check found")
	assert.Contains(t, perms[0].detail, "allow_unsafe_file_permissions")
	assert.Empty(t, deviationsIn(report, "startup-validation"),
		"encryption (off) and database (reachable) both passed; got %+v", report.deviations)
}

// #1: with the permission check OFF, encryption and database validation
// still run -- the install most likely to have a real problem must not get
// the thinnest report. RED on e45164f0: it returned right after the
// "disabled" deviation, so missing key material was never reported.
func TestCollectFilePermissionPosture_CheckDisabledStillValidatesEncryptionAndDatabase(t *testing.T) {
	yaml := strings.Replace(postureFixtureYAML, "enable_file_permission_check: true", "enable_file_permission_check: false", 1)
	yaml = strings.Replace(yaml, "  encryption:\n    enabled: false\n",
		"  encryption:\n    enabled: true\n    dek_path: {{DIR}}/dek.key\n    salt_path: {{DIR}}/kek.salt\n", 1)
	cfgPath, cfg := writePostureFixture(t, yaml, 0600)

	report := &postureReport{}
	collectFilePermissionPosture(cfg, cfgPath, report)

	require.Len(t, deviationsIn(report, "file-permissions"), 1, "the disabled check itself: got %+v", report.deviations)
	enc := deviationsIn(report, "startup-validation")
	require.Len(t, enc, 1, "missing key material must be reported even with the permission check off; got %+v", report.deviations)
	assert.Contains(t, enc[0].detail, "encryption validation")
}

// #4: origin is "explicit" exactly when the config file writes one of the
// entry's SourcePaths, whatever the Describe text says. RED on e45164f0,
// which keyed origin on Describe containing "NEEDS ANDREI": production.yaml
// writes require_transport_tls: false and it was labelled shipped-default.
func TestCollectInsecureSettingsPosture_OriginIsWhatTheFileWrites(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.EnableFilePermissionCheck = true

	written := &postureReport{}
	collectInsecureSettingsPosture(cfg, map[string]bool{"security.require_transport_tls": true}, written)
	absent := &postureReport{}
	collectInsecureSettingsPosture(cfg, map[string]bool{}, absent)

	origin := func(r *postureReport) deviationOrigin {
		for _, d := range r.deviations {
			if strings.Contains(d.detail, "insecure_allow_cleartext_transport") {
				return d.origin
			}
		}
		t.Fatalf("cleartext transport must be a counted deviation either way; got %+v", r.deviations)
		return ""
	}
	assert.Equal(t, originExplicit, origin(written), "the file wrote require_transport_tls: it asked for this")
	assert.Equal(t, originShippedDefault, origin(absent), "the file is silent: this is what Load's default gives")
}

// #5: a database error must not discard the report already collected.
// RED on e45164f0: it returned before printPostureReport, so the operator saw
// only the database error and none of the config deviations it had found.
func TestRunAdminValidatePosture_DatabaseErrorStillPrintsTheReport(t *testing.T) {
	// The database path is a DIRECTORY: the storage factory cannot open it.
	yaml := strings.Replace(postureFixtureYAML, `path: "{{DIR}}/posture.db"`, `path: "{{DIR}}"`, 1)
	yaml = strings.Replace(yaml, "enable_file_permission_check: true", "enable_file_permission_check: false", 1)
	cfgPath, cfg := writePostureFixture(t, yaml, 0600)

	out, err := captureStdout(t, func() error { return runAdminValidatePosture(cfg, cfgPath) })
	require.Error(t, err, "an unqueryable database must still fail the command")

	assert.Contains(t, out, "ADR-112 Secure Baseline Posture", "the report must still be printed")
	assert.Contains(t, out, "insecure_skip_startup_validation", "deviations collected before the database error must be shown")
	assert.Contains(t, out, "database", "the database failure must be in the report, distinctly")
}
