package startup

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fastAuditConfigYAML is a minimal, otherwise-valid config for the given
// storage type, with the ADR-112 Amendment 1 fast audit mode either absent or
// explicitly set — so the arms of each case below differ by exactly one line.
//
// No SQLite + setting arm exists on purpose: that combination cannot pass
// config validation at all (Postgres-only, Andrei's decision 2026-10-05), and
// internal/config's TestConfigValidate_RejectsFastAuditModeOnSQLite is where
// that refusal is tested. Writing one here would just re-test the refusal
// through a function whose job is posture reporting.
func fastAuditConfigYAML(storageType, absDBPath string, skipDurableSync bool) string {
	var dbBlock string
	switch storageType {
	case "local", "sqlite":
		dbBlock = fmt.Sprintf("    path: %q\n", absDBPath)
	case "postgres":
		dbBlock = "    host: db\n    name: keyorix\n    user: keyorix\n"
	}
	if skipDurableSync {
		dbBlock += "    insecure_audit_skip_durable_sync: true\n"
	}
	return fmt.Sprintf(`
storage:
  type: %s
  database:
%s  encryption:
    enabled: false

server:
  http:
    enabled: false
  grpc:
    enabled: false

security:
  enable_file_permission_check: false
`, storageType, dbBlock)
}

// TestValidateStartup_ReportsFastAuditModeAsAPostureDeviation covers all three
// states ADR-112 Amendment 1 distinguishes, in both the human-readable
// Warnings list and the structured InsecureSettings slice.
//
// All three, not just the interesting one. A guard that only checked the
// in-effect case would stay green if the deviation were appended
// unconditionally (making every default install look deviant), and a guard
// that only checked in-effect and off would stay green if the ignored case
// were reported as a durability weakening — which is precisely what Andrei's
// decision rules out.
func TestValidateStartup_ReportsFastAuditModeAsAPostureDeviation(t *testing.T) {
	t.Run("default off: no deviation, no structured entry", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "keyorix.yaml")
		writeConfig(t, configPath, fastAuditConfigYAML("local", filepath.Join(dir, "secrets.db"), false))

		result, err := ValidateStartup(configPath, false)
		require.NoError(t, err)
		assert.NotContains(t, result.Warnings, AuditDurableSyncSkippedWarning,
			"a default install must report ZERO fast-audit-mode deviations -- ADR-112 §4's own gate is that "+
				"the posture report shows no deviation on the default configuration")
		assert.Empty(t, result.InsecureSettings,
			"a setting nobody configured must not appear in the structured posture list at all; an entry with "+
				"Configured=false would make every consumer filter it out by hand")
	})

	t.Run("postgres, in effect: reported as a weakening", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "keyorix.yaml")
		writeConfig(t, configPath, fastAuditConfigYAML("postgres", "", true))

		result, err := ValidateStartup(configPath, false)
		require.NoError(t, err)
		assert.Contains(t, result.Warnings, AuditDurableSyncSkippedWarning,
			"on Postgres with the setting on, ValidateStartup must report the deviation -- this Warnings list "+
				"IS the posture surface `admin validate` prints until #2478's dedicated report lands. "+
				"Warnings seen: %v", result.Warnings)

		st := requireFastAuditEntry(t, result)
		assert.True(t, st.Configured)
		assert.True(t, st.InEffect, "Postgres is the supported backend; the setting really is in effect")
		assert.Empty(t, st.NotInEffectReason,
			"an in-effect setting must carry no not-in-effect reason, or a consumer cannot use a non-empty "+
				"reason as the signal for the ignored state")

		// The line has to name the setting and point somewhere, or an operator
		// learns something is wrong but not what or where.
		assert.Contains(t, AuditDurableSyncSkippedWarning, "storage.database.insecure_audit_skip_durable_sync")
		assert.Contains(t, AuditDurableSyncSkippedWarning, "docs/security/hardening-guide.md")
	})

	// NO "remote, ignored" arm here, and the omission is deliberate rather
	// than an oversight: Validate rejects storage.type: remote
	// UNCONDITIONALLY for a server config (validateRemoteStorageNotServer,
	// ADR-083), so ValidateStartup returns on that error long before it reaches
	// the posture block and can never observe the ignored state. The rule
	// itself is tested directly against the pure function in
	// internal/config's TestAuditDurableSyncStatus; the reachability claim is
	// pinned by the test below, so if remote ever becomes server-reachable
	// this file goes red and gains the missing arm.
}

// TestValidateStartup_RemoteConfigIsRejectedBeforePostureReporting pins the
// reachability fact the omission above rests on, instead of leaving it as a
// comment that can silently stop being true (CLAUDE.md: "when a verdict
// depends on a condition, guard the condition, not the conclusion").
//
// If ADR-083 is ever relaxed so a server CAN run with storage.type: remote,
// this test fails — and that failure is the instruction to add the
// "remote, configured but ignored" posture arm, which
// config.AuditDurableSyncStatus already returns the right answer for.
func TestValidateStartup_RemoteConfigIsRejectedBeforePostureReporting(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "keyorix.yaml")
	writeConfig(t, configPath, `
storage:
  type: remote
  database:
    path: ""
  encryption:
    enabled: false

server:
  http:
    enabled: false
  grpc:
    enabled: false

security:
  enable_file_permission_check: false
`)

	result, err := ValidateStartup(configPath, false)
	require.Error(t, err,
		"storage.type: remote must be rejected for a server config (ADR-083). If this now SUCCEEDS, remote "+
			"has become server-reachable and TestValidateStartup_ReportsFastAuditModeAsAPostureDeviation needs "+
			"its 'remote, configured but ignored' arm added back -- config.AuditDurableSyncStatus already "+
			"returns InEffect=false with the reason for it.")
	assert.Contains(t, err.Error(), "remote storage is a CLI/client mode only",
		"the rejection must still be ADR-083's, not some other error that happens to fail for a different "+
			"reason -- otherwise this test would pass while the reachability claim became false")
	require.NotNil(t, result)
	assert.Empty(t, result.InsecureSettings,
		"a config that never validated must not have had posture entries computed for it")
}

// requireFastAuditEntry returns the fast audit mode's structured posture entry,
// failing if it is absent or duplicated. Duplication matters: two entries for
// one setting would let a consumer read whichever it saw first and get a
// different answer.
func requireFastAuditEntry(t *testing.T, result *ValidationResult) InsecureSettingStatus {
	t.Helper()
	var found []InsecureSettingStatus
	for _, s := range result.InsecureSettings {
		if s.Name == AuditSkipDurableSyncSettingName {
			found = append(found, s)
		}
	}
	require.Lenf(t, found, 1,
		"expected exactly 1 structured posture entry named %q, got %d: %+v",
		AuditSkipDurableSyncSettingName, len(found), result.InsecureSettings)
	require.NotEmpty(t, found[0].Describe,
		"every structured entry needs its one-line Describe, in the shape ADR-112's registry (#2454) uses")
	return found[0]
}
