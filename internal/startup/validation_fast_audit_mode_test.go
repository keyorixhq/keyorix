package startup

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fastAuditConfigYAML is minimalConfigYAML (validation_s2_test.go) with the
// ADR-112 Amendment 1 fast audit mode either absent or explicitly set, so the
// two cases below differ by exactly one config line and nothing else.
func fastAuditConfigYAML(absDBPath string, skipDurableSync bool) string {
	line := ""
	if skipDurableSync {
		line = "    insecure_audit_skip_durable_sync: true\n"
	}
	return fmt.Sprintf(`
storage:
  type: local
  database:
    path: %q
%s  encryption:
    enabled: false

server:
  http:
    enabled: false
  grpc:
    enabled: false

security:
  enable_file_permission_check: false
`, absDBPath, line)
}

// TestValidateStartup_ReportsFastAuditModeAsAPostureDeviation is ADR-112
// Amendment 1's posture-surface requirement: the fast audit mode must appear
// as a deviation in the surface `keyorix-server admin validate` prints.
//
// Both directions, because a one-directional check here would be worthless:
// a guard that only asserted the warning appears when the setting is on would
// stay green if the warning were appended unconditionally, which would make
// every default install look deviant and teach operators to ignore the list.
func TestValidateStartup_ReportsFastAuditModeAsAPostureDeviation(t *testing.T) {
	t.Run("default off: no deviation reported", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "keyorix.yaml")
		writeConfig(t, configPath, fastAuditConfigYAML(filepath.Join(dir, "secrets.db"), false))

		result, err := ValidateStartup(configPath, false)
		require.NoError(t, err)
		assert.NotContains(t, result.Warnings, AuditDurableSyncSkippedWarning,
			"a default install must report ZERO fast-audit-mode deviations -- ADR-112 §4's own gate is that "+
				"the posture report shows no deviation on the default configuration")
	})

	t.Run("on: reported verbatim", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "keyorix.yaml")
		writeConfig(t, configPath, fastAuditConfigYAML(filepath.Join(dir, "secrets.db"), true))

		result, err := ValidateStartup(configPath, false)
		require.NoError(t, err)
		assert.Contains(t, result.Warnings, AuditDurableSyncSkippedWarning,
			"with storage.database.insecure_audit_skip_durable_sync set, ValidateStartup must report the "+
				"deviation -- this Warnings list IS the posture surface `admin validate` prints until #2478's "+
				"dedicated --posture report lands. Warnings seen: %v", result.Warnings)

		// The string itself has to name the setting and point somewhere, or an
		// operator reading `admin validate` learns that something is wrong but
		// not what or where.
		assert.Contains(t, AuditDurableSyncSkippedWarning, "storage.database.insecure_audit_skip_durable_sync",
			"the deviation line must name the exact setting an operator has to remove")
		assert.Contains(t, AuditDurableSyncSkippedWarning, "docs/security/hardening-guide.md",
			"the deviation line must point at the document that states the full trade-off")
	})
}
