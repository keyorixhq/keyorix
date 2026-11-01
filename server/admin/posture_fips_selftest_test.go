package admin

import (
	"crypto/fips140"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRunAdminValidatePosture_FIPSSelfTestLine: `admin validate --posture`
// carries the boot self-test line next to the Go FIPS mode line. Outside
// fips140=only it says the self-test was not run (never "passed"); under
// fips140=only it runs the self-test in this process and reports the result.
func TestRunAdminValidatePosture_FIPSSelfTestLine(t *testing.T) {
	yaml := `
locale:
  language: en
  fallback_language: en
storage:
  type: postgres
  database:
    host: 127.0.0.1
    port: "1"
    name: keyorix
    user: keyorix
    ssl_mode: verify-full
  encryption:
    enabled: false
security:
  enable_file_permission_check: false
  require_transport_tls: false
`
	cfgPath, cfg := writePostureFixture(t, yaml, 0600)

	out, _ := captureStdout(t, func() error { return runAdminValidatePosture(cfg, cfgPath) })
	if fips140.Enforced() {
		assert.Contains(t, out, "fips140 enforced: yes, self-test passed")
		assert.NotContains(t, out, "[fips140/")
	} else {
		assert.Contains(t, out, "fips140 enforced: no (self-test not run)")
	}
}
