//go:build e2e

package e2e

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// verifyAuditChain runs `keyorix-server admin verify-audit` directly against
// the smoke run's own database file/DSN (server/admin/audit_verify.go's
// --db/--pg-dsn mode, which never touches the serverguard lock the running
// server itself holds -- see that file's own openVerifyAuditTarget doc
// comment) while the server is STILL RUNNING, proving the tamper-evidence
// hash chain this smoke run just generated (every create/update/delete
// above writes an audit event) verifies clean. Exit code 0 = VALID; any
// other code (1 BROKEN, 2 INDETERMINATE, 3 usage error) fails the test --
// this smoke run should never produce anything but a clean, complete chain.
func verifyAuditChain(t *testing.T, srv *harness.Server, backend harness.DBBackend) {
	t.Helper()
	args := []string{"admin", "verify-audit", "--json"}
	if backend.VerifyAuditFlag != nil {
		args = append(args, backend.VerifyAuditFlag(srv.Dir)...)
	} else {
		// SQLite default: admin init wrote storage.database.path relative to
		// srv.Dir (configs/keyorix.yaml.tpl's "keyorix.db" default).
		args = append(args, "--db", filepath.Join(srv.Dir, "keyorix.db"))
	}
	cmd := exec.Command(srv.Binary, args...) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e harness itself built or downloaded, with the harness's own fixed arguments; no external input reaches it
	cmd.Dir = srv.Dir
	cmd.Env = srv.Env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("keyorix-server admin verify-audit (%s) did not report VALID: %v\n%s",
			backend.Name, err, out)
	}
	if !strings.Contains(string(out), `"verdict"`) && !strings.Contains(string(out), "VALID") {
		t.Fatalf("keyorix-server admin verify-audit (%s): unexpected output, no VALID verdict found:\n%s",
			backend.Name, out)
	}
	t.Logf("verify-audit (%s): %s", backend.Name, out)
}

// parseLibpqDSN does a minimal, deliberately-not-exhaustive parse of a
// libpq-style "key=value key2=value2" DSN string into a map -- just enough
// to pull host/port/dbname/user/sslmode back out for the YAML config
// rewrite in api_smoke_test.go's pgDatabaseYAML. Values are not expected to
// contain spaces (docker postgres:16 test DSNs don't), so no quoting support
// is needed.
func parseLibpqDSN(dsn string) map[string]string {
	out := map[string]string{}
	for _, field := range strings.Fields(dsn) {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			continue
		}
		out[kv[0]] = strings.Trim(kv[1], "'\"")
	}
	return out
}
