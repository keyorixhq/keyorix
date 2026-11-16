package edge

// edge_exit_codes_test.go -- EDGE-STARTUP-NOV-1: the exit statuses a server
// that cannot start returns (server/boot_exit.go) and the directives that act
// on them in the shipped unit must name the same numbers. A renumbered constant
// or an edited unit that no longer matched would put an unfixable boot back
// into a restart loop (78), or stop retrying an outage that heals itself (75),
// with every other test green. This test parses both and compares; it does not
// boot a real systemd (pending the e2e VM).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// bootExitConstants reads the integer constants of server/boot_exit.go.
func bootExitConstants(t *testing.T) map[string]int {
	t.Helper()
	path := filepath.Join(repoRoot(t), "server", "boot_exit.go")
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.INT {
					continue
				}
				n, err := strconv.Atoi(lit.Value)
				if err != nil {
					t.Fatalf("%s: %v", name.Name, err)
				}
				out[name.Name] = n
			}
		}
	}
	return out
}

func TestSystemdUnit_ExitStatusesMatchServerConstants(t *testing.T) {
	consts := bootExitConstants(t)
	operator, ok1 := consts["exitOperatorFix"]
	dependency, ok2 := consts["exitDependencyDown"]
	if !ok1 || !ok2 {
		t.Fatalf("server/boot_exit.go no longer defines exitOperatorFix and exitDependencyDown as integer constants: %v", consts)
	}
	if operator == dependency || operator <= 2 || dependency <= 2 || operator > 255 || dependency > 255 {
		t.Fatalf("exit statuses %d and %d must differ and avoid 0-2 (success, generic failure, flag usage error)", operator, dependency)
	}

	svc := unitDirectives(t, "keyorix-server.service")["Service"]
	prevent := svc["RestartPreventExitStatus"]
	if len(prevent) != 1 {
		t.Fatalf("RestartPreventExitStatus: want exactly one line, got %v", prevent)
	}
	got := strings.Fields(prevent[0])
	if len(got) != 1 || got[0] != strconv.Itoa(operator) {
		t.Errorf("RestartPreventExitStatus=%q, want exactly %d (exitOperatorFix): an operator-fix exit must not restart, and nothing else may be listed (%d, a dependency that heals itself, must be retried)",
			prevent[0], operator, dependency)
	}

	// Restart=always must still cover the retried class, and the retry delay
	// must be a plain seconds value that is not the old 5 s loop.
	if v := svc["Restart"]; len(v) != 1 || v[0] != "always" {
		t.Errorf("Restart=%v, want always (exit %d must be retried)", v, dependency)
	}
	if v := svc["RestartForceExitStatus"]; len(v) != 0 {
		t.Errorf("RestartForceExitStatus=%v: not needed with Restart=always, and it could re-enable exit %d", v, operator)
	}
	rs := svc["RestartSec"]
	if len(rs) != 1 {
		t.Fatalf("RestartSec: want exactly one line, got %v", rs)
	}
	secs, err := strconv.Atoi(rs[0])
	if err != nil {
		t.Fatalf("RestartSec=%q: want whole seconds (the test and §7a state the delay in seconds)", rs[0])
	}
	if secs < 30 {
		t.Errorf("RestartSec=%d: a KMS or database that is down would be retried more often than every 30 s", secs)
	}
	if secs > 120 {
		t.Errorf("RestartSec=%d: the delay is for every restart, crashes included; above 120 s an unattended device is out too long", secs)
	}
}

// The guide must state the statuses the code returns (item 3): a number that
// changed in code and not in the prose would send an operator to the wrong row.
func TestEdgeGuide_StatesTheExitStatuses(t *testing.T) {
	consts := bootExitConstants(t)
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "edge-deployment.md")) //nolint:gosec // repo file
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"exitOperatorFix", "exitDependencyDown"} {
		want := "exit " + strconv.Itoa(consts[name])
		if !strings.Contains(string(raw), want) {
			t.Errorf("docs/edge-deployment.md does not say %q (%s)", want, name)
		}
	}
}
