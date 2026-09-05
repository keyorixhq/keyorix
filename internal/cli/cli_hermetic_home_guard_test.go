// cli_hermetic_home_guard_test.go — a guard against the exact defect class
// that broke internal/cli/invite's and internal/cli/migrate's own test suites
// during this same review (2026-09-05): most of their tests never isolated
// HOME/XDG_CONFIG_HOME, so a real developer machine's ~/.keyorix/cli.yaml
// silently redirected them into remote mode, where they failed against
// whatever address that file happened to name.
//
// Per-package TestMain fixes (see internal/cli/invite/main_test.go,
// internal/cli/migrate/main_test.go) close today's two known instances, but
// each one only proves that ONE package is hermetic -- a package added later,
// or an existing package whose tests grow a new code path that reaches
// common.ResolveRemote/cliconfig.LoadCLIConfig, is not covered by either fix
// and the gap is invisible until it breaks on somebody's contaminated
// machine (as it did here) or, worse, silently changes what a test actually
// exercises without failing at all -- a non-hermetic test can mask a real
// bug as easily as cause a false failure, and that direction leaves no
// symptom to notice.
//
// This guard catches BOTH directions structurally: it runs every internal/cli
// package's test suite twice, identically except for HOME/XDG_CONFIG_HOME --
// once pointed at an empty, isolated directory, once pointed at a directory
// poisoned with a ~/.keyorix/cli.yaml naming a sentinel unreachable server --
// and asserts the pass/fail outcome of every single (sub)test is identical
// between the two runs. Any test whose outcome depends on HOME/XDG_CONFIG_HOME
// is non-hermetic by definition, regardless of which direction it broke.
package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// cliHermeticGuardChildEnv, when set, tells this guard's own test body to
// skip immediately -- otherwise the `go test ./internal/cli/...` subprocess
// this guard spawns would recursively re-run this same guard, which would
// spawn two more subprocesses, and so on.
const cliHermeticGuardChildEnv = "KEYORIX_HERMETIC_GUARD_CHILD"

func TestCLIPackagesAreHermeticToRealHOMEAndXDGConfigHome(t *testing.T) {
	if os.Getenv(cliHermeticGuardChildEnv) != "" {
		t.Skip("running as a child of this guard's own subprocess run -- skip to avoid infinite recursion")
	}
	if testing.Short() {
		t.Skip("runs the entire internal/cli test suite twice (~2 baseline + ~2 poisoned minutes); skipped in -short")
	}

	repoRoot := findRepoRoot(t)

	baseline := runCLISuiteWithHome(t, repoRoot, t.TempDir())

	poisoned := t.TempDir()
	writePoisonedCLIConfig(t, poisoned)
	poisonedResults := runCLISuiteWithHome(t, repoRoot, poisoned)

	var diverged []string
	for name, base := range baseline {
		if p, ok := poisonedResults[name]; !ok {
			diverged = append(diverged, fmt.Sprintf("%s: present with HOME=isolated (%s) but missing with HOME=poisoned", name, base))
		} else if p != base {
			diverged = append(diverged, fmt.Sprintf("%s: %s with HOME=isolated but %s with HOME=poisoned", name, base, p))
		}
	}
	for name, p := range poisonedResults {
		if _, ok := baseline[name]; !ok {
			diverged = append(diverged, fmt.Sprintf("%s: missing with HOME=isolated but present (%s) with HOME=poisoned", name, p))
		}
	}
	sort.Strings(diverged)
	if len(diverged) > 0 {
		t.Errorf("found %d internal/cli (sub)test(s) whose pass/fail outcome depends on HOME/XDG_CONFIG_HOME "+
			"(i.e. they read a real ~/.keyorix/cli.yaml instead of being isolated -- see internal/cli/invite/main_test.go "+
			"for the fix pattern):\n%s", len(diverged), strings.Join(diverged, "\n"))
	}
	if len(baseline) == 0 {
		t.Fatal("baseline run produced zero test results -- this guard's own subprocess invocation is broken, not proof everything is hermetic")
	}
}

// goEnv returns `go env <key>` from the CURRENT (real) environment, cached
// per test run -- used to pin the child subprocess's toolchain paths so
// overriding HOME doesn't redirect them (see runCLISuiteWithHome).
func goEnv(t *testing.T, key string) string {
	t.Helper()
	out, err := exec.Command("go", "env", key).Output()
	if err != nil {
		t.Fatalf("go env %s: %v", key, err)
	}
	return strings.TrimSpace(string(out))
}

// writePoisonedCLIConfig plants a ~/.keyorix/cli.yaml naming a sentinel,
// deterministically-unreachable server (loopback, port 1 -- an instant
// ECONNREFUSED, not a hang) at the given HOME/XDG_CONFIG_HOME directory,
// reproducing the exact shape of the real developer-machine file that broke
// invite/migrate's tests.
func writePoisonedCLIConfig(t *testing.T, homeDir string) {
	t.Helper()
	cliDir := filepath.Join(homeDir, ".keyorix")
	if err := os.MkdirAll(cliDir, 0o700); err != nil {
		t.Fatalf("creating poisoned .keyorix dir: %v", err)
	}
	const contents = `mode: client
active_project: ""
embedded:
    database_path: ./secrets.db
client:
    endpoint: http://127.0.0.1:1
    auth:
        type: api_key
        api_key: hermetic-guard-sentinel-key
    timeout: 1s
connections: []
`
	if err := os.WriteFile(filepath.Join(cliDir, "cli.yaml"), []byte(contents), 0o600); err != nil {
		t.Fatalf("writing poisoned cli.yaml: %v", err)
	}
}

// runCLISuiteWithHome runs `go test ./internal/cli/...` as a subprocess with
// HOME pointed at homeDir, and returns a map of "package/TestName[/SubTest]"
// -> "pass"/"fail"/"skip" parsed from `-json` output. KEYORIX_SERVER/
// KEYORIX_TOKEN are explicitly cleared, and XDG_CONFIG_HOME is explicitly
// BLANKED (not pointed at homeDir) so only HOME differs between the two
// calls this guard makes.
//
// XDG_CONFIG_HOME is deliberately left blank rather than redirected: internal/
// cli/config's getDefaultCLIConfigPath() checks XDG_CONFIG_HOME FIRST, and
// only falls back to $HOME/.keyorix/cli.yaml when it is unset -- the exact
// shape of the real bug this guard exists to catch (this dev machine has no
// XDG_CONFIG_HOME set, so its own leftover ~/.keyorix/cli.yaml was reached via
// the HOME fallback, not the XDG branch). Pointing XDG_CONFIG_HOME at homeDir
// too would make the poisoned config invisible (it lives at the dot-fallback
// path, not $homeDir/keyorix/cli.yaml) and silently defeat this whole guard --
// confirmed by hand: the first version of this guard did exactly that and
// passed even with a package's TestMain isolation deliberately disabled.
func runCLISuiteWithHome(t *testing.T, repoRoot, homeDir string) map[string]string {
	t.Helper()
	cmd := exec.Command("go", "test", "-json", "-count=1", "./internal/cli/...")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"HOME="+homeDir,
		"XDG_CONFIG_HOME=",
		"KEYORIX_SERVER=",
		"KEYORIX_TOKEN=",
		cliHermeticGuardChildEnv+"=1",
		// Overriding HOME also redirects Go's OWN toolchain: GOPATH/GOCACHE/
		// GOMODCACHE default to paths under $HOME when not set explicitly as
		// env vars, which most machines don't do. Without pinning these to
		// their real values, `go test` silently re-resolves its module cache
		// into homeDir, triggering a full re-download/rebuild (slow) and,
		// worse, leaves read-only extracted module files under t.TempDir()
		// that its own cleanup then fails to remove ("permission denied").
		// Only HOME/XDG_CONFIG_HOME -- what keyorix's OWN config resolution
		// reads -- should differ between the two calls this guard makes.
		"GOPATH="+goEnv(t, "GOPATH"),
		"GOCACHE="+goEnv(t, "GOCACHE"),
		"GOMODCACHE="+goEnv(t, "GOMODCACHE"),
	)
	out, err := cmd.Output()
	// A nonzero exit is expected whenever any test fails -- that's exactly the
	// information this guard compares between runs, not a reason to abort.
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("running go test ./internal/cli/... (HOME=%s): %v", homeDir, err)
		}
	}

	results := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		var ev struct {
			Action  string
			Package string
			Test    string
		}
		if jerr := json.Unmarshal(scanner.Bytes(), &ev); jerr != nil {
			continue // non-JSON build/tool-output lines interleave with -json events; skip them
		}
		if ev.Test == "" {
			continue // package-level event, not an individual test result
		}
		switch ev.Action {
		case "pass", "fail", "skip":
			results[ev.Package+"/"+ev.Test] = ev.Action
		}
	}
	return results
}
