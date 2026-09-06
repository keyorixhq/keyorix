// cli_remote_mode_behavior_test.go — the behavioral counterpart to
// cli_remote_check_guard_test.go's AST guard. That guard proves a remote
// check is PRESENT in a command's file; this test proves it actually WORKS,
// by walking the real, live rootCmd registry (not a hand-maintained list),
// running every leaf command as a real subprocess with a remote server
// configured but unreachable, and asserting the command (a) exits non-zero
// and (b) never creates or opens a local database file — instead of silently
// falling back to embedded storage and reporting success.
//
// A command added next month is covered automatically: the walk finds it via
// rootCmd.Commands(), not via an entry someone has to remember to add here.
package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// cliBehaviorAllowlist is the exhaustive, reasoned inventory of every leaf
// command this behavioral guard does NOT hold to the
// "unreachable-remote-must-fail-closed-with-no-local-file" standard, keyed by
// full command path (e.g. "migrate user-to-machine"). Two categories:
//   - "local-only": the command has no server-side equivalent at all and is
//     EXPECTED to touch local storage/files regardless of remote config
//     (though it should still refuse loudly when remote IS configured -- see
//     cliRemoteCheckAllowlist's entry for the same command).
//   - "no-backend": the command never touches storage/network either way
//     (pure local computation, e.g. printing version info), so this test's
//     premise doesn't apply.
//
// This intentionally starts small. Every internal/cli leaf command NOT listed
// here is held to the standard by this test today. Commands not yet reached
// by this pass are NOT silently assumed safe -- see the "not yet audited"
// note in this file's own TestMain-adjacent doc for what remains unverified.
var cliBehaviorAllowlist = map[string]string{
	"migrate user-to-machine": "local-only: no server-side equivalent; refuses loudly at runtime when " +
		"remote is configured (see internal/cli/migrate/user_to_machine.go), which itself is a non-zero " +
		"exit with no local file touched -- but the refusal message differs from the " +
		"connection-refused-shaped failure this test's dummy args are tuned for, so it's listed " +
		"explicitly rather than relying on ExactArgs(1) coincidentally producing the same outcome.",

	// The six entries below were investigated individually (2026-09-05) against the
	// same standard as every fixed command: does this command silently perform a
	// business/secrets operation against local storage when a remote server was
	// configured for it? None of internal/cli/auth/auth.go, internal/cli/config/
	// config.go, internal/cli/connect/connect.go, or internal/cli/project/current.go
	// call common.InitializeCoreService or common.InitializeStorage ANYWHERE in the
	// file (confirmed by grep, not assumed) -- so none of them can exhibit that bug
	// class at all: there is no local secrets/business storage for them to fall back
	// to. Each one's entire job is reading or writing one specific local CLI config
	// file (~/.keyorix/cli.yaml or ./keyorix.yaml), which is the intended, designed
	// behavior in exactly the same sense 'keyorix connect' must write cli.yaml as its
	// entire purpose. (internal/cli/auth/auth.go's OTHER leaf command, "auth login",
	// is NOT listed here: unlike these six, it printed "Successfully authenticated"
	// without ever verifying the given credentials against the server, which was a
	// real, separate bug -- fixed by adding a GET /auth/profile round-trip before
	// persisting or claiming success, which now makes it fail closed here too.)
	"auth status": "reads only ./keyorix.yaml (the legacy config 'auth login'/'config set-remote' write) " +
		"and reports its storage.type honestly, including truthfully reporting \"No configuration found\" " +
		"when that one file is absent -- it never calls InitializeCoreService/InitializeStorage, so it " +
		"cannot silently run a business operation against local storage. Known, separate limitation (not " +
		"the bug this guard targets): it does not consult KEYORIX_SERVER/KEYORIX_TOKEN env vars or " +
		"~/.keyorix/cli.yaml the way common.ResolveRemote() does for newer remote-mode commands, so a " +
		"deployment configured purely via env vars or 'keyorix connect' reports as unconfigured here even " +
		"though other commands would correctly go remote -- 'keyorix connect status' is the command that " +
		"reports that resolution chain. Flagged for a possible follow-up, not fixed in this pass.",
	"config set-remote": "its entire purpose is to WRITE ./keyorix.yaml's remote settings -- the write is " +
		"the feature, exactly like 'keyorix connect' writing ~/.keyorix/cli.yaml. It never calls " +
		"InitializeCoreService/InitializeStorage, so it cannot silently run a business operation against " +
		"local storage instead of remote. Its success message (\"Configuration updated successfully\") " +
		"only claims to have written the file, which is literally true -- it does not claim the server is " +
		"reachable or the API key is valid (unlike the 'auth login' bug this pass fixed); a separate " +
		"'config test-connection' command exists specifically to verify reachability after the fact.",
	"config use-local": "its entire purpose is to WRITE ./keyorix.yaml switching storage.type back to " +
		"local -- the write is the feature; there is no remote operation to defer to, since enabling local " +
		"mode is unconditionally a local-file change. Never calls InitializeCoreService/InitializeStorage. " +
		"Its success message only claims the config file was updated, which is literally true.",
	"connect disconnect": "its entire purpose is to WRITE ~/.keyorix/cli.yaml switching the CLI back to " +
		"embedded mode -- the write is the feature, the CLIConfig analogue of 'config use-local'. Never " +
		"calls InitializeCoreService/InitializeStorage. Its success message only claims the config file " +
		"was updated / already in embedded mode, which is literally true.",
	"connect status": "read-only report of ~/.keyorix/cli.yaml's persisted connection state (mode, " +
		"endpoint, timeout) plus a best-effort reachability probe it already reports as ✅/❌ inline -- " +
		"never calls InitializeCoreService/InitializeStorage, so it cannot silently run a business " +
		"operation against local storage. Reports \"Embedded Mode\" truthfully when no client-mode config " +
		"has been saved, which is the CLIConfig file's actual, true state.",
	"project current": "reads only the local 'active project' pointer (KEYORIX_PROJECT env var, or " +
		"ActiveProject in ~/.keyorix/cli.yaml) -- a CLI-side convenience selection with no server-side " +
		"equivalent to defer to, the same category as 'kubectl config current-context' or 'gcloud config " +
		"get-value project'. Never calls InitializeCoreService/InitializeStorage. Truthfully reports \"No " +
		"active project set\" when neither source has one, regardless of remote reachability.",
}

// leafCommand is one runnable (non-group) cobra command discovered by walking
// rootCmd, with the full argv path needed to reach it.
type leafCommand struct {
	path []string // e.g. []string{"user", "suspend"}
	cmd  *cobra.Command
}

func (l leafCommand) fullPath() string { return strings.Join(l.path, " ") }

// walkLeafCommands returns every leaf (runnable) command reachable from
// root, in a stable order. A command counts as a leaf if it has a Run/RunE
// function -- cobra allows a command to have both children and its own RunE,
// but none of this repo's group commands (user, group, ...) do, so "has
// RunE" and "has no children" coincide in practice; checked defensively.
func walkLeafCommands(root *cobra.Command) []leafCommand {
	var out []leafCommand
	var walk func(cmd *cobra.Command, path []string)
	walk = func(cmd *cobra.Command, path []string) {
		if cmd.Runnable() {
			out = append(out, leafCommand{path: append([]string(nil), path...), cmd: cmd})
		}
		for _, child := range cmd.Commands() {
			if child.Hidden || child.Name() == "help" || child.Name() == "completion" {
				continue
			}
			walk(child, append(path, child.Name()))
		}
	}
	for _, child := range root.Commands() {
		if child.Hidden || child.Name() == "help" || child.Name() == "completion" {
			continue
		}
		walk(child, []string{child.Name()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].fullPath() < out[j].fullPath() })
	return out
}

// cliPositionalArgOverrides supplies dummy positional arguments for the
// small number of commands that require them (cobra's Args validators, e.g.
// cobra.ExactArgs(1), aren't introspectable the way MarkFlagRequired's
// annotation is) -- required flags are discovered automatically below and
// need no entry here. A command needing positional args that's missing from
// this map fails cobra's own arg-count validation before reaching any
// backend-resolution code, which under-tests (not over-clears) that one
// command until this map is updated -- a bounded, honest limitation, not a
// silent pass for a command already known to be broken.
var cliPositionalArgOverrides = map[string][]string{
	"migrate user-to-machine": {"dummy-test-username"},
}

// dummyValueForFlag returns a syntactically valid, semantically meaningless
// value for a required flag, keyed off pflag's own reported Value.Type().
func dummyValueForFlag(f *pflag.Flag) string {
	switch f.Value.Type() {
	case "bool":
		return "true"
	case "int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64":
		return "999999"
	case "float32", "float64":
		return "1"
	case "duration":
		return "1h"
	default: // string, stringArray, stringSlice, etc.
		return "test-dummy-value"
	}
}

// requiredFlagArgs returns "--flag=value" for EVERY local flag cmd declares
// (not just ones marked required via MarkFlagRequired's cobra annotation).
// This is deliberately broader than "required-only": many commands in this
// codebase validate a flag manually in RunE (`if createName == "" { return
// errors.New(...) }`) rather than via cobra's annotation mechanism, which a
// required-only synthesis would miss entirely -- the command would fail on
// that manual check before ever reaching the remote-vs-local decision this
// test exists to exercise, trivially "passing" without testing anything
// (confirmed happening for group/create.go's --name during this test's own
// construction). Populating every flag, required-annotated or not, gets
// past both validation styles uniformly with no per-command hand-mapping.
// Persistent/inherited flags (--help, the global passphrase-source flags)
// are deliberately NOT populated here -- they're shared root-level flags,
// not per-command required inputs, and setting them could change behavior
// in ways unrelated to what this test checks.
func requiredFlagArgs(cmd *cobra.Command) []string {
	var args []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		args = append(args, fmt.Sprintf("--%s=%s", f.Name, dummyValueForFlag(f)))
	})
	return args
}

// TestCLILeafCommands_FailClosedWhenConfiguredRemoteIsUnreachable is the
// behavioral guard: builds the real keyorix binary once, then for every leaf
// command not in cliBehaviorAllowlist, runs it as a subprocess with
// KEYORIX_SERVER pointed at an address nothing listens on and KEYORIX_TOKEN
// set, HOME/XDG_CONFIG_HOME/cwd all isolated to a fresh empty temp directory
// per command, and asserts the process exits non-zero AND the temp directory
// remains completely empty (no secrets.db, no -wal/-shm sidecar, no stray
// config file written as a side effect).
func TestCLILeafCommands_FailClosedWhenConfiguredRemoteIsUnreachable(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary and spawns one subprocess per CLI command; skipped in -short")
	}

	binPath := buildCLIBinary(t)
	leaves := walkLeafCommands(rootCmd)
	if len(leaves) == 0 {
		t.Fatal("walkLeafCommands found zero commands -- the walk itself is broken")
	}

	tested := 0
	for _, leaf := range leaves {
		fp := leaf.fullPath()
		if reason, ok := cliBehaviorAllowlist[fp]; ok {
			t.Logf("skipping %q (allowlisted: %s)", fp, reason)
			continue
		}
		tested++
		t.Run(fp, func(t *testing.T) {
			runCommandExpectingFailClosed(t, binPath, leaf)
		})
	}
	if tested == 0 {
		t.Fatal("every discovered leaf command was allowlisted -- this test would silently assert nothing; " +
			"that's almost certainly a bug in the allowlist or the walk, not a real state")
	}
}

func runCommandExpectingFailClosed(t *testing.T, binPath string, leaf leafCommand) {
	t.Helper()
	scratch := t.TempDir()

	args := append([]string(nil), leaf.path...)
	args = append(args, requiredFlagArgs(leaf.cmd)...)
	args = append(args, cliPositionalArgOverrides[leaf.fullPath()]...)

	cmd := exec.Command(binPath, args...)
	cmd.Dir = scratch
	cmd.Env = []string{
		"HOME=" + scratch,
		"XDG_CONFIG_HOME=" + scratch,
		"PATH=/usr/bin:/bin",
		// Loopback on a port nothing listens on: the kernel replies ECONNREFUSED
		// immediately (no 5s defaultConnectTimeout wait needed), unlike a
		// non-routable external block which can hang until the OS routing layer
		// gives up -- with ~100+ commands under test, that difference is the gap
		// between a fast test and one that takes tens of minutes.
		"KEYORIX_SERVER=http://127.0.0.1:1",
		"KEYORIX_TOKEN=test-dummy-token",
	}
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Errorf("command %q succeeded (exit 0) against an unreachable configured remote -- output:\n%s", leaf.fullPath(), out)
	}

	entries, rerr := os.ReadDir(scratch)
	if rerr != nil {
		t.Fatalf("reading scratch dir after running %q: %v", leaf.fullPath(), rerr)
	}
	if len(entries) > 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("command %q created file(s) in an empty scratch directory instead of failing closed "+
			"against the unreachable remote: %v -- output:\n%s", leaf.fullPath(), names, out)
	}
}

// buildCLIBinary compiles the real keyorix CLI binary once per test run
// (shared across every subtest via t.Cleanup on the parent test's TempDir,
// since Go caches nothing here deliberately -- this must be the actual
// current source, not a stale cached binary from a previous run).
func buildCLIBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "keyorix")
	repoRoot := findRepoRoot(t)
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build keyorix CLI binary: %v\n%s", err, out)
	}
	return binPath
}

// findRepoRoot walks up from the current test file's directory to the
// directory containing go.mod, since this test needs to invoke `go build .`
// against the repo root (where main.go lives), not the internal/cli package
// directory this test file itself resides in.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find go.mod walking up from %s", dir)
		}
		dir = parent
	}
}
