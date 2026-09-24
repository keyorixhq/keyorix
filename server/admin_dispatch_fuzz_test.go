package main

import (
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/server/admin"
)

// adminKnownSubcommands mirrors server/admin's actual command-tree
// registration: the real top-level subcommands (server/admin/admin.go's
// init(), rootCmd.AddCommand(initCmd/validateCmd/auditCmd/diagnoseCmd/
// migrateCmd), plus encryptionCmd and verifyAuditCmd registered by their own
// files' init()s), cobra's own two auto-added builtins ("help" is always added; "completion"
// is auto-added by Execute() the first time a root command with
// subcommands and no CompletionOptions.DisableDefaultCmd runs — neither is
// set here), and the test-only hidden command server/admin/testhook.go
// registers unconditionally via its own init(). Duplicated here rather than
// exported from admin, matching this repo's convention of a harness owning
// its own fixture/expectation shapes instead of a production package
// growing a test-only export. If admin.go ever registers a new subcommand
// without this list being updated, the failure mode is loud (a real,
// now-recognized subcommand wrongly flagged "unrecognized" by oracle 4
// below), not a silent pass-through.
var adminKnownSubcommands = map[string]bool{
	"init":     true,
	"validate": true,
	"audit":    true,
	"diagnose": true,
	"migrate":  true,
	// server/admin/encryption.go's own rootCmd.AddCommand(encryptionCmd)
	// (ADR-108 §B3, #2034) and server/admin/audit_verify.go's own
	// rootCmd.AddCommand(verifyAuditCmd) (ADR-108 §B4, #2039) -- both real,
	// already-merged top-level subcommands this map had not been updated for.
	"encryption":   true,
	"verify-audit": true,
	// cobra builtins, auto-registered on any multi-command root:
	"help":       true,
	"completion": true,
	// server/admin/testhook.go's hidden, test-only lock-holder command.
	"__hold-lock-for-test": true,
}

// splitArgvForFuzz turns one fuzzed string into an argv-shaped []string:
// whitespace-separated tokens, empties dropped by strings.Fields itself, and
// capped at 64 tokens so a pathological huge token count doesn't dominate a
// fuzz run's wall-clock budget independent of fuzzutil.Guard's own per-call
// timeout.
func splitArgvForFuzz(raw string) []string {
	fields := strings.Fields(raw)
	if len(fields) > 64 {
		fields = fields[:64]
	}
	return fields
}

// FuzzAdminDispatch fuzzes argv-shaped input against ADR-108 §B's dispatch
// decision end to end: isAdminDispatch's own routing predicate (server/
// main.go) and — whenever it routes to admin — admin.Execute's real cobra
// command tree (server/admin). Oracle:
//
//  1. isAdminDispatch's routing decision is EXACTLY
//     "len(args) > 1 && args[1] == \"admin\"" for every input, matching its
//     own doc comment's promise that this is the ONLY thing that diverts
//     from the plain server flag path — so
//     --passphrase-fd/--passphrase-file/--passphrase-stdin and every other
//     flag keep their existing, documented meaning for every non-"admin"
//     first token, unchanged, for any fuzzer-chosen argv shape.
//  2. admin.Execute never panics and never hangs (fuzzutil.Guard's timeout
//     budget) — ADR-108 §B's "no admin command ever starts an HTTP or gRPC
//     listener" promise would manifest here as a call that never returns; a
//     real offline host-side operation against an unreachable/garbage
//     config always fails fast instead.
//  3. admin.Execute's exit code is always 0 or 1 (its own documented
//     contract — see Execute's doc comment in server/admin/admin.go), never
//     anything else -- except verify-audit, whose exit code is a documented
//     four-way verdict (0/1/2/3, design §6), checked separately below.
//  4. `admin <unrecognized-token>` (with no -h/--help anywhere in argv, and
//     the first admin-args token not itself a flag) must return a NON-ZERO
//     exit code — cobra's own "unknown command" error path, never a silent
//     0/no-op.
func FuzzAdminDispatch(f *testing.F) {
	// raw represents argv AFTER the program name (os.Args[1:]) -- the harness
	// below prepends "keyorix-server" itself to reconstruct an os.Args-shaped
	// slice (matching main.go's real isAdminDispatch(os.Args) call), so a seed
	// must NOT repeat "keyorix-server" as its own leading token. A seed that
	// does is silently self-defeating: the doubled "keyorix-server" lands at
	// args[1] instead of "admin"/the real first flag, isAdminDispatch correctly
	// (if uselessly) reports dispatch=false for it, and the whole admin.Execute
	// path this fuzzer exists to drive (oracles 2-4 below) never fires for that
	// seed at all -- it only ever exercises the trivial "not admin" branch.
	// Confirmed 2026-09-24: every one of this target's original seeds (as
	// landed in #2036) had exactly this defect.
	seeds := []string{
		"",
		"admin",
		"admin init --config x.yaml",
		"admin init --force",
		"admin validate",
		"admin audit",
		"admin diagnose",
		"admin migrate",
		"admin migrate --force --config /nonexistent.yaml",
		"admin bogus-subcommand",
		"admin --help",
		"admin -h",
		"admin init -h",
		"admin __hold-lock-for-test",
		"admin encryption shamir-split",
		"admin encryption --help",
		"admin verify-audit",
		"-passphrase-fd 3",
		"-passphrase-stdin",
		"--passphrase-file /run/secrets/pw",
		"-admin",
		"-h",
		"administrate",
		"foo",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		args := append([]string{"keyorix-server"}, splitArgvForFuzz(raw)...)

		var dispatch bool
		fuzzutil.Guard(t.Fatalf, "isAdminDispatch", func() { dispatch = isAdminDispatch(args) })

		want := len(args) > 1 && args[1] == "admin"
		if dispatch != want {
			t.Fatalf("isAdminDispatch(%q) = %v, want %v", args, dispatch, want)
		}
		if !dispatch {
			// Plain server flag path — not admin.Execute's concern, and not
			// safely re-invocable per fuzz iteration (flag.Parse/global flag
			// state — see main_test.go's own isolation notes). The routing
			// decision itself, asserted above, is the whole contract this
			// non-dispatch branch needs to keep.
			return
		}

		// Isolate every admin command's filesystem side effects (a relative
		// default config path, a local SQLite file admin init/migrate might
		// open) to a throwaway directory — this harness fuzzes DISPATCH and
		// argument handling, not what a real admin command does to a real
		// database, and a fuzzed --config value should never be able to
		// write into this repo's own working tree. config.Load resolves its
		// relative default ("keyorix.yaml") against "." at call time, so
		// os.Chdir here genuinely changes what a bare `admin migrate` (no
		// --config) resolves against.
		if origWD, err := os.Getwd(); err == nil {
			if os.Chdir(t.TempDir()) == nil {
				defer func() { _ = os.Chdir(origWD) }()
			}
		}

		adminArgs := args[2:]
		var code int
		fuzzutil.Guard(t.Fatalf, "admin.Execute", func() { code = admin.Execute(adminArgs) })

		// verify-audit is the one documented exception to admin.Execute's own
		// 0/1 contract (admin.go's own doc comment above Execute): its exit
		// code is a four-way verdict (0 valid / 1 broken / 2 indeterminate /
		// 3 couldn't-run, design §6), not a plain success/failure bit.
		if len(adminArgs) > 0 && adminArgs[0] == "verify-audit" {
			if code < 0 || code > 3 {
				t.Fatalf("admin.Execute(%q) returned exit code %d, want 0-3 (verify-audit's documented four-way verdict)", adminArgs, code)
			}
		} else if code != 0 && code != 1 {
			t.Fatalf("admin.Execute(%q) returned exit code %d, want 0 or 1", adminArgs, code)
		}

		if len(adminArgs) == 0 {
			return // bare "admin": cobra's own documented show-help behavior
		}
		first := adminArgs[0]
		if strings.HasPrefix(first, "-") {
			return // a flag as the first token — cobra's own flag-parsing path, not the subcommand-lookup oracle 4 targets
		}
		for _, a := range adminArgs {
			if a == "-h" || a == "--help" {
				return // help always exits 0 by cobra's own design, regardless of subcommand validity
			}
		}
		if !adminKnownSubcommands[first] && code == 0 {
			t.Fatalf("admin.Execute(%q): unrecognized subcommand %q returned exit code 0 (silent no-op), want a non-zero error exit", adminArgs, first)
		}
	})
}
