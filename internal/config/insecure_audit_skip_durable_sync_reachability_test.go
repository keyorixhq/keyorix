// insecure_audit_skip_durable_sync_reachability_test.go — ADR-112 Amendment 1
// (FASTAUDIT-1, docs/specs/fast-audit-mode.md §S4) requires the fast audit
// mode to be settable from the config FILE ONLY: no HTTP handler, no gRPC RPC,
// no environment variable and no CLI flag may turn it on. A compromised admin
// API must not be able to silently weaken an install's durability posture
// remotely — exactly the attack keyless_mode's own guard closes, so this is
// deliberately the same mechanism applied to the same shape of setting (see
// keyless_mode_reachability_test.go, whose structure and helpers this mirrors).
//
// IDIOM-COMPLETENESS NOTE, per this repo's standing lesson ("an enumeration is
// only as complete as the idioms it knows about"). These tests recognise
// exactly TWO call shapes, and nothing else:
//
//  1. the literal Go selector `.InsecureAuditSkipDurableSync` (case-sensitive),
//     with // and /* */ comments STRIPPED first, so a doc comment that merely
//     names the field is not mistaken for a read of it;
//  2. the literal YAML key `insecure_audit_skip_durable_sync`.
//
// Both are grepped across every non-test *.go file in the main module's repo
// tree. cli/ and operator/ are excluded for the same sound structural reason
// keyless_mode's scan excludes them: they are separate Go modules with their
// own go.mod, outside the root go.work, and cannot reference this package's
// DatabaseConfig type at all.
//
// What these tests would NOT see, stated so the gap reads as considered rather
// than overlooked: a refactor that renamed the field, or copied the bool out
// into a package-level var or a differently-named second field, would be
// invisible to a grep — that is the limit of a grep-based guard rather than a
// real dataflow analysis. Anyone doing that refactor must re-derive this list.
// It would also not catch a NEW env-var source added via config.resolveSecret,
// which only handles string secrets and cannot produce a bool; a new bool-
// from-env helper would need its own entry in
// TestInsecureAuditSkipDurableSync_NotSettableFromTheEnvironment below.
package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// insecureAuditSkipDurableSyncAllowedFiles is the exhaustive, reasoned
// inventory of every non-test file OUTSIDE internal/config allowed to
// reference the raw field at all.
//
// IT IS DELIBERATELY EMPTY, and that is the invariant this file now enforces.
// After the Postgres-only/remote-ignored decision (2026-10-05) every consumer
// reads DatabaseConfig.AuditDurableSyncStatus instead of the bool, so the raw
// field is touched in exactly two places, both inside
// internal/config/config.go: Validate's SQLite refusal, and
// AuditDurableSyncStatus itself. That is a stronger guarantee than the
// previous five-file allowlist, because the rule "is this setting in effect?"
// now has ONE implementation rather than five call sites that could each drift
// from it. Comment-only mentions elsewhere (internal/storage/store/entry.go
// names the field in a doc comment) are excluded by the scan below, which
// strips comments before matching.
//
// If a future file genuinely needs the raw bool rather than the computed
// status, add it here WITH the reason it cannot use AuditDurableSyncStatus —
// and expect that reason to be challenged, because "configured" and "in
// effect" being the same question is exactly the bug this shape prevents.
var insecureAuditSkipDurableSyncAllowedFiles = map[string]string{}

// repoRootForFastAuditScan resolves the main module's repo root from this
// file's own location (internal/config/..), so the scan works regardless of
// the test runner's working directory.
func repoRootForFastAuditScan() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

var fastAuditSelectorRe = regexp.MustCompile(`\.InsecureAuditSkipDurableSync\b`)

// commentStripRe removes // line comments and /* */ block comments. Needed
// because this scan matches raw file bytes: internal/storage/store/entry.go
// legitimately NAMES the field in a doc comment ("set once at construction
// from config.DatabaseConfig.InsecureAuditSkipDurableSync") while reading only
// the computed status, and counting that as a reference would force a
// permanent allowlist entry for a file that does not actually touch the field.
// Crude by design -- it will also blank a // inside a string literal, which in
// this scan can only ever cause a MISSED match in a file that embeds the
// field's name in a string, and no such file exists (checked: the only string
// form anywhere is the YAML key, which has no leading dot and so never matches
// this selector regardless).
var commentStripRe = regexp.MustCompile(`(?s)//[^\n]*|/\*.*?\*/`)

func stripGoComments(data []byte) []byte {
	return commentStripRe.ReplaceAll(data, []byte(" "))
}

// walkMainModuleGoFiles calls fn(repoRelativeSlashPath, contents) for every
// non-test *.go file in the main module's tree.
func walkMainModuleGoFiles(t *testing.T, root string, fn func(rel string, data []byte)) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "cli", "operator":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, rerr := os.ReadFile(path) // #nosec G304 -- fixed test-time repo-tree walk, not user input
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		fn(filepath.ToSlash(rel), data)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

// TestInsecureAuditSkipDurableSync_ReferencesAreAllowlisted is the
// completeness guard: every non-test file that references the field must have
// a reasoned allowlist entry, and every entry must still correspond to a real
// reference — so a future removal cannot leave a stale "reviewed as safe"
// claim about code that no longer exists.
func TestInsecureAuditSkipDurableSync_ReferencesAreAllowlisted(t *testing.T) {
	root := repoRootForFastAuditScan()
	actual := map[string]bool{}
	walkMainModuleGoFiles(t, root, func(rel string, data []byte) {
		if strings.HasPrefix(rel, "internal/config/") {
			// The field's owning package. Validate's SQLite refusal and
			// AuditDurableSyncStatus are the two legitimate reads, and they
			// are the whole point of the design -- scanning them would just
			// require permanently allowlisting the owner.
			return
		}
		if fastAuditSelectorRe.Match(stripGoComments(data)) {
			actual[rel] = true
		}
	})

	var missing []string
	for path := range actual {
		if _, ok := insecureAuditSkipDurableSyncAllowedFiles[path]; !ok {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		t.Errorf("found file(s) OUTSIDE internal/config referencing the raw InsecureAuditSkipDurableSync "+
			"field: %v\n"+
			"Read DatabaseConfig.AuditDurableSyncStatus(storageType) instead. The raw bool answers "+
			"\"did the operator write this key\"; the status answers \"is it actually in effect on this "+
			"backend, and if not, why not\" — and those are different questions on a remote backend. "+
			"Keeping the rule in one place is what stops a new surface from reporting a setting as "+
			"weakening durability when it is being ignored. If you genuinely need the bool, add a reasoned "+
			"entry to insecureAuditSkipDurableSyncAllowedFiles.", missing)
	}

	var stale []string
	for path := range insecureAuditSkipDurableSyncAllowedFiles {
		if !actual[path] {
			stale = append(stale, path)
		}
	}
	if len(stale) > 0 {
		t.Errorf("allowlist entr(y/ies) no longer reference InsecureAuditSkipDurableSync: %v\n"+
			"Remove the stale entry — it has either been refactored away or moved to "+
			"AuditDurableSyncStatus, which is where it belongs.", stale)
	}
}

// TestInsecureAuditSkipDurableSync_NoWriteAssignment is the actual security
// property: among every reference the scan finds, NONE is an assignment TO the
// field outside internal/config's own YAML-unmarshal path. No HTTP handler, no
// gRPC RPC, no other Go code in the main module can SET this value — only read
// it.
func TestInsecureAuditSkipDurableSync_NoWriteAssignment(t *testing.T) {
	root := repoRootForFastAuditScan()
	writeRe := regexp.MustCompile(`\.InsecureAuditSkipDurableSync\s*[:=]\s*(?:true|false|[A-Za-z_][A-Za-z0-9_.]*)\s*[,}\n]`)

	walkMainModuleGoFiles(t, root, func(rel string, data []byte) {
		if rel == "internal/config/config.go" {
			// The field's own definition; its struct-tag line matches the same
			// regex harmlessly. YAML unmarshal into this struct is the one
			// legitimate write path.
			return
		}
		if m := writeRe.FindString(string(data)); m != "" {
			t.Errorf("found what looks like a WRITE to InsecureAuditSkipDurableSync outside "+
				"internal/config/config.go: %s: %q\n"+
				"ADR-112 Amendment 1 requires this setting to be settable from the config FILE ONLY. If this "+
				"is a test fixture it belongs in a _test.go file (which this scan skips); if it is production "+
				"code, it is a remotely-reachable durability downgrade and must not ship.", rel, m)
		}
	})
}

// TestInsecureAuditSkipDurableSync_NotSettableFromTheEnvironment closes the
// other half of "config file only". Every env-var-sourced setting in this
// package goes through resolveSecret, which returns a STRING and is wired only
// to credential fields (KEYORIX_DB_PASSWORD, KEYORIX_SIEM_TOKEN, ...) — it
// structurally cannot produce a bool. This test pins that: no KEYORIX_*
// environment variable anywhere in the package mentions this setting, and the
// loader produces the secure default from a config file that does not name it.
//
// Guards the condition, not the conclusion (CLAUDE.md): rather than asserting
// "the env cannot set it" — unfalsifiable from outside — it asserts the two
// checkable facts that make it true.
func TestInsecureAuditSkipDurableSync_NotSettableFromTheEnvironment(t *testing.T) {
	root := repoRootForFastAuditScan()
	envRe := regexp.MustCompile(`(?i)KEYORIX_[A-Z0-9_]*(AUDIT_SKIP|SKIP_DURABLE|DURABLE_SYNC)[A-Z0-9_]*`)
	walkMainModuleGoFiles(t, root, func(rel string, data []byte) {
		if m := envRe.FindString(string(data)); m != "" {
			t.Errorf("%s introduces an environment variable %q for the fast audit mode. ADR-112 Amendment 1 "+
				"scopes this setting to the config FILE only; an env var is reachable from a container "+
				"spec or a compromised orchestrator without touching the audited config file.", rel, m)
		}
	})

	// And the default really is the secure one when the key is simply absent.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("storage:\n  type: local\n  database:\n    path: ./secrets.db\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Storage.Database.InsecureAuditSkipDurableSync {
		t.Fatal("a config file that does not mention insecure_audit_skip_durable_sync must leave it false — " +
			"the secure baseline has to be what you get by not asking for anything")
	}
}

// TestInsecureAuditSkipDurableSync_YAMLKeyCarriesTheInsecurePrefix pins
// ADR-112 §1's naming rule for this setting specifically: the YAML key's leaf
// must carry the `insecure_` prefix, so it cannot be enabled by accident or
// misread in review. Asserted against the struct tag the loader actually uses,
// not against a doc claim — a rename that dropped the prefix would go red here
// even if every other test still passed.
func TestInsecureAuditSkipDurableSync_YAMLKeyCarriesTheInsecurePrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// A POSTGRES config on purpose: a SQLite backend with this key set cannot
	// pass Validate at all (TestConfigValidate_RejectsFastAuditModeOnSQLite),
	// so writing one here would pin a state no deployment can reach.
	if err := os.WriteFile(path, []byte(
		"storage:\n  type: postgres\n  database:\n    host: db\n    name: keyorix\n    user: keyorix\n"+
			"    insecure_audit_skip_durable_sync: true\n",
	), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.Storage.Database.InsecureAuditSkipDurableSync {
		t.Fatal("the YAML key `insecure_audit_skip_durable_sync` under storage.database did not load into " +
			"InsecureAuditSkipDurableSync. Either the struct tag no longer matches this key, or the key has " +
			"been renamed away from ADR-112 §1's required insecure_ prefix — the whole point of which is that " +
			"a weakening setting cannot be enabled by accident or misread in review.")
	}
}
