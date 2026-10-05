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
//  1. the literal Go selector `.InsecureAuditSkipDurableSync` (case-sensitive);
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
// inventory of every non-test file allowed to reference the field at all.
// Every one of them only ever READS it. A file listed here that turns out to
// WRITE it fails TestInsecureAuditSkipDurableSync_NoWriteAssignment
// independently of this allowlist.
//
// internal/config/config.go is deliberately absent: the field's own
// DECLARATION has no leading dot, so the `.InsecureAuditSkipDurableSync`
// selector this scan looks for never matches it. It is handled (and specially
// exempted, as the one legitimate write path — ordinary YAML unmarshal) by the
// write test's own file-path check.
var insecureAuditSkipDurableSyncAllowedFiles = map[string]string{
	"internal/storage/factory.go": "reads it twice — once to build the SQLite DSN (sqliteDSN's skipDurableSync " +
		"parameter) and once per backend to configure the LocalStorage (SetAuditSkipDurableSync). Never writes " +
		"it; both are right-hand-side reads of an already-loaded *config.Config.",
	"internal/storage/gormdb.go": "reads it once to build the SQLite DSN for the handful of host-side CLI admin " +
		"commands that need a raw *gorm.DB (DEK rotation, auth-encryption stats — ADR-049). Never writes it, and " +
		"no HTTP or gRPC transport reaches this code path at all (ADR-108 §B: no admin command starts a listener).",
	"internal/storage/store/entry.go": "does not reference the field in CODE at all — this is a COMMENT-only " +
		"match (auditSkipDurableSync's and SetAuditSkipDurableSync's doc comments name " +
		"config.DatabaseConfig.InsecureAuditSkipDurableSync as the value they are set from). Listed rather " +
		"than filtered out because this scan matches raw file bytes, comments included, exactly like " +
		"keyless_mode_reachability_test.go's: a comment match is a false positive for reachability but a TRUE " +
		"positive for \"a human should look at this file when the field changes,\" which is what the allowlist " +
		"is for. The write test below is the one that enforces the security property, and it is unaffected " +
		"either way.",
	"internal/startup/validation.go": "reads it once in ValidateStartup to append the posture-deviation warning " +
		"`keyorix-server admin validate` prints (ADR-112 Amendment 1's posture-surface requirement). Never " +
		"writes it.",
	"server/main.go": "reads it once at server startup (only) to print the repeated-every-boot warning and write " +
		"the startup audit event. Never writes it.",
	"server/http/handlers/system.go": "reads it once to populate SecurityInfo.AuditDurableSyncSkipped for the " +
		"authenticated GET /system/info response — never writes it. This is the one HTTP handler that touches " +
		"the field AT ALL, and it is read-only by construction: a http.HandlerFunc closure over an " +
		"already-loaded *config.Config, with no request body ever reaching this value.",
}

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
		if fastAuditSelectorRe.Match(data) {
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
		t.Errorf("found file(s) referencing InsecureAuditSkipDurableSync with NO allowlist entry in "+
			"insecureAuditSkipDurableSyncAllowedFiles (internal/config/"+
			"insecure_audit_skip_durable_sync_reachability_test.go): %v\n"+
			"Every new reference needs a reasoned entry there — especially an HTTP handler or gRPC service, "+
			"which must never SET this field (ADR-112 Amendment 1: config file only).", missing)
	}

	var stale []string
	for path := range insecureAuditSkipDurableSyncAllowedFiles {
		if !actual[path] {
			stale = append(stale, path)
		}
	}
	if len(stale) > 0 {
		t.Errorf("allowlist entr(y/ies) no longer reference InsecureAuditSkipDurableSync: %v\n"+
			"Remove the stale entry — it has either been refactored away or the reference moved.", stale)
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
	cfg := &Config{}
	cfg.Storage.Database.InsecureAuditSkipDurableSync = true

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(
		"storage:\n  type: local\n  database:\n    path: ./secrets.db\n    insecure_audit_skip_durable_sync: true\n",
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
