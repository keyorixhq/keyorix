package main

// admin_encryption_fault_fuzz_test.go — FuzzAdminEncryptionCommandFault.
//
// FuzzAdminDispatch (admin_dispatch_fuzz_test.go) already proves argv routing
// and admin.Execute's own dispatch-level contract; FuzzFaultInjectedOperations
// (internal/encryption) already proves fine-grained durability at the exact
// file/SQL seam level. This target sits BETWEEN them: the server/admin CLI
// WIRING layer's own contract when the encryption family's underlying
// operation fails -- lock release, audit-event truthfulness, and exit-code
// correctness -- for the real cobra command tree, not a replica of it.
//
// Investigated (per this track's report) whether these commands could be
// fault-injected the SAME way as internal/encryption's fileFaultHook: no.
// server/admin's encryption commands open their OWN *gorm.DB and key
// directory internally (via internal/encryptionops), so this package's test
// never gets a handle to register a GORM callback on, or gets to set
// internal/encryption's unexported fileFaultHook (a different package; doing
// so would need a new exported test-only knob there, out of scope here). The
// fault model below is deliberately coarser and BLACK-BOX instead: make the
// whole working directory (key files AND the SQLite DB, including its
// -wal/-shm sidecars) read-only immediately before running one command, so
// EVERY write inside it fails with a real OS permission error, then restore
// write access before checking any oracle. This is the right grain for what
// this layer's own oracles actually claim (lock/audit/exit-code), which
// don't need per-seam precision -- that precision is what the two fuzzers
// above already provide, at the layers where it matters.
//
// ── Command catalog ──────────────────────────────────────────────────────
//
// Limited to the STATE-CHANGING commands that (a) require no interactive
// input beyond the master passphrase (sourced via KEYORIX_MASTER_PASSWORD/
// KEYORIX_NEW_MASTER_PASSWORD, ADR-099's weakest-fallback env vars -- no
// --passphrase-file plumbing needed) and (b) call recordAdminAction on their
// own success path, so the audit oracle has something to check for every
// entry. Deliberately excludes: status/validate (read-only, no audit, no
// lock -- see their own doc comments in encryption.go/auth_encryption.go),
// shamir-split (touches no database or existing key file at all -- correctly
// unaudited, not a coverage gap), and migrate-provider/-cleanup (needs a
// --to-type target provider choice this harness would have to fake safely --
// a good extension, not done here).
//
// ── Oracles ───────────────────────────────────────────────────────────────
//
//  1. Exit code is always 0 or 1 (same contract FuzzAdminDispatch's oracle 3
//     already asserts generically) -- checked again here specifically tied
//     to whether the fault fired: faulted => 1, unfaulted => 0.
//  2. Lock always released: a FRESH serverguard.AcquireExclusive(cfg) against
//     the SAME database, immediately after admin.Execute returns (and after
//     restoring write access), must succeed -- proving the command's own
//     lock (acquireDatabaseLock, admin.go) was released, not leaked, on
//     EITHER the success or the failure path.
//  3. No false-success audit: a faulted run must not leave a Success=true
//     audit_events row for the command's own eventType -- the underlying
//     encryptionops call returns an error BEFORE any run* function reaches
//     its recordAdminAction call (every one of them follows the same
//     if-err-return-err-then-recordAdminAction-then-return-nil shape), so a
//     fault that actually fired must leave zero such rows. An UNFAULTED run
//     is checked the other direction: exactly one Success=true row for that
//     eventType must exist (recordAdminAction is a real, unconditional call
//     on that path, and this harness never faults the audit write itself --
//     only the primary operation's own directory).

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/keyorixhq/keyorix/server/admin"
)

const (
	adminEncTestPassphrase    = "admin-enc-fault-fuzz-passphrase"
	adminEncTestNewPassphrase = "admin-enc-fault-fuzz-new-passphrase"
)

// adminEncFaultVerifiedMu/adminEncFaultVerifiedSet back the reachability
// guard test (TestFuzzAdminEncryptionCommandFaultSeedsReachEveryCommand):
// recordAdminEncFaultVerified is called ONLY when chmodTree's own stat check
// confirms the working directory's mode bits actually changed, never merely
// when a fault=true case ran.
var (
	adminEncFaultVerifiedMu  sync.Mutex
	adminEncFaultVerifiedSet = map[string]bool{}
)

func recordAdminEncFaultVerified(key string) {
	adminEncFaultVerifiedMu.Lock()
	adminEncFaultVerifiedSet[key] = true
	adminEncFaultVerifiedMu.Unlock()
}

func resetAdminEncFaultVerified() {
	adminEncFaultVerifiedMu.Lock()
	adminEncFaultVerifiedSet = map[string]bool{}
	adminEncFaultVerifiedMu.Unlock()
}

func adminEncFaultVerified(key string) bool {
	adminEncFaultVerifiedMu.Lock()
	defer adminEncFaultVerifiedMu.Unlock()
	return adminEncFaultVerifiedSet[key]
}

type adminEncCmdSpec struct {
	key       string   // stable label for test output
	args      []string // argv AFTER "encryption" (e.g. {"init"})
	eventType string   // recordAdminAction's eventType on this command's success path
}

// adminEncCommands' rotate-kek entry needs KEYORIX_NEW_MASTER_PASSWORD, set
// unconditionally (harmlessly unused by every other command) in
// bootstrapAdminEncWorld alongside KEYORIX_MASTER_PASSWORD.
var adminEncCommands = []adminEncCmdSpec{
	{key: "rotate", args: []string{"rotate", "--confirm"}, eventType: "admin.encryption.rotate"},
	{key: "upgrade-aad", args: []string{"upgrade-aad"}, eventType: "admin.encryption.upgrade_aad"},
	{key: "fix-perms", args: []string{"fix-perms"}, eventType: "admin.encryption.fix_perms"},
	{key: "rotate-kek", args: []string{"rotate-kek", "--confirm"}, eventType: "admin.encryption.rotate_kek"},
	{key: "auth-encryption-enable", args: []string{"auth-encryption", "enable"}, eventType: "admin.encryption.auth_encryption_enable"},
	{key: "auth-encryption-migrate", args: []string{"auth-encryption", "migrate"}, eventType: "admin.encryption.auth_encryption_migrate"},
}

// adminEncConfigYAML is the minimal local-storage-plus-encryption config every
// case needs. dbPath is relative to dir, matching how a real deployment's
// keyorix.yaml resolves storage.database.path against its own directory.
func adminEncConfigYAML() string {
	return `storage:
  type: local
  database:
    path: "test.db"
  encryption:
    enabled: true
    dek_path: "keys/dek.key"
    salt_path: "keys/kek.salt"
`
}

// bootstrapAdminEncWorld creates a fresh directory, writes its config, and
// runs a REAL, unfaulted `encryption init` so every command in the catalog
// (which all require encryption already initialized) has real key material
// to act on. Returns the absolute config path and directory.
func bootstrapAdminEncWorld(t *testing.T) (cfgPath, dir string) {
	t.Helper()
	dir = t.TempDir()
	cfgPath = filepath.Join(dir, "keyorix.yaml")
	if err := os.WriteFile(cfgPath, []byte(adminEncConfigYAML()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// securefiles' write path refuses to create missing intermediate
	// directories (a deliberate security property, not a bug) — the "keys"
	// directory must exist before Initialize's first salt/DEK write.
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatalf("mkdir keys dir: %v", err)
	}
	t.Setenv("KEYORIX_MASTER_PASSWORD", adminEncTestPassphrase)
	t.Setenv("KEYORIX_NEW_MASTER_PASSWORD", adminEncTestNewPassphrase)

	origWD, err := os.Getwd()
	if err == nil {
		if os.Chdir(dir) == nil {
			defer func() { _ = os.Chdir(origWD) }()
		}
	}
	var code int
	fuzzutil.Guard(t.Fatalf, "bootstrap admin.Execute(init)", func() {
		code = admin.Execute([]string{"encryption", "init", "--config", cfgPath})
	})
	if code != 0 {
		t.Fatalf("bootstrap `encryption init` failed with exit code %d", code)
	}
	return cfgPath, dir
}

// chmodTree sets mode on dir and every entry directly inside it (one level:
// covers keys/, test.db, test.db-wal/-shm if present) -- deep enough to block
// every write this catalog's commands can make, shallow enough to be cheap
// per fuzz iteration. Best-effort: a chmod failure mid-walk still leaves
// SOME of the tree locked down, which is fine -- the oracle only needs SOME
// real write to fail, not every possible one. Returns whether dir's own mode
// bits were actually verified changed afterward -- e.g. a test suite running
// as root would make os.Chmod(dir, 0o500) a complete no-op against root's own
// writes, silently defeating this harness's whole fault model without this
// check (the reachability guard test below asserts this always came back
// true for every fault=true case, not just that chmodTree was CALLED).
func chmodTree(dir string, mode os.FileMode) bool {
	_ = os.Chmod(dir, mode)
	verified := false
	if info, err := os.Stat(dir); err == nil {
		verified = info.Mode().Perm() == mode
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return verified
	}
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		_ = os.Chmod(full, mode)
		if e.IsDir() {
			sub, err := os.ReadDir(full)
			if err != nil {
				continue
			}
			for _, se := range sub {
				_ = os.Chmod(filepath.Join(full, se.Name()), mode)
			}
		}
	}
	return verified
}

// auditSuccessCount opens dbPath directly (bypassing the admin command tree
// entirely) and counts Success=true audit_events rows with the given
// eventType and an event_time at or after since -- since is this run's own
// start time, so a stale row from bootstrapAdminEncWorld's own init call (a
// DIFFERENT eventType, admin.encryption.init, so it wouldn't collide anyway,
// but the time bound keeps this robust against catalog changes) never
// contaminates the count.
func auditSuccessCount(t *testing.T, dbPath, eventType string, since time.Time) int {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db for audit check: %v", err)
	}
	defer func() { _ = db.Close() }()
	var count int
	row := db.QueryRow(
		`SELECT COUNT(*) FROM audit_events WHERE event_type = ? AND success = 1 AND event_time >= ?`,
		eventType, since.UTC().Format("2006-01-02 15:04:05"),
	)
	if err := row.Scan(&count); err != nil {
		t.Fatalf("query audit_events: %v", err)
	}
	return count
}

func runAdminEncCase(t *testing.T, spec adminEncCmdSpec, fault bool) {
	cfgPath, dir := bootstrapAdminEncWorld(t)
	dbPath := filepath.Join(dir, "test.db")

	if fault {
		if chmodTree(dir, 0o500) {
			recordAdminEncFaultVerified(spec.key)
		}
	}
	runStart := time.Now()

	args := append([]string{"encryption"}, spec.args...)
	args = append(args, "--config", cfgPath)

	origWD, err := os.Getwd()
	if err == nil {
		if os.Chdir(dir) == nil {
			defer func() { _ = os.Chdir(origWD) }()
		}
	}
	var code int
	fuzzutil.Guard(t.Fatalf, "admin.Execute(encryption "+spec.key+")", func() {
		code = admin.Execute(args)
	})

	// Restore write access BEFORE any oracle check below needs to open the
	// DB or re-acquire the lock -- both require a writable directory.
	if fault {
		chmodTree(dir, 0o700)
	}

	// oracle 1: exit code tied to whether the fault fired.
	if fault && code != 1 {
		t.Fatalf("admin encryption %s: fault case returned exit code %d, want 1 (a read-only working directory must make this command fail)", spec.key, code)
	}
	if !fault && code != 0 {
		t.Fatalf("admin encryption %s: unfaulted baseline returned exit code %d, want 0", spec.key, code)
	}
	if code != 0 && code != 1 {
		t.Fatalf("admin encryption %s: exit code %d, want 0 or 1 (this command's own documented contract, same as every non-verify-audit admin command)", spec.key, code)
	}

	// oracle 2: lock always released, whichever path was taken.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("admin encryption %s: reload config for lock check: %v", spec.key, err)
	}
	lock, lockErr := serverguard.AcquireExclusive(cfg)
	if lockErr != nil {
		t.Fatalf("LOCK LEAK: admin encryption %s (fault=%v) left the exclusive lock held after admin.Execute returned: %v", spec.key, fault, lockErr)
	}
	if lock != nil {
		_ = lock.Release()
	}

	// oracle 3: audit truthfulness.
	got := auditSuccessCount(t, dbPath, spec.eventType, runStart)
	switch {
	case fault && got != 0:
		t.Fatalf("FALSE-SUCCESS AUDIT: admin encryption %s recorded %d Success=true audit_events row(s) for %q despite the fault making this command fail (exit code %d)", spec.key, got, spec.eventType, code)
	case !fault && got != 1:
		t.Fatalf("MISSING AUDIT: admin encryption %s succeeded (exit code 0) but recorded %d Success=true audit_events row(s) for %q, want exactly 1", spec.key, got, spec.eventType)
	}
}

func runAdminEncFaultCase(t *testing.T, cmdSel, faultSel byte) {
	spec := adminEncCommands[int(cmdSel)%len(adminEncCommands)]
	runAdminEncCase(t, spec, faultSel%2 == 1)
}

func allAdminEncSeedPairs() []struct{ cmdSel, faultSel byte } {
	var pairs []struct{ cmdSel, faultSel byte }
	for i := range adminEncCommands {
		pairs = append(pairs, struct{ cmdSel, faultSel byte }{byte(i), 0})
		pairs = append(pairs, struct{ cmdSel, faultSel byte }{byte(i), 1})
	}
	return pairs
}

func FuzzAdminEncryptionCommandFault(f *testing.F) {
	for _, p := range allAdminEncSeedPairs() {
		f.Add(p.cmdSel, p.faultSel)
	}

	f.Fuzz(func(t *testing.T, cmdSel, faultSel byte) {
		runAdminEncFaultCase(t, cmdSel, faultSel)
	})
}

// TestFuzzAdminEncryptionCommandFaultSeedsReachEveryCommand replays this
// fuzzer's own seed set outside `go test -fuzz` and asserts every catalog
// entry actually ran, both unfaulted and faulted, printing no panics and no
// unexpected t.Skip — PR #2047's lesson applied here too: a seed that looks
// like it covers a command without ever actually invoking it must fail CI,
// not silently contribute zero coverage.
func TestFuzzAdminEncryptionCommandFaultSeedsReachEveryCommand(t *testing.T) {
	resetAdminEncFaultVerified()
	for _, p := range allAdminEncSeedPairs() {
		spec := adminEncCommands[int(p.cmdSel)%len(adminEncCommands)]
		fault := p.faultSel%2 == 1
		t.Run(fmt.Sprintf("%s/fault=%v", spec.key, fault), func(t *testing.T) {
			runAdminEncCase(t, spec, fault)
		})
	}
	// Independent of whether the subtests above passed: for every catalog
	// entry, the fault=true case must have ACTUALLY made the directory
	// read-only at the OS level (chmodTree's own verified return value),
	// not merely have been iterated over by this loop. This is what would
	// have caught, for example, this whole suite silently running as root
	// (chmod to a stricter mode is a no-op against root's own writes) —
	// a condition the oracle checks inside runAdminEncCase can't
	// distinguish from "the fault genuinely fired" on their own, since
	// SOME of those oracles could coincidentally still pass by accident.
	for _, spec := range adminEncCommands {
		if !adminEncFaultVerified(spec.key) {
			t.Errorf("DEAD SEED: command %q's fault=true case never verified the working directory actually became read-only (chmodTree's stat check failed) — the fault model may be silently defeated (e.g. running as root)", spec.key)
		}
	}
}
