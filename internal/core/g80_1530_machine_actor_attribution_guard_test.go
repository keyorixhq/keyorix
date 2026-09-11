// g80_1530_machine_actor_attribution_guard_test.go — #1530's guard: every
// audit-emitting path funnels through emitAudit (service.go), the single
// choke point that stamps MachineIdentityID from context when an event is
// actor-typed "machine_identity", and (#1626/#1628) unconditionally clears
// UserID for the same events. A call site that bypasses emitAudit and writes
// storage.LogAuditEvent directly skips BOTH corrections -- if such a site
// ever sets ActorType to "machine_identity" (or leaves it derivable from a
// machine-authenticated context) without also setting MachineIdentityID
// itself and leaving UserID unset, it silently reintroduces #1530's and
// #1626's gaps at once.
//
// Repo-wide, not internal/core-only (#1626 verification pass, 2026-08-30):
// this guard used to scan only internal/core's own directory, and its own
// doc comment claimed "there is exactly one direct storage.LogAuditEvent
// caller outside emitAudit" -- true for that one package, false for the
// repo. Two more direct callers exist outside internal/core entirely
// (server/main.go's auditConnectorProjectBindingCreate,
// server/http/handlers/audit_ingest_proxy.go's IngestAuditEventProxy), both
// safe on inspection but invisible to the old package-scoped scan -- an
// enumeration is only as complete as the directories it looks in. Still
// allowlist-shaped, not a full AST walk (a `.LogAuditEvent(` substring match
// per function, not real parsing), but now walks every non-test *.go file
// in the repository.
package core

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// auditAttributionAllowlist is the exhaustive, reasoned inventory of every
// direct storage.LogAuditEvent caller (bypassing emitAudit) reviewed as safe
// -- either it never sets ActorType to "machine_identity" at all (a genuine
// system/no-actor event), or it sets MachineIdentityID itself and leaves
// UserID unset. Each entry needs a reason; TestDirectLogAuditEventCallersAreSafe
// fails if a new direct caller appears unlisted, or if a listed entry no
// longer matches what it claims. Keys are repo-root-relative "path:func".
var auditAttributionAllowlist = map[string]string{
	"internal/core/anomaly.go:auditBusinessHoursConfig": "hardcodes ActorType: \"system\" -- a " +
		"scheduler/config-change event with no human or machine actor, correctly using the system-actor marker " +
		"rather than a null. Never machine-identity-typed, so emitAudit's corrections would never apply to it " +
		"anyway.",
	"server/main.go:auditConnectorProjectBindingCreate": "hardcodes ActorType: core.ActorTypeSystem and never " +
		"sets UserID (absent from the struct literal, so it's the zero value nil) -- an unattended boot-time " +
		"binding-creation event with no actor, same shape as the anomaly.go entry above.",
	"server/http/handlers/audit_ingest_proxy.go:IngestAuditEventProxy": "the hub side of the storage.type: " +
		"remote LogAuditEvent proxy (#r122-A): persists an already-fully-formed AuditEvent a follower's own " +
		"core.KeyorixCore already ran through emitAudit (correctly clearing UserID) before serializing it over " +
		"the wire -- this endpoint is a raw passthrough, not a second policy decision. A malicious system.write " +
		"holder submitting a forged event directly (bypassing the emitting server's emitAudit entirely) is a " +
		"KNOWN, already-tracked, separately-scoped gap (#G79, this file's own auditIngestProxyMaxClockSkew doc " +
		"comment) -- a distinct trust-boundary problem (attesting the submitter is a legitimate node) that " +
		"#1626/#1628's single-process UserID-attribution fix was never going to close, deferred to Wave 4.",
}

var logAuditEventFuncRe = regexp.MustCompile(`^func\s+(?:\([^)]*\)\s*)?([A-Za-z0-9_]+)\(`)

// repoRootG1626 locates the repository root relative to this file's own
// location on disk (internal/core), so the guard works regardless of the
// test runner's working directory.
func repoRootG1626() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

// findDirectLogAuditEventCallers scans every non-test *.go file in the
// repository for a `.LogAuditEvent(` call NOT inside emitAudit itself
// (service.go's own funnel implementation is the one legitimate direct
// caller of the storage interface method), returning "path:func" keys
// relative to the repo root.
func findDirectLogAuditEventCallers(t *testing.T, root string) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web", ".scratch", ".task", ".semgrep":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		currentFunc := ""
		for _, line := range strings.Split(string(b), "\n") {
			if m := logAuditEventFuncRe.FindStringSubmatch(line); m != nil {
				currentFunc = m[1]
			}
			if currentFunc == "emitAudit" {
				continue // the funnel itself, not a bypass
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.Contains(line, ".LogAuditEvent(") && currentFunc != "" {
				found[rel+":"+currentFunc] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking repo for direct LogAuditEvent callers: %v", err)
	}
	return found
}

// TestDirectLogAuditEventCallersScannerDetectsBypass is this guard's
// red-proof.
//
// TestDirectLogAuditEventCallersAreSafe has no total-collapse tripwire at
// all (unlike several sibling guards in this campaign) -- if
// logAuditEventFuncRe stopped matching, or the emitAudit exclusion or the
// "//"-comment skip became too permissive, actual would just come back
// smaller or noisier, and the allowlist comparison would report either
// nothing (a false "all safe") or unrelated staleness, never "the scanner
// broke."
func TestDirectLogAuditEventCallersScannerDetectsBypass(t *testing.T) {
	root := t.TempDir()
	// Line-scanned as plain text (findDirectLogAuditEventCallers is a
	// substring scanner, not go/ast), so this fixture is never compiled
	// either way -- undefined identifiers (storage, ev, ctx's type) are fine
	// and deliberate.
	const src = `package fixture

// emitAudit is the funnel itself -- its own LogAuditEvent call must never
// be reported as a bypass.
func emitAudit(ctx context.Context) {
	storage.LogAuditEvent(ctx, ev)
}

// directBypass is the planted violation: a direct call outside emitAudit.
func directBypass(ctx context.Context) {
	storage.LogAuditEvent(ctx, ev)
}

// commentedOut's call is text inside a comment and must not be reported.
func commentedOut(ctx context.Context) {
	// storage.LogAuditEvent(ctx, ev)
}
`
	if err := os.WriteFile(filepath.Join(root, "fixture.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing the synthetic fixture: %v", err)
	}
	// A _test.go file with an otherwise-matching bypass must be excluded —
	// the scanner only walks non-test files, matching every real caller site.
	const testSrc = `package fixture

func shouldNotAppear(ctx context.Context) {
	storage.LogAuditEvent(ctx, ev)
}
`
	if err := os.WriteFile(filepath.Join(root, "fixture_test.go"), []byte(testSrc), 0o600); err != nil {
		t.Fatalf("writing the synthetic test-file fixture: %v", err)
	}

	found := findDirectLogAuditEventCallers(t, root)

	if !found["fixture.go:directBypass"] {
		t.Errorf("findDirectLogAuditEventCallers must find fixture.go:directBypass; got %v", found)
	}
	if found["fixture.go:emitAudit"] {
		t.Errorf("findDirectLogAuditEventCallers reported emitAudit's own call as a bypass — the funnel "+
			"exclusion has stopped working, got %v", found)
	}
	if found["fixture.go:commentedOut"] {
		t.Errorf("findDirectLogAuditEventCallers reported a commented-out call — the \"//\" skip has "+
			"stopped working, got %v", found)
	}
	if len(found) != 1 {
		t.Errorf("expected exactly 1 direct caller (fixture_test.go's shouldNotAppear must be excluded), "+
			"got %d: %v", len(found), found)
	}
}

// TestDirectLogAuditEventCallersAreSafe is #1530's guard: every direct
// storage.LogAuditEvent caller (bypassing emitAudit's MachineIdentityID
// stamp) must be in auditAttributionAllowlist with a reason, or the test
// fails -- a new bypass site is exactly how this gap would reappear.
func TestDirectLogAuditEventCallersAreSafe(t *testing.T) {
	t.Parallel()
	actual := findDirectLogAuditEventCallers(t, repoRootG1626())

	var unjustified []string
	for key := range actual {
		if _, ok := auditAttributionAllowlist[key]; !ok {
			unjustified = append(unjustified, key)
		}
	}
	if len(unjustified) > 0 {
		t.Errorf("%d direct storage.LogAuditEvent caller(s) bypass emitAudit's MachineIdentityID stamp with no "+
			"reasoned allowlist entry: %v\nEither route through emitAudit instead, or add a reasoned entry to "+
			"auditAttributionAllowlist explaining why this site can never emit a machine-identity-typed event "+
			"without attribution.", len(unjustified), unjustified)
	}

	var stale []string
	for key := range auditAttributionAllowlist {
		if !actual[key] {
			stale = append(stale, key+" (no longer calls LogAuditEvent directly)")
		}
	}
	if len(stale) > 0 {
		t.Errorf("auditAttributionAllowlist entr(y/ies) no longer reproduce: %v\nRemove the entry -- it's either "+
			"been fixed to route through emitAudit, or the direct call was removed.", stale)
	}
}
