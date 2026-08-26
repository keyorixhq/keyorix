// g80_1530_machine_actor_attribution_guard_test.go — #1530's guard: every
// audit-emitting path funnels through emitAudit (service.go), the single
// choke point that stamps MachineIdentityID from context when an event is
// actor-typed "machine_identity". A call site that bypasses emitAudit and
// writes storage.LogAuditEvent directly skips that stamp entirely -- if such
// a site ever sets ActorType to "machine_identity" (or leaves it derivable
// from a machine-authenticated context) without also setting
// MachineIdentityID itself, it silently reintroduces #1530's exact gap.
//
// This is a small, allowlist-shaped guard, not a repo-wide AST walk: as of
// writing there is exactly one direct storage.LogAuditEvent caller outside
// emitAudit itself (anomaly.go's auditBusinessHoursConfig), and it correctly
// hardcodes ActorType: "system" -- a genuine no-actor event (a scheduler
// config change), not a machine-identity one. Cheap to keep this way: a new
// direct LogAuditEvent caller that constructs a "machine_identity"-typed
// event without setting MachineIdentityID fails this test immediately.
package core

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// auditAttributionAllowlist is the exhaustive, reasoned inventory of every
// direct storage.LogAuditEvent caller (bypassing emitAudit) reviewed as safe
// -- either it never sets ActorType to "machine_identity" at all (a genuine
// system/no-actor event), or it sets MachineIdentityID itself. Each entry
// needs a reason; TestDirectLogAuditEventCallersAreSafe fails if a new
// direct caller appears unlisted, or if a listed entry no longer matches
// what it claims.
var auditAttributionAllowlist = map[string]string{
	"anomaly.go:auditBusinessHoursConfig": "hardcodes ActorType: \"system\" -- a scheduler/config-change event " +
		"with no human or machine actor, correctly using the system-actor marker rather than a null. Never " +
		"machine-identity-typed, so emitAudit's MachineIdentityID stamp would never apply to it anyway.",
}

var logAuditEventFuncRe = regexp.MustCompile(`^func\s+(?:\([^)]*\)\s*)?([A-Za-z0-9_]+)\(`)

// findDirectLogAuditEventCallers scans every non-test *.go file in
// internal/core for a `.LogAuditEvent(` call NOT inside emitAudit itself
// (service.go's own funnel implementation is the one legitimate direct
// caller of the storage interface method), returning "file:func" keys.
func findDirectLogAuditEventCallers(t *testing.T) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading internal/core: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
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
				found[name+":"+currentFunc] = true
			}
		}
	}
	return found
}

// TestDirectLogAuditEventCallersAreSafe is #1530's guard: every direct
// storage.LogAuditEvent caller (bypassing emitAudit's MachineIdentityID
// stamp) must be in auditAttributionAllowlist with a reason, or the test
// fails -- a new bypass site is exactly how this gap would reappear.
func TestDirectLogAuditEventCallersAreSafe(t *testing.T) {
	actual := findDirectLogAuditEventCallers(t)

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
