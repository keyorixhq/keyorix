// raw_storage_bypass_guard_test.go — #1542's guard: a node-credential-gated
// proxy handler that calls h.coreService.Storage().X(...) directly, when
// internal/core ALSO has an exported KeyorixCore method that calls
// c.storage.X(...) itself, is exactly the shape that let AssignRoleWithExpiryProxy/
// AssignRoleToGroupWithExpiryProxy/AssignMachineRoleProxy/RemoveAllProjectRoleGrantsProxy
// bypass every real ceiling (requireGranterHoldsRolePermissions, requireAuthorityForRole,
// guardLastProjectAdmin) for any system.write holder, human or machine -- the
// handler wasn't taking the storage-primitive-name-matches-a-core-method-name
// coincidence as a signal that a real policy path exists for that operation.
//
// Scope: intentionally limited to the 18 routes classifiedNodeCredentialRoutes
// (node_credential_route_classification_test.go) already covers, not every
// Storage() call in every handler. A repo-wide run of this exact detection
// logic (not a cruder name-overlap estimate) flags 149 call sites across
// server/http/handlers -- 90 of them (60%) are read-shaped storage methods
// (Get*/List*/Count*/Export*, mechanically excludable: a read confers no new
// access, so there's no ceiling to bypass), leaving 59 write-shaped
// candidates that would need real classification (some already confirmed
// audit-only/no-ceiling, some deliberate documented exceptions like
// CreateUserWithRoleGrantsProxy/RemoveGlobalAdminRoleGuardedProxy below, and
// at least DeleteProjectProxy/TransitionMembershipProxy genuinely
// unresolved). #1545 and #1546 were both found by hand in code this
// 18-route scope doesn't watch -- direct evidence the narrowing loses real
// coverage, the same shape #1540 already flagged for
// knownUnresolvedWireCalls. Filed as #1547 (the C5 treatment for this
// guard's exclusion pattern), not implemented here.
package http

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// exportedCoreStorageWrappers scans every non-test *.go file in internal/core
// and returns the set of storage.Storage method names called (as
// c.storage.X(...)) from within at least one EXPORTED (c *KeyorixCore) method
// body -- i.e., a real, reachable core-level path exists for that storage
// primitive, not just an incidental reference from an unexported helper no
// handler could ever be near.
func exportedCoreStorageWrappers(t *testing.T) map[string]bool {
	t.Helper()
	wrapped := map[string]bool{}
	coreFuncRe := regexp.MustCompile(`^func \(c \*KeyorixCore\) ([A-Z][A-Za-z0-9_]*)\(`)
	storageCallRe := regexp.MustCompile(`c\.storage\.([A-Za-z0-9_]+)\(`)

	entries, err := os.ReadDir(filepath.Join("..", "..", "internal", "core"))
	if err != nil {
		t.Fatalf("reading internal/core: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "core", name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		inExported := false
		depth := 0
		for _, line := range strings.Split(string(b), "\n") {
			if depth == 0 {
				if m := coreFuncRe.FindStringSubmatch(line); m != nil {
					inExported = true
				} else if strings.HasPrefix(line, "func ") {
					inExported = false
				}
			}
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth < 0 {
				depth = 0
			}
			if inExported {
				for _, m := range storageCallRe.FindAllStringSubmatch(line, -1) {
					wrapped[m[1]] = true
				}
			}
			if depth == 0 {
				inExported = false
			}
		}
	}
	return wrapped
}

// handlerStorageCalls returns the set of storage.Storage method names called
// as h.coreService.Storage().X(...) (or a local var equivalent — the proxy
// files in this repo always use the receiver form) from within the named
// handler method's body, searched across every non-test *.go file in
// server/http/handlers.
func handlerStorageCalls(t *testing.T, handlerName string) []string {
	t.Helper()
	funcRe := regexp.MustCompile(`^func \([a-zA-Z]+ \*[A-Za-z]+\) ` + regexp.QuoteMeta(handlerName) + `\(`)
	storageCallRe := regexp.MustCompile(`Storage\(\)\.([A-Za-z0-9_]+)\(`)

	dir := filepath.Join("..", "..", "server", "http", "handlers")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading server/http/handlers: %v", err)
	}
	var calls []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		inFunc := false
		depth := 0
		for _, line := range strings.Split(string(b), "\n") {
			if !inFunc && funcRe.MatchString(line) {
				inFunc = true
			}
			if inFunc {
				depth += strings.Count(line, "{") - strings.Count(line, "}")
				for _, m := range storageCallRe.FindAllStringSubmatch(line, -1) {
					calls = append(calls, m[1])
				}
				if depth <= 0 {
					inFunc = false
				}
			}
		}
	}
	return calls
}

// rawStorageBypassAllowlist is the exhaustive, reasoned inventory of every
// classifiedNodeCredentialRoutes handler that still calls
// h.coreService.Storage().X(...) directly for a storage method X that ALSO
// has an exported internal/core wrapper -- i.e., every currently-accepted
// "the wrapper exists but this call site deliberately doesn't use it" case.
// Each entry needs a reason; TestNoUnjustifiedRawStorageBypass fails if a
// route not in this list is found calling a wrapped storage method (the
// #1542 shape recurring), or if a listed entry no longer applies (fixed and
// forgotten).
var rawStorageBypassAllowlist = map[string]string{
	"RemoveGlobalAdminRoleGuardedProxy": "deliberate exception, not a gap: no real transaction spans the HTTP hop " +
		"back to the calling server (RemoteStorage.WithTransaction is a no-op), so the last-global-admin invariant " +
		"can only be enforced atomically by whichever server owns the row -- see rbac_role_grants_proxy.go's package doc.",
	"ClearProjectSecretOwnershipProxy": "false positive: the exported core wrapper (RemoveProjectMember) calls this " +
		"storage method only as a best-effort CLEANUP side effect of removing a member, not as its own gated " +
		"operation -- there is no independent ceiling for 'clear ownership' alone to bypass.",
	"DeleteSecretACLsByUserAndProjectProxy": "false positive: same shape as ClearProjectSecretOwnershipProxy above " +
		"-- a best-effort cleanup side effect inside RemoveProjectMember, not an independently-gated operation.",
	"DeleteExpiredRoleGrantsProxy": "false positive: the exported core wrapper (RemoveExpiredRoleGrants) has no " +
		"actor ceiling either -- an unconditional, time-bounded system sweep. Its only extra value over the raw " +
		"call is per-grant audit-event writing, an audit-completeness gap (#1529 territory), not a policy bypass.",
	"CreateUserWithRoleGrantsProxy": "deliberate exception (C2), documented in its own handler doc: must be ONE " +
		"atomic DB transaction (ADR-028), which a naive validate-via-core-then-create-via-core two-call proxy " +
		"would break. ValidateRoleGrantAuthority re-applies the same escalation-ceiling + SoD checks the core " +
		"wrapper (CreateUserWithAssignments, a different exported method than the storage method name this " +
		"guard matched) uses, before the single atomic raw-storage create.",
	"TransitionMembershipProxy": "NOT YET RESOLVED -- filed as #1546. Unlike the routes above, this one is not " +
		"confirmed as a false positive: the exported wrapper (TransitionMembership) gates activation with " +
		"requireAuthorityForRole and grants/revokes the underlying role grant as a side effect neither of which " +
		"this raw call performs. Whether that's covered by a separate relayed call from the downstream's own " +
		"core.TransitionMembership, or a real gap, needs tracing before this entry can be resolved either way.",
}

// TestNoUnjustifiedRawStorageBypass is #1542's guard: for every route in
// classifiedNodeCredentialRoutes, if its handler calls
// h.coreService.Storage().X(...) for a storage method X that an EXPORTED
// internal/core method also wraps, that handler must have an entry in
// rawStorageBypassAllowlist explaining why. A newly-added route (or a
// regression in an already-fixed one) that reintroduces this shape fails
// immediately, instead of waiting for the next manual audit round to notice.
func TestNoUnjustifiedRawStorageBypass(t *testing.T) {
	wrapped := exportedCoreStorageWrappers(t)
	routerPath := filepath.Join(".", "router.go")
	actual := extractSystemGroupRoutes(t, routerPath)

	routeKey := map[string]string{} // "METHOD path" -> handler name
	for _, r := range actual {
		routeKey[r.Method+" "+r.Path] = r.Handler
	}

	var flagged []string
	for _, c := range classifiedNodeCredentialRoutes {
		handler, ok := routeKey[c.Method+" "+c.Path]
		if !ok || handler == "" {
			continue
		}
		for _, storageMethod := range handlerStorageCalls(t, handler) {
			if !wrapped[storageMethod] {
				continue
			}
			if _, allowed := rawStorageBypassAllowlist[handler]; allowed {
				continue
			}
			flagged = append(flagged, handler+" calls Storage()."+storageMethod+"(...) directly, "+
				"but internal/core has an exported method that also wraps "+storageMethod)
		}
	}
	sort.Strings(flagged)

	if len(flagged) > 0 {
		t.Errorf("found %d handler(s) bypassing a wrapped core ceiling via raw storage (the #1542 shape): %v\n"+
			"Either route the handler through the core method that wraps this storage call, or add a reasoned "+
			"entry to rawStorageBypassAllowlist (node_credential_route_classification_test.go's sibling, this "+
			"file) explaining why the raw call is deliberate.", len(flagged), flagged)
	}

	var staleAllowlist []string
	for handler := range rawStorageBypassAllowlist {
		found := false
		for _, r := range actual {
			if r.Handler == handler {
				found = true
				break
			}
		}
		if !found {
			staleAllowlist = append(staleAllowlist, handler)
		}
	}
	sort.Strings(staleAllowlist)
	if len(staleAllowlist) > 0 {
		t.Errorf("rawStorageBypassAllowlist entr(y/ies) name a handler no longer registered under /system: %v",
			staleAllowlist)
	}
}
