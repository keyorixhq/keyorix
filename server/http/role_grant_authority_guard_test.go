// role_grant_authority_guard_test.go — a guard for the pattern named in #1582
// (G80): three /system handlers were each found, one at a time, by a
// different method, to persist a Role grant directly via storage with no
// authority check at all — CreateInvitationProxy (found first, fixed in the
// documented-exception re-verification sweep), then CreateMembershipProxy and
// UpdateMembershipProxy (found by #1578, fixed alongside it). Three
// independent discoveries of the same missing call is a signal that there is
// an invariant to assert, not a list to maintain: every /system handler that
// persists a Role grant DIRECTLY via storage (bypassing core) must call
// core.RequireAuthorityForRole before doing so.
//
// Scope, deliberately narrow: this guard only covers the raw-storage-bypass
// shape #1578/#1582 fixed — a handler that decodes a wire body carrying a
// Role-shaped field and calls h.coreService.Storage().Create*/Update*
// directly. A handler that instead routes through a core business-logic
// function (e.g. AssignRoleWithExpiryProxy -> core.AssignUserRoleWithExpiry,
// whose OWN body calls requireAuthorityForRole internally) is a different,
// already-correct shape — core.AssignGroupRoleWithExpiry's own doc comment
// names this explicitly. This guard would not, and should not, flag it: the
// ceiling is enforced, just one hop further down, which the existing
// raw_storage_bypass_guard_test.go already accounts for when classifying a
// handler as calling core vs. calling storage directly. Detecting "the
// ceiling is enforced SOMEWHERE in the full call graph" for every possible
// handler shape would require the same interprocedural AST walk
// raw_storage_bypass_guard_test.go's exportedCoreStorageWrappers already
// does for a different question; duplicating that here was assessed and
// rejected as growing this pass beyond a small check (per the G80 standing
// guardrail) — the raw-storage-bypass shape is where all three real
// instances were actually found, and is what this guard targets.
package http

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// roleFieldRe matches a Role-shaped wire field reference: `body.Role`,
// `.Role:` in a struct literal, `a.Role` in an assignments-loop variable
// (CreateInvitationProxy's per-assignment loop), or `SystemRole` (the
// substring match is deliberate — "SystemRole" is one identifier, not a
// separate word-bounded "Role", but is exactly the field
// RequireAuthorityForRole is also called for in CreateInvitationProxy).
var roleFieldRe = regexp.MustCompile(`\.Role\b|\bRole:|SystemRole`)

// directStorageWriteRe matches a direct, unmediated
// h.coreService.Storage().Create*/Update* call — the raw-storage-bypass
// shape, as opposed to routing through a core.KeyorixCore business-logic
// method (core.AssignUserRoleWithExpiry and similar never appear as
// `.Storage().Create`/`.Storage().Update` in a handler body).
var directStorageWriteRe = regexp.MustCompile(`\.Storage\(\)\.(Create|Update)[A-Za-z]*\(`)

// persistsRoleGrantDirectly reports whether the named handler's body both
// references a Role-shaped field and calls storage directly to persist it —
// the exact shape #1578/#1582 fixed.
func persistsRoleGrantDirectly(t *testing.T, handlerName string) bool {
	t.Helper()
	text := handlerBodyText(t, handlerName)
	return roleFieldRe.MatchString(text) && directStorageWriteRe.MatchString(text)
}

// callsRequireAuthorityForRole reports whether the named handler's body
// calls the escalation-by-proxy ceiling anywhere (this guard does not check
// ordering relative to the storage write — a handler decoding, checking,
// THEN persisting is the only sane shape in practice, and ordering bugs are
// a different, more targeted review question than this guard's population
// check). FIX-1 deleted core.RequireAuthorityForRole (name-based: only fired
// for 4 canonical admin-tier role names) and replaced every caller with
// core.RequireGranterHoldsRolePermissions (derives the ceiling from the
// role's real bundled permissions) — recognize both names so a handler still
// carrying the old symbol (pre-FIX-1) and one already migrated are equally
// detected as having a check.
func callsRequireAuthorityForRole(t *testing.T, handlerName string) bool {
	t.Helper()
	body := handlerBodyText(t, handlerName)
	return strings.Contains(body, "RequireAuthorityForRole(") ||
		strings.Contains(body, "RequireGranterHoldsRolePermissions(")
}

// roleGrantAuthorityAllowlist is the exhaustive, reasoned inventory of every
// /system handler this guard's scan flags as persisting a Role grant
// directly via storage WITHOUT calling RequireAuthorityForRole, reviewed as
// safe for a stated reason (e.g. the Role field is never admin-tier by
// construction, or a different, equivalent ceiling already runs first).
// TestEveryDirectRoleGrantChecksAuthority fails if a flagged handler is
// missing from both this list and knownUnfixedRoleGrantAuthorityGaps, or if
// a listed entry stops reproducing.
var roleGrantAuthorityAllowlist = map[string]string{}

// knownUnfixedRoleGrantAuthorityGaps is the set of /system handlers
// confirmed, by individual review, to persist a Role grant directly with no
// authority check, not yet fixed. Grandfathered so this guard can go live
// immediately; each entry is a tracked gap, not a claim of safety. Empty as
// of this guard's introduction (G80 deletion pass) — all three known
// instances were fixed before this guard was written.
var knownUnfixedRoleGrantAuthorityGaps = map[string]string{}

// TestEveryDirectRoleGrantChecksAuthority is the guard: for every /system
// handler that persists a Role-shaped field directly via storage, that
// handler must call RequireAuthorityForRole, or have a reasoned entry in
// roleGrantAuthorityAllowlist or knownUnfixedRoleGrantAuthorityGaps. RED
// without #1582's fix: CreateMembershipProxy and UpdateMembershipProxy would
// both have been flagged here.
func TestEveryDirectRoleGrantChecksAuthority(t *testing.T) {
	routerPath := "router.go"
	actual := extractSystemGroupRoutes(t, routerPath)

	handlerFlagged := map[string]bool{}
	seenHandlers := map[string]bool{}
	var flagged []string
	for _, r := range actual {
		if r.Handler == "" || seenHandlers[r.Handler] {
			continue
		}
		seenHandlers[r.Handler] = true
		if !persistsRoleGrantDirectly(t, r.Handler) {
			continue
		}
		if callsRequireAuthorityForRole(t, r.Handler) {
			continue
		}
		handlerFlagged[r.Handler] = true
		_, safe := roleGrantAuthorityAllowlist[r.Handler]
		_, unfixed := knownUnfixedRoleGrantAuthorityGaps[r.Handler]
		if !safe && !unfixed {
			flagged = append(flagged, r.Handler+" persists a Role-shaped field directly via storage with no "+
				"RequireAuthorityForRole call")
		}
	}
	sort.Strings(flagged)

	if len(flagged) > 0 {
		t.Errorf("found %d /system handler(s) persisting a Role grant directly via storage with no authority "+
			"check (the #1578/#1582 shape): %v\nEither call h.coreService.RequireAuthorityForRole(r.Context(), "+
			"actorID(r), projectID, role) before persisting, or add a reasoned entry to "+
			"roleGrantAuthorityAllowlist (if genuinely safe) or knownUnfixedRoleGrantAuthorityGaps (if it's a "+
			"real, tracked, not-yet-fixed gap) in this file.", len(flagged), flagged)
	}

	checkStale := func(listName string, m map[string]string) {
		var stale []string
		for handler := range m {
			found := false
			for _, r := range actual {
				if r.Handler == handler {
					found = true
					break
				}
			}
			if !found {
				stale = append(stale, handler+" (no longer registered under /system)")
				continue
			}
			if !handlerFlagged[handler] {
				stale = append(stale, handler+" (no longer persists an unchecked Role grant)")
			}
		}
		sort.Strings(stale)
		if len(stale) > 0 {
			t.Errorf("%s entr(y/ies) no longer reproduce: %v\nRemove the entry, or move it to the other list if "+
				"its status changed (e.g. a real gap just got fixed).", listName, stale)
		}
	}
	checkStale("roleGrantAuthorityAllowlist", roleGrantAuthorityAllowlist)
	checkStale("knownUnfixedRoleGrantAuthorityGaps", knownUnfixedRoleGrantAuthorityGaps)
}
