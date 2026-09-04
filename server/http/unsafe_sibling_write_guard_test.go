// unsafe_sibling_write_guard_test.go — #1592's stale-fork sweep, kept live:
// the sweep found the pattern's complete population (a "narrow, purpose-
// built, exported internal/core primitive" per ADR-088 has an unsafe, plain
// sibling storage method that predates it), and its live extent turned out
// to be zero — #1585/#1586/#1587 were the only three /system proxies calling
// the unsafe sibling, and all three were deleted (docs/adr-090-stale-fork-
// proxy-deletion.md) for having no live caller under any topology, not
// fixed. This guard makes that "zero" durable: no FUTURE /system proxy may
// call an unsafe sibling where a safe one already exists, without a reasoned
// allowlist entry.
//
// Population derivation (docs/adr-090-stale-fork-proxy-deletion.md records
// the full method): commit-message search (G42, 8ba2109d, #518, #517,
// #260/#519, #528, #525/#340, #303/#304 each name their own complete scope)
// cross-checked against an exhaustive structural scan of
// internal/core/storage/interface.go for the (bool, error) CAS-return
// signature or a conditional|atomically|CAS doc comment. Both derivations
// agree on the same population below. Stated residual gap: a conditional-
// write method with neither a telltale name, nor that signature, nor such a
// comment would be invisible to both — none found, none ruled out.
//
// This is a NARROWER, more specific guard than TestNoUnjustifiedRawStorageBypass
// (raw_storage_bypass_guard_test.go) above: that guard requires a reason for
// ANY unreviewed write-shaped raw call; this one specifically names the
// unsafe→safe sibling relationship so the invariant is self-documenting and
// can't be satisfied by a plausible-sounding allowlist reason alone — the
// safe primitive named in the failure message is the fix, not a suggestion.
package http

import (
	"fmt"
	"path/filepath"
	"sort"
	"testing"
)

// unsafeSiblingPairs maps a plain/unsafe storage.Storage write method to the
// safe CAS/exclusive/guarded sibling that exists specifically to replace it
// for any caller with a real invariant to protect. A /system proxy calling
// the KEY here bypasses whatever race or correctness property the VALUE
// exists to provide — see docs/adr-090-stale-fork-proxy-deletion.md for the
// full citation (commit or issue) behind each pair.
var unsafeSiblingPairs = map[string]string{
	"UpdateMachineIdentity":      "TransitionMachineIdentityState",
	"UpdateProjectMembership":    "TransitionProjectMembershipState",
	"CreateSecretDependency":     "CreateSecretDependencyExclusive",
	"UpdateSecret":               "TransitionSecretStatus",
	"UpdateDynamicSecretConfig":  "TransitionDynamicSecretConfigDisabled",
	"UpdateUser":                 "UpdateUserIfActiveStateMatches",
	"UpdateRiskException":        "RevokeRiskExceptionIfNotRevoked/ApproveRiskExceptionIfPending",
	"UpdateWebAuthnCredential":   "AdvanceWebAuthnCredentialCounter",
	"DeleteProject":              "DeleteProjectIfEmpty",
	"RemoveRole":                 "RemoveGlobalAdminRoleGuarded",
	"UpdateBreakGlassActivation": "RevokeBreakGlassActivation",
}

// unsafeSiblingAllowlist is the exhaustive, reasoned inventory of every
// /system handler that calls a key of unsafeSiblingPairs directly and has
// been individually verified safe despite that — the two legitimate
// exceptions #1592's sweep found (Task 4: every OTHER call site of this
// shape repo-wide was #1585/#1586/#1587, now deleted). Each entry needs a
// real reason; TestNoProxyCallsUnsafeSiblingWhenSafeExists fails if a
// handler not in this list calls an unsafe sibling (a brand new instance of
// the stale-fork shape), or if a listed entry no longer reproduces (fixed,
// or the route removed) — same discipline as
// rawStorageBypassAllowlist/knownUnfixedRawStorageBypasses above.
var unsafeSiblingAllowlist = map[string]string{
	// UpdateWebAuthnCredentialProxy entry removed (#1714): reclassified from
	// "capability-reducing, no independent ceiling" to a real authz bypass --
	// the old raw call trusted an attacker-controlled full-row body
	// (ownership reassignment via a mismatched user_id, silent re-enable of a
	// clone-disabled credential). Fixed by routing through
	// KeyorixCore.MarkWebAuthnCredentialClonedByLookup; the handler no longer
	// makes an unsafe-sibling call at all, so this guard no longer flags it.
	"DeleteProjectProxy": "no-independent-ceiling: core.DeleteProject(force=true) intentionally skips the " +
		"force=false guard+cascade atomicity problem entirely and calls the plain, unconditional " +
		"storage.DeleteProject cascade -- no actor-authority check of any kind exists at the core layer for " +
		"this path, so there is nothing for the raw call to bypass.",
}

// TestNoProxyCallsUnsafeSiblingWhenSafeExists is the preventive half of
// #1592's sweep: for every /system route, if its handler calls a
// write-shaped raw storage method that is a KEY in unsafeSiblingPairs, that
// handler must be in unsafeSiblingAllowlist with a reasoned exception, or
// the test fails naming the safe sibling it should call instead.
func TestNoProxyCallsUnsafeSiblingWhenSafeExists(t *testing.T) {
	routerPath := filepath.Join(".", "router.go")
	actual := extractAllRouterRoutes(t, routerPath)

	handlerFlagged := map[string]bool{}
	seenHandlers := map[string]bool{}
	var flagged []string
	for _, r := range actual {
		if r.Handler == "" || seenHandlers[r.Handler] {
			continue
		}
		seenHandlers[r.Handler] = true
		for _, storageMethod := range handlerStorageCalls(t, r.Handler) {
			safe, isUnsafe := unsafeSiblingPairs[storageMethod]
			if !isUnsafe {
				continue
			}
			handlerFlagged[r.Handler] = true
			if _, ok := unsafeSiblingAllowlist[r.Handler]; ok {
				continue
			}
			flagged = append(flagged, fmt.Sprintf(
				"%s calls Storage().%s(...) directly, but %s exists specifically to replace it safely -- "+
					"call the safe sibling, or add a reasoned entry to unsafeSiblingAllowlist in this file",
				r.Handler, storageMethod, safe))
		}
	}
	sort.Strings(flagged)

	if len(flagged) > 0 {
		t.Errorf("found %d handler(s) calling an unsafe sibling where a safe one exists (#1592's stale-fork "+
			"shape, #1585/#1586/#1587): %v", len(flagged), flagged)
	}

	// Staleness: an allowlist entry is stale if its handler is no longer
	// registered anywhere, or no longer makes a flagged unsafe-sibling call.
	var stale []string
	for handler := range unsafeSiblingAllowlist {
		found := false
		for _, r := range actual {
			if r.Handler == handler {
				found = true
				break
			}
		}
		if !found {
			stale = append(stale, handler+" (no longer registered anywhere in router.go)")
			continue
		}
		if !handlerFlagged[handler] {
			stale = append(stale, handler+" (no longer makes a flagged unsafe-sibling call)")
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("unsafeSiblingAllowlist entr(y/ies) no longer reproduce: %v\nRemove the entry -- its "+
			"exception no longer applies.", stale)
	}
}
