// wire_actor_identity_forgery_guard_test.go — a guard for the bug class named
// and swept in the G80 documented-exception re-verification sweep
// (2026-08-25): a /system handler that reads an actor-shaped field straight
// off the wire body (invited_by, resolved_by, created_by, decided_by,
// approver_id, revoked_by) for an authorization decision or a persisted
// actor-identity field, instead of deriving it from the AUTHENTICATED caller
// (actorID(r) / requestActorKindAndID(r)). Two confirmed instances
// (CreateInvitationProxy's invited_by, UpdateAccessRequestProxy's
// resolved_by) were recorded FIXED under earlier PRs without ever touching
// this axis — this guard exists so a THIRD instance of the same shape can't
// land silently again.
//
// Modeled directly on raw_storage_bypass_guard_test.go's
// rawStorageBypassAllowlist / knownUnfixedRawStorageBypasses shape: flag
// every occurrence, require a reasoned entry in one of two lists, and fail on
// staleness (a listed handler that no longer reproduces, or no longer exists
// under /system).
//
// KNOWN BLIND SPOT, disclosed rather than hidden (matching this guard's own
// precedent's own documented gaps): this scan only catches `body.<Field>`
// where `body` is the DIRECT wire-decode variable. It does NOT see through an
// intermediate `.toModel()`/nested-struct hop — e.g.
// TransitionMachineIdentityStateProxy's actor field lives at
// `body.MachineIdentity.CreatedBy`, reached only via `body.MachineIdentity.
// toModel()`, never as a literal `body.CreatedBy` token. Those cases were
// found and fixed by hand during the sweep (see machine_identities_proxy.go's
// own doc comments); this guard cannot re-detect a regression in them and
// makes no claim to.
package http

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// actorShapedFieldNames are wire-struct field names that name WHO performed
// an action, as opposed to WHAT the action targets. `user_id`/`group_id`-as-
// target (e.g. "invite this user") are deliberately excluded — only fields
// that have been found, in this campaign, to actually feed an authorization
// decision or a persisted actor-identity column are listed. A new field name
// discovered later should be added here, not worked around.
var actorShapedFieldNames = []string{
	"InvitedBy", "ResolvedBy", "CreatedBy", "DecidedBy", "ApproverID", "RevokedBy",
}

// actorFieldReadRe matches `body.<ActorField>` for each name above, used to
// scan a handler's raw source text (comments included, filtered separately —
// see actorFieldReads).
var actorFieldReadRes = func() []*regexp.Regexp {
	res := make([]*regexp.Regexp, len(actorShapedFieldNames))
	for i, name := range actorShapedFieldNames {
		res[i] = regexp.MustCompile(`\bbody\.` + name + `\b`)
	}
	return res
}()

// handlerBodyText returns the raw source text of the named handler method's
// body (opening brace to matching close), searched across every non-test
// *.go file in server/http/handlers — mirrors
// raw_storage_bypass_guard_test.go's handlerStorageCalls exactly, except it
// returns the joined text instead of extracted call names, since this guard
// needs to inspect the surrounding characters around each match (is it a
// read or a write?), not just detect a call name.
func handlerBodyText(t *testing.T, handlerName string) string {
	t.Helper()
	funcRe := regexp.MustCompile(`^func \([a-zA-Z]+ \*[A-Za-z]+\) ` + regexp.QuoteMeta(handlerName) + `\(`)

	dir := filepath.Join("..", "..", "server", "http", "handlers")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading server/http/handlers: %v", err)
	}
	var out strings.Builder
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
				out.WriteString(line)
				out.WriteByte('\n')
				if depth <= 0 {
					inFunc = false
				}
			}
		}
	}
	return out.String()
}

// actorFieldReads returns the actor-shaped field names read (not written)
// from the wire body within the given handler's source text. A line whose
// trimmed content starts with "//" is skipped entirely — a comment
// mentioning "body.ResolvedBy" in prose (this file's own fix commentary does
// exactly that, describing what USED to happen) must not itself trip the
// guard. For each remaining match, the immediately-following non-space
// character is inspected: a single `=` (not `==`) means the field is being
// OVERWRITTEN before use — the fix pattern this sweep applied everywhere
// (`body.CreatedBy = actorID(r)`) — and is not flagged; anything else (a bare
// reference, `==`, a function argument, a struct-literal read via
// `body.toModel()` picking it up implicitly) is flagged as a live read.
func actorFieldReads(t *testing.T, handlerName string) []string {
	t.Helper()
	text := handlerBodyText(t, handlerName)
	var found []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		for i, re := range actorFieldReadRes {
			name := actorShapedFieldNames[i]
			for _, loc := range re.FindAllStringIndex(line, -1) {
				rest := strings.TrimLeft(line[loc[1]:], " \t")
				if strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==") {
					continue // overwritten before use -- the fix pattern, not a read
				}
				if !seen[name] {
					seen[name] = true
					found = append(found, name)
				}
			}
		}
	}
	sort.Strings(found)
	return found
}

// actorIdentityForgeryAllowlist is the exhaustive, reasoned inventory of
// every /system handler this guard's scan currently flags, reviewed as
// SAFE — either fixed (the flagged read is a false-positive remnant, e.g. a
// name that also appears as a struct field TAG rather than a live read the
// scan's line-level heuristic can't distinguish) or genuinely inconsequential
// (no authorization decision or trusted attribution ever reads the field
// back). Each entry needs a reason; TestNoUnjustifiedActorIdentityForgery
// fails if a flagged handler is missing from both this list and
// knownUnfixedActorIdentityForgeries, or if a listed entry stops reproducing.
var actorIdentityForgeryAllowlist = map[string]string{}

// knownUnfixedActorIdentityForgeries is the set of /system handlers
// confirmed, by individual review during the G80 documented-exception
// re-verification sweep (2026-08-25), to read an actor-shaped field off the
// wire with a real (if low-severity) consequence, not yet fixed.
// Grandfathered so this guard can go live immediately; each entry is a
// tracked gap, not a claim of safety.
//
// CreateDynamicSecretConfigProxy is a REAL, LOW-SEVERITY, not-yet-fixed
// instance (CreatedBy is a display STRING, forgeable, but read back by no
// authorization decision traced so far) that does NOT appear here: it falls
// into this guard's own documented blind spot above (`body.toModel()`
// picks the field up implicitly; the handler never writes the literal token
// `body.CreatedBy`), so the scan cannot see it at all, flagged or not. Left
// as a plain code comment rather than a map entry — a map entry the
// staleness check can never observe as flagged would itself be permanently
// stale, defeating the point of this guard's staleness check.
var knownUnfixedActorIdentityForgeries = map[string]string{}

// TestNoUnjustifiedActorIdentityForgery is this sweep's guard: for every
// /system handler, if its body reads an actor-shaped field straight off the
// wire (see actorFieldReads), that handler must have an entry in
// actorIdentityForgeryAllowlist (reviewed safe) or
// knownUnfixedActorIdentityForgeries (reviewed real, tracked, not yet fixed)
// explaining why. A newly-added route (or a regression in an already-fixed
// one) that reintroduces this shape fails immediately.
func TestNoUnjustifiedActorIdentityForgery(t *testing.T) {
	routerPath := filepath.Join(".", "router.go")
	actual := extractSystemGroupRoutes(t, routerPath)

	handlerFlagged := map[string]bool{}
	seenHandlers := map[string]bool{}
	var flagged []string
	for _, r := range actual {
		if r.Handler == "" || seenHandlers[r.Handler] {
			continue
		}
		seenHandlers[r.Handler] = true
		reads := actorFieldReads(t, r.Handler)
		if len(reads) == 0 {
			continue
		}
		handlerFlagged[r.Handler] = true
		_, safe := actorIdentityForgeryAllowlist[r.Handler]
		_, unfixed := knownUnfixedActorIdentityForgeries[r.Handler]
		if !safe && !unfixed {
			flagged = append(flagged, r.Handler+" reads wire-supplied actor field(s) "+strings.Join(reads, ",")+
				" directly -- derive from actorID(r)/requestActorKindAndID(r) instead")
		}
	}
	sort.Strings(flagged)

	if len(flagged) > 0 {
		t.Errorf("found %d /system handler(s) trusting a wire-supplied actor identity (the wire-actor-identity "+
			"forgery shape): %v\nEither derive the field from the authenticated caller (actorID(r) for a "+
			"human-only decision, requestActorKindAndID(r) for an actor-kind-aware one), or add a reasoned entry "+
			"to actorIdentityForgeryAllowlist (if genuinely safe) or knownUnfixedActorIdentityForgeries (if it's a "+
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
				stale = append(stale, handler+" (no longer reads a wire-supplied actor field)")
			}
		}
		sort.Strings(stale)
		if len(stale) > 0 {
			t.Errorf("%s entr(y/ies) no longer reproduce: %v\nRemove the entry, or move it to the other list if "+
				"its status changed (e.g. a real gap just got fixed).", listName, stale)
		}
	}
	checkStale("actorIdentityForgeryAllowlist", actorIdentityForgeryAllowlist)
	checkStale("knownUnfixedActorIdentityForgeries", knownUnfixedActorIdentityForgeries)
}
