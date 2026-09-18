package connect

// FuzzConnectRefScoping fuzzes prefixAllowed -- the Keyorix Connect (ADR-043) allowlist guardrail
// that decides whether a caller may proxy-read an external-store secret ref. It scopes which refs a
// connector will fetch, so an over-grant here reads secrets outside the operator-configured scope.
// The package had no fuzz coverage.
//
// Two sound invariants, both assert only the direction that cannot false-positive (a DENY is always
// safe; we never assert "must allow"):
//
//   - NO TRAVERSAL: a ref containing a "." or ".." path segment must never be allowed. A downstream
//     resolver (Vault's API, a proxy, any RFC-3986 resolver) can collapse ".." and climb outside the
//     allowed prefix, so prefixAllowed rejects such refs before the prefix comparison.
//   - NO OVER-GRANT (independent differential): whenever prefixAllowed ALLOWS a ref against a
//     non-empty allowlist, some allowed prefix must genuinely contain the ref on a path-SEGMENT
//     boundary -- checked here by an independent segment-slice implementation, not the byte-prefix
//     one under test. This is exactly the "db/prod must not match db/production-other-team" property
//     the segment-boundary check exists for; a divergence between the two implementations is a real
//     scope-bypass bug.
//
// Pure functions, no network/DB -- CI-runnable.

import (
	"strings"
	"testing"
)

// segContainsBySegments is an INDEPENDENT oracle for "ref is within prefix p on a path-segment
// boundary", implemented by comparing "/"-split segment slices rather than the byte-prefix logic in
// refWithinPrefix. Two independent implementations of the same containment rule must agree on the
// allow direction; a mismatch is the bug. A trailing "/" on p is a scoping convenience (p and p+"/"
// scope identically), so it is trimmed before splitting.
func segContainsBySegments(p, ref string) bool {
	if p == "" {
		return false
	}
	pSegs := strings.Split(strings.TrimSuffix(p, "/"), "/")
	refSegs := strings.Split(ref, "/")
	if len(refSegs) < len(pSegs) {
		return false
	}
	for i := range pSegs {
		if refSegs[i] != pSegs[i] {
			return false
		}
	}
	return true
}

func FuzzConnectRefScoping(f *testing.F) {
	seeds := []struct{ p1, p2, ref string }{
		{"db/prod", "", "db/prod/pass"},              // in-scope extend
		{"db/prod", "", "db/production-other/pass"},  // sibling over-grant hazard
		{"db/prod", "", "db/prod"},                   // exact match
		{"db/prod/", "", "db/prod/x"},                // trailing-slash prefix
		{"app", "svc", "svc/token"},                  // second prefix matches
		{"db/prod", "", "db/prod/../secret"},         // traversal via ..
		{"db/prod", "", "db/./prod/x"},               // dot segment
		{"", "", "anything/goes"},                    // empty allowlist = allow all
		{"a", "", "ab"},                              // byte-prefix but not segment boundary
		{"a/b", "", "a/bc"},                          // sibling segment
	}
	for _, s := range seeds {
		f.Add(s.p1, s.p2, s.ref)
	}

	f.Fuzz(func(t *testing.T, p1, p2, ref string) {
		var allowed []string
		for _, p := range []string{p1, p2} {
			if p != "" {
				allowed = append(allowed, p)
			}
		}

		if !prefixAllowed(allowed, ref) {
			return // denied -- always safe
		}

		// Invariant 1: a traversal-shaped ref must never be allowed.
		if RefHasDotSegment(ref) {
			t.Fatalf("TRAVERSAL BYPASS: prefixAllowed allowed a ref with a dot segment: ref=%q allowed=%q", ref, allowed)
		}

		// Invariant 2: an allowed ref (non-empty allowlist) must be segment-contained in some
		// allowed prefix per the independent segment-slice oracle.
		if len(allowed) > 0 {
			ok := false
			for _, p := range allowed {
				if segContainsBySegments(p, ref) {
					ok = true
					break
				}
			}
			if !ok {
				t.Fatalf("OVER-GRANT: prefixAllowed allowed ref=%q but no allowed prefix segment-contains it (allowed=%q) -- byte-prefix match diverges from segment-boundary containment", ref, allowed)
			}
		}
	})
}
