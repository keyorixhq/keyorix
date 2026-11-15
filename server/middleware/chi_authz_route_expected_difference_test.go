package middleware

// expectedDifferenceClasses is the committed EXPECTED-DIFFERENCE table for CH1-C
// (the routing differential). Each entry is a chi-vs-reference disagreement class
// that is a KNOWN, benign consequence of the semantic gap between chi's matcher
// (matches on the escaped path; %2F is not a separator; trailing slash and case are
// significant) and the harness's strict decoded reference matcher. A disagreement
// whose class is NOT in this map fails the oracle — only NEW classes fail.
//
// IMPORTANT: a class being "expected" means the chi-vs-reference DISAGREEMENT is
// understood and non-security-relevant for ROUTE SELECTION; it does NOT weaken the
// primary CH1-A/CH1-B oracle, which is independent of this table and always fires on
// a restricted-PAT bypass or wrong-route refusal. See EXPECTED-DIFFERENCE.md for the
// per-class rationale and what each does NOT cover.
var expectedDifferenceClasses = map[string]bool{
	// A %2F in the request: chi keeps it as a literal inside one segment (so a
	// {param} captures "a/b" whole); the decoded reference sees two segments and so
	// matches a longer pattern or nothing. Route selection is chi's; the decoded
	// value only ever reaches a handler/scope resolver, never re-routes.
	"encoded-slash": true,
	// Other percent-encoding (%2E, %41, ...) the reference decodes before splitting
	// but chi matches on the escaped bytes: a literal segment can therefore match in
	// the reference but not in chi, or vice-versa. Not a cross-route hazard.
	"percent-encoding": true,
	// Empty segment from "//": chi collapses nothing (an empty segment fails to
	// match any literal/{param}), the reference drops it. Divergence is a non-match
	// on one side, never a match to a different gated route.
	"double-slash": true,
	// "." / ".." path segments: neither chi nor net/http normalizes them inside the
	// mux (normalization, if any, is upstream); the reference treats them as literal
	// segments. Divergence is a non-match, not a cross-route match.
	"dot-segment": true,
	// Trailing slash: chi treats "/x" and "/x/" as distinct and does not redirect
	// (no RedirectSlashes middleware is installed); the strict reference likewise
	// distinguishes them but can disagree on which concrete pattern a Route-root
	// "/x/" belongs to.
	"trailing-slash": true,
	// The reference matcher found MORE THAN ONE same-method pattern for a path with
	// no encoding feature — an overlap of a literal route and a {param} route (e.g.
	// /secrets/export vs /secrets/{id}). chi deterministically prefers the literal;
	// the reference reports both. This is a reference limitation, not a chi defect:
	// chi's choice is still a real registered route, and the primary oracle checks
	// its refusal-status regardless.
	"reference-ambiguous": true,
}
