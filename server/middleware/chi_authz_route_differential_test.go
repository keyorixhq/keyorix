// chi_authz_route_differential_test.go — CH1: differential harness for go-chi
// routing vs. Keyorix's authorization path.
//
// PROPERTY (CH1): for any method+path, the handler chi dispatches to is the one
// the authorization policy was evaluated for — a request must never be authorized
// as route A and served by route B.
//
// Keyorix applies its permission gates PER ROUTE (chi `r.With(RequireScopedPermission)`),
// so the gate lives inside the matched route's own handler chain: if chi matches
// route B, route B's gate runs, by construction. The ONE place that makes an authz
// decision by INDEPENDENTLY re-matching the route — a second matcher, separate from
// chi's dispatch — is RefuseRestrictedPATUngatedWrites (pat_restriction_writes.go):
// it calls routes.Find(...) to look the request up in core's restricted-PAT refusal
// table and 403s a restricted PAT before the handler runs. That is exactly the
// "route A vs route B" surface: if the pattern Find computes diverges from the
// pattern chi dispatches, a restricted PAT is authorized as one route, served as
// another.
//
// This harness drives the REAL RefuseRestrictedPATUngatedWrites, the REAL
// core.RestrictedPATWriteRefusal table, and a REAL chi router whose route set is
// loaded from the committed, AST-derived inventory scripts/e2e/routes.json (kept
// current by server/http TestRouteInventoryIsCurrent). chi routing depends only on
// the pattern set and mux options — no path-rewriting middleware is installed in
// NewRouter — so recording handlers reporting chi.RouteContext(r).RoutePattern()
// give the ground truth for "what got served".
//
// Oracles (see chi_authz_route_differential_fuzz_test.go for the fuzzer and
// EXPECTED-DIFFERENCE.md for the committed disagreement-class table):
//
//	CH1-A (bypass / VULN direction): the dispatched route is a refused ungated
//	  write, yet the middleware does NOT refuse — a restricted PAT reaches a write
//	  it must be refused.
//	CH1-B (wrong-route refusal / DEFECT direction): the middleware refuses, yet the
//	  dispatched route is NOT a refused write — refused as route A, served as route B.
//	CH1-C (routing differential): an independent segment-wise matcher built from the
//	  same route table is compared to chi's dispatch; classes in EXPECTED-DIFFERENCE
//	  pass, a NEW class fails.
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/internal/core"
)

const matchHeader = "X-Ch1-Matched-Pattern"

// methodSet is the fixed set the fuzzer picks from, so a fuzz input can never
// produce an invalid HTTP method token.
var methodSet = []string{
	http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete,
	http.MethodPatch, http.MethodHead, http.MethodOptions,
}

func isWriteMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	}
	return false
}

type routeEntry struct {
	Method  string `json:"method"`
	Pattern string `json:"pattern"`
}

// --- loading the committed route inventory ---

func repoRoot(tb testing.TB) string {
	tb.Helper()
	dir, err := os.Getwd()
	if err != nil {
		tb.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			tb.Fatal("could not find repo root (go.mod) above working dir")
		}
		dir = parent
	}
}

var (
	invOnce  sync.Once
	invCache []routeEntry
	invErr   error
)

func loadInventory(tb testing.TB) []routeEntry {
	tb.Helper()
	invOnce.Do(func() {
		p := filepath.Join(repoRoot(tb), "scripts", "e2e", "routes.json")
		b, err := os.ReadFile(p) // #nosec G304 -- fixed repo-internal path
		if err != nil {
			invErr = err
			return
		}
		invErr = json.Unmarshal(b, &invCache)
	})
	if invErr != nil {
		tb.Fatalf("load route inventory: %v", invErr)
	}
	if len(invCache) == 0 {
		tb.Fatal("route inventory is empty — scripts/e2e/routes.json did not load")
	}
	return invCache
}

// --- building a faithful replica router ---

func recordingHandler(w http.ResponseWriter, r *http.Request) {
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		w.Header().Set(matchHeader, rctx.RoutePattern())
	}
	w.WriteHeader(http.StatusOK)
}

func registerRoute(r chi.Router, method, pattern string) {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete,
		http.MethodPatch, http.MethodHead, http.MethodOptions:
		r.MethodFunc(method, pattern, recordingHandler)
	case "HANDLE":
		// router.go's r.Handle(pattern, ...) — all methods (e.g. /metrics).
		r.HandleFunc(pattern, recordingHandler)
	case "MOUNT":
		// router.go's r.Mount(pattern, ...) — a subtree (e.g. /swagger/).
		r.HandleFunc(strings.TrimSuffix(pattern, "/")+"/*", recordingHandler)
	}
}

// patFactory builds the /api/v1 middleware under test, given the subrouter it is
// installed on (the production call is identical: r.Use(F(r, "/api/v1"))).
type patFactory func(routes chi.Routes) func(http.Handler) http.Handler

// realPATFactory is the production middleware, verbatim.
func realPATFactory(routes chi.Routes) func(http.Handler) http.Handler {
	return RefuseRestrictedPATUngatedWrites(routes, "/api/v1")
}

// buildReplica constructs an outer chi router with the /api/v1 subtree carrying
// the supplied PAT middleware (nil installs none), mirroring router.go's mount.
func buildReplica(tb testing.TB, inv []routeEntry, pf patFactory) http.Handler {
	tb.Helper()
	outer := chi.NewRouter()
	var api, other []routeEntry
	for _, e := range inv {
		if strings.HasPrefix(e.Pattern, "/api/v1/") {
			api = append(api, e)
		} else {
			other = append(other, e)
		}
	}
	defer func() {
		if rec := recover(); rec != nil {
			tb.Fatalf("replica construction panicked (route conflict?): %v", rec)
		}
	}()
	for _, e := range other {
		registerRoute(outer, e.Method, e.Pattern)
	}
	outer.Route("/api/v1", func(r chi.Router) {
		if pf != nil {
			r.Use(pf(r))
		}
		for _, e := range api {
			registerRoute(r, e.Method, strings.TrimPrefix(e.Pattern, "/api/v1"))
		}
	})
	return outer
}

// --- driving the replica ---

// makeReq builds a request with the raw (possibly percent-encoded) path preserved
// and a restricted-or-not PAT principal in context. ok=false for a target that is
// not a well-formed request URI (not a routing case).
func makeReq(method, rawpath string, restricted bool) (*http.Request, bool) {
	u, err := url.ParseRequestURI(rawpath)
	if err != nil || u.Path == "" || u.Path[0] != '/' {
		return nil, false
	}
	req := httptest.NewRequest(method, "/", nil)
	req.URL = u
	req.RequestURI = rawpath
	uc := &UserContext{}
	if restricted {
		uc.PATRestriction = &core.PATRestriction{}
	}
	req = req.WithContext(context.WithValue(req.Context(), userContextKey, uc))
	return req, true
}

type serveResult struct {
	ok      bool   // request was well-formed and served
	status  int    // response status
	matched string // chi.RouteContext.RoutePattern() of the dispatched handler ("" if no match)
}

func ch1Serve(h http.Handler, method, rawpath string, restricted bool) serveResult {
	req, ok := makeReq(method, rawpath, restricted)
	if !ok {
		return serveResult{}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return serveResult{ok: true, status: rec.Code, matched: rec.Header().Get(matchHeader)}
}

// --- the oracles ---

// oracleViolation is a non-expected disagreement a run surfaced. Class names are
// compared against EXPECTED-DIFFERENCE classes; a class not listed there fails.
type oracleViolation struct {
	Class   string
	Method  string
	Path    string
	Matched string // chi dispatch pattern
	Detail  string
}

func (v oracleViolation) String() string {
	return fmt.Sprintf("[%s] %s %q -> chi=%q : %s", v.Class, v.Method, v.Path, v.Matched, v.Detail)
}

// checkCase runs the real-middleware oracles for one (method, path). It returns any
// violations (empty when the case is consistent). realReplica must be built with
// realPATFactory. inv is the route table for the reference matcher.
func checkCase(realReplica http.Handler, inv []routeEntry, method, rawpath string) []oracleViolation {
	var out []oracleViolation

	a := ch1Serve(realReplica, method, rawpath, false) // unrestricted principal
	if !a.ok {
		return nil // not a well-formed request URI
	}

	// Primary oracle (CH1-A / CH1-B) applies only to /api/v1 writes, where the PAT
	// middleware is installed and makes an independent routes.Find decision.
	if isWriteMethod(method) {
		b := ch1Serve(realReplica, method, rawpath, true) // restricted PAT
		actualRefuse := b.status == http.StatusForbidden
		if a.matched != "" && strings.HasPrefix(a.matched, "/api/v1") {
			shouldRefuse := core.RestrictedPATWriteRefusal(method+" "+a.matched) != nil
			switch {
			case shouldRefuse && !actualRefuse:
				out = append(out, oracleViolation{
					Class: "CH1-A-bypass", Method: method, Path: rawpath, Matched: a.matched,
					Detail: "dispatched route is a refused ungated write but the restricted PAT was NOT refused",
				})
			case !shouldRefuse && actualRefuse:
				out = append(out, oracleViolation{
					Class: "CH1-B-wrong-route-refusal", Method: method, Path: rawpath, Matched: a.matched,
					Detail: "restricted PAT refused but the dispatched route is not a refused write (Find matched a different route than chi served)",
				})
			}
		} else if a.matched == "" && actualRefuse {
			// chi dispatches to NO handler (404/405) yet the PAT middleware found a
			// pattern and refused: Find and dispatch disagree on routability.
			out = append(out, oracleViolation{
				Class: "CH1-B-pat-refuses-unrouted", Method: method, Path: rawpath, Matched: "",
				Detail: "PAT middleware refused a request chi routes to no handler",
			})
		}
	}

	// CH1-C routing differential: compare chi's dispatch to the independent matcher.
	if a.matched != "" {
		for _, v := range differentialViolations(inv, method, rawpath, a.matched) {
			out = append(out, v)
		}
	}
	return out
}

// --- CH1-C: independent reference matcher ---
//
// The reference is intentionally simple and well-defined: it matches on the
// PERCENT-DECODED path with strict RFC-3986 generic-URI segment semantics — split
// on '/', a literal pattern segment must equal the decoded request segment exactly
// (case-sensitive), a {param} segment matches exactly one non-empty segment, no
// wildcard crossing. chi instead matches on the ESCAPED path and treats %2F as a
// non-separator; the differences between the two are the EXPECTED-DIFFERENCE classes
// (encoded-slash, trailing-slash, dot-segment, ...). A disagreement that maps to no
// known class is a NEW class and fails the oracle, catching a genuinely surprising
// routing outcome or a route-table change that introduces a new ambiguity.

func splitSegments(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// effectivePattern maps an inventory entry to the pattern chi actually registers
// and reports via RoutePattern(): a MOUNT subtree (e.g. "/swagger/") is served as a
// catch-all "/swagger/*", every other entry keeps its pattern verbatim.
func effectivePattern(e routeEntry) string {
	if e.Method == "MOUNT" {
		return strings.TrimSuffix(e.Pattern, "/") + "/*"
	}
	return e.Pattern
}

// referenceMatch returns the set of same-method effective patterns that match
// rawpath under the strict decoded semantics above.
func referenceMatch(inv []routeEntry, method, rawpath string) []string {
	decoded, err := url.PathUnescape(stripQuery(rawpath))
	if err != nil {
		return nil
	}
	reqSegs := splitSegments(decoded)
	var matches []string
	for _, e := range inv {
		if !methodMatches(e.Method, method) {
			continue
		}
		if patternMatches(effectivePattern(e), reqSegs) {
			matches = append(matches, effectivePattern(e))
		}
	}
	sort.Strings(matches)
	return matches
}

func methodMatches(invMethod, reqMethod string) bool {
	switch invMethod {
	case "HANDLE", "MOUNT":
		return true // any method
	}
	return invMethod == reqMethod
}

func patternMatches(pattern string, reqSegs []string) bool {
	patSegs := splitSegments(pattern)
	for i, ps := range patSegs {
		// A trailing "*" catch-all (chi mount subtree) matches the remainder,
		// including zero further segments.
		if ps == "*" {
			return true
		}
		if i >= len(reqSegs) {
			return false
		}
		rs := reqSegs[i]
		if strings.HasPrefix(ps, "{") && strings.HasSuffix(ps, "}") {
			if rs == "" {
				return false
			}
			continue
		}
		if ps != rs {
			return false
		}
	}
	return len(patSegs) == len(reqSegs)
}

// stripQuery removes a query string. It deliberately does NOT treat '#' as a
// fragment delimiter: in an origin-form request target (RFC 7230 §5.3.1) there is no
// fragment, and Go's url.ParseRequestURI / chi keep a '#' as a literal path byte, so
// the reference matcher must route it the same way chi does (a '#' inside a segment
// is part of that segment's {param} value), not slice the path off at it.
func stripQuery(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

// differentialViolations classifies any disagreement between chi's dispatch and the
// reference matcher into a named class, returning only classes NOT in the committed
// EXPECTED-DIFFERENCE set.
func differentialViolations(inv []routeEntry, method, rawpath, chiMatched string) []oracleViolation {
	ref := referenceMatch(inv, method, rawpath)
	agree := false
	for _, r := range ref {
		if r == chiMatched {
			agree = true
			break
		}
	}
	if agree && len(ref) == 1 {
		return nil // unambiguous agreement
	}
	class := classifyDifferential(rawpath, chiMatched, ref)
	if expectedDifferenceClasses[class] {
		return nil
	}
	return []oracleViolation{{
		Class: "CH1-C:" + class, Method: method, Path: rawpath, Matched: chiMatched,
		Detail: fmt.Sprintf("reference matched %v", ref),
	}}
}

// classifyDifferential assigns a stable class name to a chi-vs-reference
// disagreement, based on the structural feature of the request path that explains it.
func classifyDifferential(rawpath, chiMatched string, ref []string) string {
	decodedPath := stripQuery(rawpath)
	switch {
	case strings.Contains(strings.ToUpper(rawpath), "%2F"):
		return "encoded-slash"
	case strings.Contains(rawpath, "%"):
		return "percent-encoding"
	case strings.Contains(decodedPath, "//"):
		return "double-slash"
	case hasDotSegment(decodedPath):
		return "dot-segment"
	case strings.HasSuffix(decodedPath, "/") && decodedPath != "/":
		return "trailing-slash"
	case len(ref) == 0:
		// chi matched but the strict reference matched nothing, and no encoding
		// feature explains it: a structural surprise worth a hard look.
		return "chi-matched-reference-empty"
	case len(ref) > 1:
		return "reference-ambiguous"
	default:
		return "chi-picks-different-route"
	}
}

func hasDotSegment(p string) bool {
	for _, s := range splitSegments(p) {
		if s == "." || s == ".." {
			return true
		}
	}
	return false
}
