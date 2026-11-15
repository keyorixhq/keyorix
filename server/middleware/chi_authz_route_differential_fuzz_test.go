package middleware

import (
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/internal/core"
)

// adversarialSeeds are method+path pairs that exercise the path-manipulation shapes
// CH1 targets: percent-encoding, encoded slashes, dot segments, double slashes,
// trailing slashes, case, and unicode — over both REFUSED and ALLOWED restricted-PAT
// ungated writes, plus a few reads and non-/api routes.
var adversarialSeeds = []struct{ method, path string }{
	// Refused ungated writes (restricted PAT must be 403'd on the real route).
	{"POST", "/api/v1/auth/mfa/disable"},
	{"POST", "/api/v1/auth/mfa/disable/"},                    // trailing slash
	{"POST", "/api/v1/auth/mfa/disable/."},                   // dot segment
	{"POST", "/api/v1/auth//mfa/disable"},                    // double slash
	{"POST", "/api/v1/auth/mfa/%64isable"},                   // percent-encoded 'd'
	{"POST", "/api/v1/AUTH/mfa/disable"},                     // case
	{"POST", "/api/v1/notifications/1/read"},                 // refused {id}/read
	{"POST", "/api/v1/notifications/1%2Fread"},               // encoded slash collapse attempt
	{"DELETE", "/api/v1/secrets/7/self-share"},               // refused
	{"DELETE", "/api/v1/secrets/7%2Fself-share"},             // encoded slash
	{"POST", "/api/v1/projects/7/break-glass"},               // refused
	{"POST", "/api/v1/projects/7%2Fbreak-glass/break-glass"}, // encoded-slash reroute
	{"POST", "/api/v1/secret-access-requests"},               // refused
	// Allowed ungated writes (restricted PAT must pass).
	{"POST", "/api/v1/secrets"},
	{"POST", "/api/v1/secrets/"},
	{"DELETE", "/api/v1/auth/tokens/5"},
	{"DELETE", "/api/v1/auth/tokens/expired"},
	{"POST", "/api/v1/folders"},
	{"PUT", "/api/v1/secret-access-requests/9"},
	// Gated writes (not in the table; PAT middleware must pass, Authorize handles it).
	{"PUT", "/api/v1/projects/3"},
	{"DELETE", "/api/v1/secrets/7"},
	{"POST", "/api/v1/roles"},
	// Reads and non-/api routes (PAT middleware is a no-op for these).
	{"GET", "/api/v1/secrets/7"},
	{"HEAD", "/api/v1/projects/3"},
	{"OPTIONS", "/api/v1/secrets"},
	{"POST", "/auth/login"},
	{"GET", "/health"},
	{"GET", "/swagger/index.html"},
	// Unicode / odd bytes in params.
	{"POST", "/api/v1/projects/%C3%A9/break-glass"},
	{"POST", "/api/v1/projects/../break-glass"},
	{"DELETE", "/api/v1/secrets/7/self-share/../self-share"},
}

// TestChiAuthzReplica_Smoke proves the replica builds, dispatches, and reports the
// full mounted RoutePattern (including /api/v1) — the ground truth the oracles read.
func TestChiAuthzReplica_Smoke(t *testing.T) {
	inv := loadInventory(t)
	h := buildReplica(t, inv, realPATFactory)

	// A concrete dispatch records the full pattern.
	r := ch1Serve(h, "POST", "/api/v1/auth/mfa/disable", false)
	if !r.ok || r.status != http.StatusOK {
		t.Fatalf("expected 200 dispatch, got ok=%v status=%d", r.ok, r.status)
	}
	if r.matched != "/api/v1/auth/mfa/disable" {
		t.Fatalf("RoutePattern not the full mounted pattern: got %q", r.matched)
	}
	// The real middleware refuses a restricted PAT on that refused route.
	rb := ch1Serve(h, "POST", "/api/v1/auth/mfa/disable", true)
	if rb.status != http.StatusForbidden {
		t.Fatalf("restricted PAT must be 403 on a refused ungated write, got %d", rb.status)
	}
	// And passes it on an allowed one.
	ra := ch1Serve(h, "POST", "/api/v1/secrets", true)
	if ra.status == http.StatusForbidden {
		t.Fatalf("restricted PAT must NOT be 403 on an allowed ungated write, got 403")
	}
	// Sanity: the refusal table actually classifies these as expected.
	if core.RestrictedPATWriteRefusal("POST /api/v1/auth/mfa/disable") == nil {
		t.Fatal("precondition broken: POST /api/v1/auth/mfa/disable is not refused in the table")
	}
	if core.RestrictedPATWriteRefusal("POST /api/v1/secrets") != nil {
		t.Fatal("precondition broken: POST /api/v1/secrets is not allowed in the table")
	}
}

// TestChiAuthzRouteDifferential_Seeds runs all oracles deterministically over the
// adversarial seed corpus. It is the committed guard (default `go test`): a new
// routing-vs-authz divergence class fails here.
func TestChiAuthzRouteDifferential_Seeds(t *testing.T) {
	inv := loadInventory(t)
	h := buildReplica(t, inv, realPATFactory)
	for _, s := range adversarialSeeds {
		for _, v := range checkCase(h, inv, s.method, s.path) {
			t.Errorf("oracle violation: %s", v)
		}
	}
}

// buggyUnescapedPATFactory is a SCRATCH COPY of RefuseRestrictedPATUngatedWrites
// carrying a planted defect: it resolves the route from the DECODED r.URL.Path
// instead of chi's escaped rctx.RoutePath. This is the classic encoded-slash bug
// class — Find then matches a different pattern than chi dispatches. Never shipped;
// exists only to red-prove the CH1-A/CH1-B oracle fires on a real divergence.
func buggyUnescapedPATFactory(routes chi.Routes) func(http.Handler) http.Handler {
	const prefix = "/api/v1"
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			u := GetUserFromContext(r.Context())
			if u == nil || u.PATRestriction == nil {
				next.ServeHTTP(w, r)
				return
			}
			// PLANTED DEFECT: decoded path, ignoring rctx.RoutePath.
			path := strings.TrimPrefix(r.URL.Path, prefix)
			pattern := routes.Find(chi.NewRouteContext(), r.Method, path)
			if len(pattern) > 1 {
				pattern = strings.TrimSuffix(pattern, "/")
			}
			if pattern != "" {
				if err := core.RestrictedPATWriteRefusal(r.Method + " " + prefix + pattern); err != nil {
					forbiddenResponse(w, err.Error())
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TestChiAuthzRouteDifferential_RedProof is the red/green proof for the primary
// oracle: the SAME vector is consistent against the real middleware (green) and
// trips CH1-A against the planted decoded-path defect (red). The vector
// `/api/v1/projects/{id}/break-glass` reached via an encoded slash in {id} dispatches
// to the refused break-glass route in chi, but the buggy middleware's decoded Find
// sees a different (unregistered) path and fails to refuse.
func TestChiAuthzRouteDifferential_RedProof(t *testing.T) {
	inv := loadInventory(t)
	const method = "POST"
	const vector = "/api/v1/projects/7%2Fbreak-glass/break-glass"

	// Precondition: chi dispatches this vector to the refused break-glass route.
	real := buildReplica(t, inv, realPATFactory)
	disp := ch1Serve(real, method, vector, false)
	if disp.matched != "/api/v1/projects/{id}/break-glass" {
		t.Fatalf("precondition: expected chi to dispatch the vector to the break-glass route, got %q", disp.matched)
	}
	if core.RestrictedPATWriteRefusal(method+" "+disp.matched) == nil {
		t.Fatalf("precondition: break-glass must be a refused ungated write")
	}

	// GREEN: the real middleware is consistent — no violation.
	if vs := checkCase(real, inv, method, vector); len(vs) != 0 {
		t.Fatalf("real middleware should be consistent on the vector, got violations: %v", vs)
	}

	// RED: against the planted defect, the oracle must fire CH1-A (bypass). We drive
	// the buggy replica directly through the same oracle comparison.
	buggy := buildReplica(t, inv, buggyUnescapedPATFactory)
	a := ch1Serve(buggy, method, vector, false) // dispatch pattern (unrestricted)
	b := ch1Serve(buggy, method, vector, true)  // restricted PAT
	if a.matched != "/api/v1/projects/{id}/break-glass" {
		t.Fatalf("buggy replica dispatch changed unexpectedly: %q", a.matched)
	}
	shouldRefuse := core.RestrictedPATWriteRefusal(method+" "+a.matched) != nil
	actualRefuse := b.status == http.StatusForbidden
	if !(shouldRefuse && !actualRefuse) {
		t.Fatalf("red proof failed: expected CH1-A bypass against the planted defect "+
			"(shouldRefuse=%v actualRefuse=%v status=%d) — the oracle did not distinguish the bug",
			shouldRefuse, actualRefuse, b.status)
	}
}

// FuzzChiAuthzRouteDifferential drives the real PAT-restriction middleware and chi
// over fuzzed method+path inputs, failing on any CH1-A/CH1-B authorization-vs-routing
// divergence or any NEW CH1-C routing-differential class. See the package doc and
// EXPECTED-DIFFERENCE.md for what each oracle does and does not verify.
func FuzzChiAuthzRouteDifferential(f *testing.F) {
	inv := loadInventory(f)
	h := buildReplica(f, inv, realPATFactory)

	for _, s := range adversarialSeeds {
		f.Add(methodIndexOf(s.method), s.path)
	}
	// A couple of raw structural seeds.
	f.Add(uint8(1), "/api/v1/secrets/../auth/mfa/disable")
	f.Add(uint8(1), "/api/v1/auth/mfa/disable%2F")

	f.Fuzz(func(t *testing.T, mIdx uint8, path string) {
		method := methodSet[int(mIdx)%len(methodSet)]
		if path == "" || path[0] != '/' {
			return // only absolute-path request targets are routing cases
		}
		for _, v := range checkCase(h, inv, method, path) {
			t.Errorf("oracle violation: %s", v)
		}
	})
}

func methodIndexOf(m string) uint8 {
	for i, v := range methodSet {
		if v == m {
			return uint8(i)
		}
	}
	return 0
}
