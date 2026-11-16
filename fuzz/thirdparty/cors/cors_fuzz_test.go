// Package corshostile is a test-only hostile-input harness for the go-chi/cors
// middleware (github.com/go-chi/cors) as Keyorix wires it in
// server/http/router.go. The Origin / Access-Control-Request-* headers are fully
// attacker-controlled on every request that reaches the server, and cors.Handler
// is the FIRST security-relevant middleware in the chain, so its origin-matching
// and credentialed-response behaviour is on the real request path.
//
// This package deliberately does NOT rebuild the chi routing-vs-authz differential
// (owned by server/middleware FuzzChiAuthzRouteDifferential) nor the kin-openapi
// request/response stateful fuzzer (server/http FuzzOpenAPIStateful). It fills the
// one un-covered gap for go-chi/cors: before this harness the only CORS test was
// server/http TestEnvironmentLabel_TemplatesDoNotRelaxCORS, which checks the config
// template's origin LIST but never exercises the middleware against a hostile Origin.
//
// ORACLES (each documents below what it does and does NOT verify):
//
//	O-CORS-1  reflect-only-allowlisted: under Keyorix's real EXACT allowlist, any
//	          Access-Control-Allow-Origin emitted must be the request Origin AND be
//	          a (case-insensitive) member of the configured allowlist. Never reflect
//	          an origin that is not allowlisted. FATAL. Reachable.
//	O-CORS-2  no credentialed wildcard: Access-Control-Allow-Origin=="*" must never
//	          co-occur with Access-Control-Allow-Credentials:true in one response.
//	          FATAL. Reachable (the classic CORS bypass).
//	O-CORS-3  matching pinned to a faithful reference: go-chi's isOriginAllowed
//	          verdict (observed via a canonical preflight probe) must equal a
//	          line-for-line port of cors v1.2.2's matcher. A divergence is a
//	          dependency-bump behaviour change. FATAL.
//	O-CORS-4  no panic + bounded work: one handler serve under a resguard budget;
//	          a panic or an alloc blow-up (e.g. parseHeaderList amplification on a
//	          comma-dense Access-Control-Request-Headers) fails. FATAL.
package corshostile

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/cors"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// keyorixCORSOptions mirrors the option set in server/http/router.go EXACTLY except
// for AllowedOrigins, which the caller supplies (getAllowedOrigins derives it from
// config at runtime). If router.go's options change, update this mirror in the same
// change (INV-FUZZCORS-options-mirror-router).
func keyorixCORSOptions(allowed []string) cors.Options {
	return cors.Options{
		AllowedOrigins:   allowed,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Requested-With"},
		ExposedHeaders:   []string{"Link", "X-Total-Count", "X-Page-Count"},
		MaxAge:           300,
		AllowCredentials: true,
	}
}

// exactAllowlist is the UNION of every origin shape getAllowedOrigins can return
// WITHOUT an admin wildcard: the dev localhost set plus a representative prod
// same-origin value. None contains '*'. This is the reachable, security-critical
// configuration (O-CORS-1/2 run against it).
var exactAllowlist = []string{
	"http://localhost:3000",
	"http://localhost:5173",
	"http://127.0.0.1:3000",
	"http://127.0.0.1:5173",
	"https://app.keyorix.example",
}

// wildAllowlist adds an admin-configured wildcard pattern (the only way a '*' ever
// enters Keyorix's CORS config). O-CORS-3 pins go-chi's wildcard matching here; it
// is a library-characterisation config, reachable only via operator misconfiguration.
var wildAllowlist = []string{
	"https://app.keyorix.example",
	"https://*.keyorix.example",
}

// sentinelBody is written by the terminal handler so a test can tell whether the
// chain continued past the CORS middleware (actual requests pass through; preflight
// stops the chain with 200).
const sentinelBody = "NEXT-RAN"

func corsHandler(allowed []string) http.Handler {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(sentinelBody))
	})
	return cors.Handler(keyorixCORSOptions(allowed))(next)
}

// ---------------------------------------------------------------------------
// Faithful reference port of cors v1.2.2 origin matching (cors.go isOriginAllowed
// + utils.go wildcard.match). Used by O-CORS-3 to pin the library's verdict.
// ---------------------------------------------------------------------------

type refWildcard struct{ prefix, suffix string }

type refMatcher struct {
	all   bool
	exact []string
	wild  []refWildcard
}

func newRefMatcher(allowed []string) refMatcher {
	var m refMatcher
	if len(allowed) == 0 {
		m.all = true
		return m
	}
	for _, o := range allowed {
		o = strings.ToLower(o)
		if o == "*" {
			m.all = true
			m.exact = nil
			m.wild = nil
			return m
		}
		if i := strings.IndexByte(o, '*'); i >= 0 {
			m.wild = append(m.wild, refWildcard{o[:i], o[i+1:]})
		} else {
			m.exact = append(m.exact, o)
		}
	}
	return m
}

func (m refMatcher) allowed(origin string) bool {
	if m.all {
		return true
	}
	o := strings.ToLower(origin)
	for _, e := range m.exact {
		if e == o {
			return true
		}
	}
	for _, w := range m.wild {
		if len(o) >= len(w.prefix)+len(w.suffix) && strings.HasPrefix(o, w.prefix) && strings.HasSuffix(o, w.suffix) {
			return true
		}
	}
	return false
}

// hasExplicitStar reports whether the allowlist literally contains "*" (which makes
// go-chi emit ACAO "*"). Keyorix never configures this; the check exists so O-CORS-1
// can distinguish "exact-list config" (where "*" output is impossible-by-design) from
// a genuine all-origins config.
func hasExplicitStar(allowed []string) bool {
	for _, o := range allowed {
		if o == "*" {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Oracle (pure function over config + request + response) — shared by the fuzz
// body and the committed red/green proof.
// ---------------------------------------------------------------------------

type corsReq struct {
	method     string
	hasOrigin  bool
	origin     string
	reqMethod  string // Access-Control-Request-Method
	reqHeaders string // Access-Control-Request-Headers
}

// checkSecurity runs O-CORS-1 and O-CORS-2 against one real response. allowed is the
// configured allowlist; exactConfig is true when that allowlist is Keyorix's wildcard-
// free reachable configuration (O-CORS-1 only makes its "member of allowlist" claim
// there). Returns human-readable violations.
//
// Does NOT verify: Vary header correctness, Max-Age value, exposed-header list, or
// that a LEGITIMATE origin is accepted (under-permissiveness is not a security bug and
// is logged, not failed — see O-CORS-3 for the pinned verdict).
func checkSecurity(allowed []string, exactConfig bool, req corsReq, resp http.Header) []string {
	var v []string
	acao := resp.Get("Access-Control-Allow-Origin")
	acac := resp.Get("Access-Control-Allow-Credentials")

	// O-CORS-2: credentialed wildcard, forbidden on any config.
	if acao == "*" && strings.EqualFold(acac, "true") {
		v = append(v, "O-CORS-2: Access-Control-Allow-Origin:* emitted together with Access-Control-Allow-Credentials:true")
	}

	if acao == "" {
		return v // nothing reflected — no reflection hazard to check.
	}

	if exactConfig {
		// O-CORS-1a: an exact (wildcard-free, star-free) config must never emit "*".
		if acao == "*" {
			v = append(v, "O-CORS-1: exact allowlist emitted Access-Control-Allow-Origin:* (no '*' is configured)")
			return v
		}
		// O-CORS-1b: the reflected value must equal the request Origin (go-chi reflects
		// the original-case Origin), and must be a case-insensitive member of the list.
		if req.hasOrigin && acao != req.origin {
			v = append(v, "O-CORS-1: reflected ACAO "+quote(acao)+" != request Origin "+quote(req.origin))
		}
		m := newRefMatcher(allowed)
		if !m.allowed(acao) {
			v = append(v, "O-CORS-1: reflected non-allowlisted origin "+quote(acao)+" (lower-case not in exact allowlist)")
		}
	}
	return v
}

func quote(s string) string {
	if len(s) > 120 {
		s = s[:120] + "...(truncated)"
	}
	return "\"" + s + "\""
}

// buildRequest constructs an *http.Request carrying exactly the fuzzed headers. A
// present-but-empty Origin ("null"/empty) is distinguished from an absent one.
func buildRequest(req corsReq) *http.Request {
	r := httptest.NewRequest(req.method, "/api/v1/secrets", nil)
	// httptest.NewRequest does not set Origin; set it explicitly (and only when present
	// so the absent case exercises the no-Origin branch).
	r.Header.Del("Origin")
	if req.hasOrigin {
		r.Header["Origin"] = []string{req.origin}
	}
	if req.reqMethod != "" {
		r.Header.Set("Access-Control-Request-Method", req.reqMethod)
	}
	if req.reqHeaders != "" {
		r.Header.Set("Access-Control-Request-Headers", req.reqHeaders)
	}
	return r
}

// serve runs one request through the real cors.Handler and returns the response
// header (metered by probe when non-nil for O-CORS-4).
func serve(h http.Handler, req corsReq, probe *resguard.Probe, cost *resguard.Cost) http.Header {
	r := buildRequest(req)
	rec := httptest.NewRecorder()
	if probe != nil {
		c := probe.Measure(len(req.origin)+len(req.reqHeaders)+len(req.reqMethod), func() {
			h.ServeHTTP(rec, r)
		})
		*cost = c
	} else {
		h.ServeHTTP(rec, r)
	}
	return rec.Header()
}

// canonicalPreflight isolates origin matching: an OPTIONS preflight with an ALLOWED
// method (GET) and NO requested headers passes every gate except the origin gate, so
// ACAO is set iff go-chi's isOriginAllowed returned true.
func canonicalPreflight(origin string, hasOrigin bool) corsReq {
	return corsReq{method: http.MethodOptions, hasOrigin: hasOrigin, origin: origin, reqMethod: http.MethodGet}
}

var methodChoices = []string{http.MethodGet, http.MethodPost, http.MethodOptions, http.MethodPut, http.MethodDelete, http.MethodPatch, "TRACE"}

func FuzzCORSHostileOrigin(f *testing.F) {
	exactH := corsHandler(exactAllowlist)
	wildH := corsHandler(wildAllowlist)
	exactRef := newRefMatcher(exactAllowlist)
	wildRef := newRefMatcher(wildAllowlist)

	// Budget: the CORS serve allocates header-map entries plus (for a comma-dense
	// Access-Control-Request-Headers) a parseHeaderList slice of ~one entry per comma.
	// Calibrated on benign serves; a blow-up beyond the slope is an amplification.
	budget, budgetErr := resguard.LoadBudget("testdata/resguard-cors.json")
	haveBudget := budgetErr == nil
	if !haveBudget {
		f.Logf("no committed budget at testdata/resguard-cors.json (run TestCORSCalibrate with RESGUARD_CALIBRATE=1); metering without a ceiling")
	}
	p := resguard.New(f, resguard.Options{SampleEvery: 16})

	seedOrigins := []string{
		"https://app.keyorix.example",      // allowed
		"http://localhost:3000",            // allowed (dev)
		"HTTP://LOCALHOST:3000",            // case-fold -> allowed, reflected original case
		"https://evil.example",             // not allowed
		"null",                             // null origin
		"",                                 // present-empty origin
		"https://app.keyorix.example.evil", // suffix-trick (must NOT match exact)
		"https://evil.keyorix.example",     // subdomain (matches wildCfg, not exactCfg)
		"https://app.keyorix.example\r\nX-Injected: 1",
		"https://app.keyorix.example#.keyorix.example",
	}
	for _, o := range seedOrigins {
		f.Add(uint8(2), true, o, "GET", "")                             // preflight probe shape
		f.Add(uint8(1), true, o, "POST", "Authorization, Content-Type") // actual-ish
	}
	// sel=4 -> method=OPTIONS, so ACRM makes it a preflight and the comma-dense
	// Access-Control-Request-Headers is parsed under measurement (parseHeaderList).
	f.Add(uint8(4), true, "https://x.keyorix.example", "GET", strings.Repeat(",", 4096)) // comma bomb (preflight)
	f.Add(uint8(0), false, "", "GET", "")                                                // no Origin

	f.Fuzz(func(t *testing.T, sel uint8, hasOrigin bool, origin, reqMethod, reqHeaders string) {
		if len(origin) > 1<<16 || len(reqHeaders) > 1<<16 || len(reqMethod) > 4096 {
			return
		}
		method := methodChoices[int(sel>>1)%len(methodChoices)]
		useWild := sel&1 == 1

		h, allowed, ref := exactH, exactAllowlist, exactRef
		if useWild {
			h, allowed, ref = wildH, wildAllowlist, wildRef
		}
		exactConfig := !useWild && !hasExplicitStar(allowed)

		// --- O-CORS-4 + O-CORS-1/2 on the fuzzed request shape ---
		fuzzReq := corsReq{method: method, hasOrigin: hasOrigin, origin: origin, reqMethod: reqMethod, reqHeaders: reqHeaders}
		var cost resguard.Cost
		var hdr http.Header
		if haveBudget {
			hdr = serve(h, fuzzReq, p, &cost)
			resguard.FeedCoverage(cost)
			budget.Check(t.Fatalf, cost)
		} else {
			hdr = serve(h, fuzzReq, nil, nil)
		}
		for _, viol := range checkSecurity(allowed, exactConfig, fuzzReq, hdr) {
			t.Fatalf("%s\n  config=%v method=%s hasOrigin=%v origin=%q acrm=%q acrh.len=%d\n  resp=%v",
				viol, allowed, method, hasOrigin, origin, reqMethod, len(reqHeaders), hdr)
		}

		// --- O-CORS-3: pin go-chi's origin verdict to the faithful reference via a
		// canonical preflight (isolates the origin gate). Only meaningful with Origin. ---
		if hasOrigin {
			pre := canonicalPreflight(origin, true)
			preHdr := serve(h, pre, nil, nil)
			gochiAllowed := preHdr.Get("Access-Control-Allow-Origin") != ""
			refAllowed := ref.allowed(origin)
			if gochiAllowed != refAllowed {
				t.Fatalf("O-CORS-3: go-chi/cors origin verdict diverged from the pinned reference\n  config=%v origin=%q\n  go-chi allowed=%v  reference allowed=%v",
					allowed, origin, gochiAllowed, refAllowed)
			}
			// Re-check the security oracles on the isolated preflight too.
			for _, viol := range checkSecurity(allowed, exactConfig, pre, preHdr) {
				t.Fatalf("%s (canonical preflight)\n  config=%v origin=%q resp=%v", viol, allowed, origin, preHdr)
			}
		}
	})
}
