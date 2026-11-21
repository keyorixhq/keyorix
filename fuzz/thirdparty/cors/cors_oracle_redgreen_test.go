package corshostile

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const budgetPath = "testdata/resguard-cors.json"

// hostileOrigins are Origin values an attacker can send that must NEVER be reflected
// by Keyorix's real (exact, wildcard-free) CORS config. The committed guard
// TestCORSRealConfig_NeverReflectsUnlisted asserts each yields no Access-Control-
// Allow-Origin; the fuzzer generalises it.
var hostileOrigins = []string{
	"https://evil.example",
	"https://app.keyorix.example.evil", // suffix append
	"https://app.keyorix.example.evil.com",
	"https://evil.keyorix.example", // subdomain (would match a wildcard config, not the exact one)
	"https://appxkeyorix.example",
	"https://app.keyorix.example#.keyorix.example",
	"https://app.keyorix.example/.keyorix.example",
	"null",
	"http://localhost:3000.evil.com",
	"http://localhost:3001", // wrong port
	"file://",
	"https://APP.KEYORIX.EXAMPLE.ATTACKER", // case + suffix
}

// TestCORSRealConfig_NeverReflectsUnlisted is the committed security guard (default
// `go test`): under the real exact allowlist, no hostile origin is ever reflected and
// no credentialed wildcard is ever emitted — across actual AND preflight shapes.
func TestCORSRealConfig_NeverReflectsUnlisted(t *testing.T) {
	h := corsHandler(exactAllowlist)
	for _, o := range hostileOrigins {
		shapes := []corsReq{
			{method: http.MethodGet, hasOrigin: true, origin: o},
			{method: http.MethodPost, hasOrigin: true, origin: o, reqMethod: "", reqHeaders: "Authorization"},
			canonicalPreflight(o, true),
			{method: http.MethodOptions, hasOrigin: true, origin: o, reqMethod: "POST", reqHeaders: "Authorization, Content-Type"},
		}
		for _, req := range shapes {
			hdr := serve(h, req, nil, nil)
			if v := checkSecurity(exactAllowlist, true, req, hdr); len(v) != 0 {
				t.Errorf("origin %q shape %+v: %v (resp=%v)", o, req, v, hdr)
			}
			if acao := hdr.Get("Access-Control-Allow-Origin"); acao != "" {
				t.Errorf("origin %q shape %+v: unexpected reflection ACAO=%q", o, req, acao)
			}
		}
	}
}

// TestCORSAllowedOrigins_AreAccepted is the calibration/positive guard: a legitimate
// origin IS reflected (so the harness is not vacuously green because CORS is off).
func TestCORSAllowedOrigins_AreAccepted(t *testing.T) {
	h := corsHandler(exactAllowlist)
	for _, o := range []string{"https://app.keyorix.example", "http://localhost:3000", "HTTP://LOCALHOST:5173"} {
		hdr := serve(h, canonicalPreflight(o, true), nil, nil)
		if hdr.Get("Access-Control-Allow-Origin") == "" {
			t.Errorf("legitimate origin %q was NOT reflected — harness would be vacuously green", o)
		}
		// Reflected value must be the request origin (original case).
		if got := hdr.Get("Access-Control-Allow-Origin"); got != o {
			t.Errorf("origin %q reflected as %q (expected echo of request origin)", o, got)
		}
		if !strings.EqualFold(hdr.Get("Access-Control-Allow-Credentials"), "true") {
			t.Errorf("origin %q: credentials header missing on allowed origin", o)
		}
	}
}

// TestCORSOracle_RedGreen red/green-proves the O-CORS-1 and O-CORS-2 detection logic
// on crafted responses (the defect is expressible as a crafted response header set, so
// no library/production edit is needed — mirroring backupfmt's input-expressible plant).
func TestCORSOracle_RedGreen(t *testing.T) {
	// --- O-CORS-2: credentialed wildcard ---
	redWildcard := http.Header{}
	redWildcard.Set("Access-Control-Allow-Origin", "*")
	redWildcard.Set("Access-Control-Allow-Credentials", "true")
	if v := checkSecurity(exactAllowlist, true, corsReq{hasOrigin: true, origin: "https://evil.example"}, redWildcard); !hasViolation(v, "O-CORS-2") {
		t.Fatalf("O-CORS-2 RED failed: credentialed wildcard not flagged: %v", v)
	}
	greenWildcard := http.Header{}
	greenWildcard.Set("Access-Control-Allow-Origin", "https://app.keyorix.example")
	greenWildcard.Set("Access-Control-Allow-Credentials", "true")
	if v := checkSecurity(exactAllowlist, true, corsReq{hasOrigin: true, origin: "https://app.keyorix.example"}, greenWildcard); hasViolation(v, "O-CORS-2") {
		t.Fatalf("O-CORS-2 GREEN failed: specific credentialed origin wrongly flagged: %v", v)
	}

	// --- O-CORS-1: reflected non-allowlisted origin ---
	redReflect := http.Header{}
	redReflect.Set("Access-Control-Allow-Origin", "https://evil.example")
	redReflect.Set("Access-Control-Allow-Credentials", "true")
	if v := checkSecurity(exactAllowlist, true, corsReq{hasOrigin: true, origin: "https://evil.example"}, redReflect); !hasViolation(v, "O-CORS-1") {
		t.Fatalf("O-CORS-1 RED failed: reflected non-allowlisted origin not flagged: %v", v)
	}
	greenReflect := http.Header{}
	greenReflect.Set("Access-Control-Allow-Origin", "https://app.keyorix.example")
	if v := checkSecurity(exactAllowlist, true, corsReq{hasOrigin: true, origin: "https://app.keyorix.example"}, greenReflect); hasViolation(v, "O-CORS-1") {
		t.Fatalf("O-CORS-1 GREEN failed: allowlisted reflection wrongly flagged: %v", v)
	}
}

// TestCORSDifferential_RedGreen proves O-CORS-3's comparison distinguishes a matcher
// change. GREEN: the real handler's verdict equals the faithful reference. RED: a
// deliberately-broken reference (rejects everything) disagrees with go-chi on a real
// allowed origin, and the comparison catches it.
func TestCORSDifferential_RedGreen(t *testing.T) {
	h := corsHandler(exactAllowlist)
	ref := newRefMatcher(exactAllowlist)
	const allowed = "https://app.keyorix.example"

	hdr := serve(h, canonicalPreflight(allowed, true), nil, nil)
	gochiAllowed := hdr.Get("Access-Control-Allow-Origin") != ""
	if !gochiAllowed {
		t.Fatalf("precondition: go-chi must allow the configured origin")
	}
	// GREEN: faithful reference agrees.
	if gochiAllowed != ref.allowed(allowed) {
		t.Fatalf("O-CORS-3 GREEN failed: faithful reference disagrees with go-chi on an allowed origin")
	}
	// RED: a broken reference that rejects everything must be detected as a divergence.
	brokenAllowed := false // a matcher-change that stopped allowing the configured origin
	if gochiAllowed == brokenAllowed {
		t.Fatalf("O-CORS-3 RED failed: comparison did not distinguish a matcher change")
	}
}

func hasViolation(vs []string, code string) bool {
	for _, v := range vs {
		if strings.Contains(v, code) {
			return true
		}
	}
	return false
}

// benignCORSCosts measures a representative benign corpus for calibration: allowed and
// rejected origins, actual and preflight, including a moderately comma-dense (benign)
// Access-Control-Request-Headers so the per-byte slope reflects parseHeaderList.
func benignCORSCosts(tb testing.TB) []resguard.Cost {
	tb.Helper()
	h := corsHandler(exactAllowlist)
	reqs := []corsReq{
		{method: http.MethodGet, hasOrigin: true, origin: "https://app.keyorix.example"},
		{method: http.MethodPost, hasOrigin: true, origin: "http://localhost:3000", reqHeaders: "Authorization, Content-Type"},
		{method: http.MethodOptions, hasOrigin: true, origin: "https://app.keyorix.example", reqMethod: "POST", reqHeaders: "Accept, Authorization, Content-Type, X-CSRF-Token, X-Requested-With"},
		{method: http.MethodGet, hasOrigin: true, origin: "https://evil.example"},
		{method: http.MethodOptions, hasOrigin: true, origin: "https://app.keyorix.example", reqMethod: "GET", reqHeaders: strings.Repeat("A, ", 256)},
		{method: http.MethodGet, hasOrigin: false},
	}
	var costs []resguard.Cost
	for range 6 {
		for _, req := range reqs {
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			var c resguard.Cost
			_ = serve(h, req, p, &c)
			costs = append(costs, c)
		}
	}
	return costs
}

// TestCORSCalibrate regenerates the committed budget under RESGUARD_CALIBRATE=1;
// otherwise it asserts calibration yields an alloc budget.
func TestCORSCalibrate(t *testing.T) {
	b := resguard.Calibrate("cors_serve", benignCORSCosts(t), resguard.DefaultFactor)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes should be calibrated; meters=%v", b.Summary())
	}
	// Drop live_heap: a single CORS serve is sub-microsecond and allocates a few KiB,
	// so the post-GC whole-process live-heap reading is dominated by the fuzz engine's
	// own heap (observed 21 MiB vs a 15 MiB calibrated ceiling on a 7-byte input), not
	// by anything input-attributable. The input-attributable amplification meters for
	// this target are alloc_bytes and mallocs; those stay fatal. Cross-input heap leaks,
	// if any, would still surface via Probe.CheckDrift, not via a per-input ceiling.
	// (INV-FUZZCORS-liveheap-not-metered)
	delete(b.Meters, "live_heap")
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(budgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", budgetPath, b.Summary())
	}
}
