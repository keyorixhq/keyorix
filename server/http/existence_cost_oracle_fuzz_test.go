package http

// EX1 — information leakage by DIFFERENCE, with a DETERMINISTIC COST proxy.
//
// Oracle 7 (openapi_error_oracles_fuzz_test.go, osOracleDenialExistence /
// TestOSFDenialExistenceCensus) already proves that a zero-authority actor gets the SAME
// DENIAL STATUS for an existing-but-forbidden id as for an absent id — but it states, in its
// own doc comment, that it does NOT verify "timing/length side channels (status code only)".
//
// This file closes that stated gap. For the same metamorphic pair (existing-forbidden id vs
// a same-shape absent id, under the same zero-authority principal) it compares, in addition to
// the status code: the normalised error text, a response-body LENGTH BUCKET, information-
// bearing response HEADERS, and a DETERMINISTIC COST proxy — the resguard DBMeter's per-request
// DB QUERY COUNT and ROWS-TOUCHED delta. The cost is read as a METAMORPHIC DELTA between the two
// probes under the identical principal, so the common per-request overhead (token resolution,
// routing, deny-audit) cancels and only the id-existence-dependent component remains. Never wall
// time.
//
// It also adds the ACCOUNT-existence pair on POST /auth/login (known username + wrong password
// vs unknown username): the classic missing-dummy-hash bug would show as a status/text/length
// difference; the DB-cost proxy additionally surfaces the recordFailedLogin write asymmetry that
// the dummy-bcrypt equalizer does not cover.
//
// All TEST code; no production change. Classification of any difference:
//   ENUMERATION          — distinguishes existence in a client-observable dimension
//   EXPECTED-DIFFERENCE  — product deliberately differs (ADR-096 403-vs-404 for a globally
//                          privileged caller) — not reachable by the zero-authority principals here
//   ARTIFACT             — measurement/server-side only, not client-observable (e.g. rows scanned)

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// ex1Probe captures every dimension the oracle compares for one request.
type ex1Probe struct {
	code    int
	bodyLen int
	errText string            // normalised (digits/ids stripped) error envelope text
	headers map[string]string // only information-bearing headers
	dbQ     int               // DB round-trips issued by this request (resguard DBMeter)
	dbRows  int64             // DB rows touched by this request
}

// ex1InfoHeaders are the response headers that can carry existence information.
var ex1InfoHeaders = []string{
	"Location", "Retry-After", "Www-Authenticate",
	"X-Ratelimit-Remaining", "X-Ratelimit-Limit", "X-Ratelimit-Reset",
}

var ex1DigitRe = regexp.MustCompile(`\d+`)

// ex1NormErr reduces an error body to a shape-and-text signature that is independent of the
// specific id probed: parse the typed envelope, take error label + message, strip digits. Two
// denials that differ ONLY because one echoes a (different) numeric id are then equal, which is
// correct — that is not an existence oracle. A denial that names the RESOURCE differently
// ("secret not found" vs "forbidden") is NOT equal, which is the leak we want to catch.
func ex1NormErr(body string) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return "nonjson:" + ex1DigitRe.ReplaceAllString(strings.TrimSpace(body), "#")
	}
	lbl, _ := obj["error"].(string)
	msg, _ := obj["message"].(string)
	s := strings.ToLower(strings.TrimSpace(lbl + "|" + msg))
	return ex1DigitRe.ReplaceAllString(s, "#")
}

func ex1Headers(rec *httptest.ResponseRecorder) map[string]string {
	h := map[string]string{}
	for _, k := range ex1InfoHeaders {
		if v := rec.Header().Get(k); v != "" {
			// Strip digits so a (benign) numeric reset-timestamp/remaining-count that is the
			// same for both probes does not read as a difference, while presence/absence and
			// textual content still do.
			h[k] = ex1DigitRe.ReplaceAllString(v, "#")
		}
	}
	// Set-Cookie presence (not value) can itself be an existence signal on auth paths.
	if len(rec.Result().Cookies()) > 0 {
		h["Set-Cookie-present"] = "yes"
	}
	return h
}

// ex1LenBucket buckets a body length so a benign ±few-byte id-echo difference is tolerated but a
// structurally different body (an extra field, a different envelope) is not.
func ex1LenBucket(n int) int {
	switch {
	case n == 0:
		return 0
	case n < 32:
		return 1
	case n < 64:
		return 2
	case n < 128:
		return 3
	case n < 256:
		return 4
	case n < 512:
		return 5
	default:
		return 6 + n/512
	}
}

// ex1RunProbe issues build() under meter, warming once so the token/secret caches are hot, then
// measures the second (steady-state) call. Returns the probe signature.
func ex1RunProbe(w *osWorld, meter *resguard.DBMeter, build func() *http.Request) ex1Probe {
	_ = osExec(w, build()) // warm caches
	q0, r0 := meter.Queries(), meter.Rows()
	rec := osExec(w, build())
	q1, r1 := meter.Queries(), meter.Rows()
	body := rec.Body.String()
	return ex1Probe{
		code:    rec.Code,
		bodyLen: len(body),
		errText: ex1NormErr(body),
		headers: ex1Headers(rec),
		dbQ:     q1 - q0,
		dbRows:  r1 - r0,
	}
}

// ex1Finding is one distinguishing difference between an existing-forbidden and an absent probe.
type ex1Finding struct {
	dim    string // status | errtext | length | header:<name> | dbqueries | dbrows
	exist  string
	absent string
}

// ex1Compare is the PURE detector: it lists every dimension in which the two probes differ. The
// caller assigns the security classification (it knows the principal/op context). Kept pure so
// its red/green is a unit test (TestEX1CostDetector_RedGreen), per CLAUDE.md "a guard nobody has
// watched fail is not a guard" — we watch it fail on a synthetic planted difference and pass on
// an identical pair.
func ex1Compare(e, a ex1Probe) []ex1Finding {
	var f []ex1Finding
	if e.code != a.code {
		f = append(f, ex1Finding{"status", strconv.Itoa(e.code), strconv.Itoa(a.code)})
	}
	if e.errText != a.errText {
		f = append(f, ex1Finding{"errtext", e.errText, a.errText})
	}
	if ex1LenBucket(e.bodyLen) != ex1LenBucket(a.bodyLen) {
		f = append(f, ex1Finding{"length", strconv.Itoa(e.bodyLen), strconv.Itoa(a.bodyLen)})
	}
	keys := map[string]struct{}{}
	for k := range e.headers {
		keys[k] = struct{}{}
	}
	for k := range a.headers {
		keys[k] = struct{}{}
	}
	var sortedKeys []string
	for k := range keys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	for _, k := range sortedKeys {
		if e.headers[k] != a.headers[k] {
			f = append(f, ex1Finding{"header:" + k, e.headers[k], a.headers[k]})
		}
	}
	if e.dbQ != a.dbQ {
		f = append(f, ex1Finding{"dbqueries", strconv.Itoa(e.dbQ), strconv.Itoa(a.dbQ)})
	}
	if e.dbRows != a.dbRows {
		f = append(f, ex1Finding{"dbrows", strconv.FormatInt(e.dbRows, 10), strconv.FormatInt(a.dbRows, 10)})
	}
	return f
}

// ex1Classify assigns a security class to a dimension, given that BOTH probes were denials under
// a ZERO-AUTHORITY principal (so ADR-096's EXPECTED 403-vs-404-for-global-admin case cannot
// arise here).
//
//	status / errtext / length / header  -> ENUMERATION (client-observable)
//	dbqueries                           -> ENUMERATION candidate: a DB ROUND-TRIP asymmetry is a
//	                                       deterministic timing proxy (reported; severity depends
//	                                       on whether a dominating constant-time step masks it)
//	dbrows                              -> ARTIFACT: rows scanned is server-side, not a client-
//	                                       observable round-trip (DBMeter doc: "round-trips, not
//	                                       total DB work"); recorded, never gated
func ex1Classify(dim string) string {
	switch {
	case dim == "dbrows":
		return "ARTIFACT"
	case dim == "dbqueries":
		return "ENUMERATION-COST"
	default:
		return "ENUMERATION"
	}
}

// ---------------------------------------------------------------------------
// Red/green of the detector itself (committed proof the oracle fires)
// ---------------------------------------------------------------------------

func TestEX1CostDetector_RedGreen(t *testing.T) {
	base := ex1Probe{code: 403, bodyLen: 48, errText: "forbidden|", headers: map[string]string{}, dbQ: 3, dbRows: 3}

	// GREEN: identical pair -> no finding.
	if got := ex1Compare(base, base); len(got) != 0 {
		t.Fatalf("green case: expected 0 findings on identical probes, got %v", got)
	}

	// RED, each dimension in isolation must be caught.
	cases := []struct {
		name string
		mut  func(p *ex1Probe)
		dim  string
	}{
		{"status 403-vs-404", func(p *ex1Probe) { p.code = 404 }, "status"},
		{"errtext forbidden-vs-notfound", func(p *ex1Probe) { p.errText = "not found|" }, "errtext"},
		{"length bucket", func(p *ex1Probe) { p.bodyLen = 300 }, "length"},
		{"header Location appears", func(p *ex1Probe) { p.headers = map[string]string{"Location": "/x"} }, "header:Location"},
		{"extra db query on existing", func(p *ex1Probe) { p.dbQ = 4 }, "dbqueries"},
		{"extra db row on existing", func(p *ex1Probe) { p.dbRows = 4 }, "dbrows"},
	}
	for _, c := range cases {
		exist := base
		exist.headers = map[string]string{}
		c.mut(&exist)
		got := ex1Compare(exist, base)
		found := false
		for _, fnd := range got {
			if fnd.dim == c.dim {
				found = true
			}
		}
		if !found {
			t.Fatalf("red case %q: detector did not flag dimension %q (findings=%v)", c.name, c.dim, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Census: every single-id GET/DELETE op, zero-authority principals, cost proxy
// ---------------------------------------------------------------------------

// TestEX1ExistenceCostCensus drives the existing-vs-absent metamorphic pair over every enumerated
// single-id GET/DELETE op under each zero-authority principal, comparing all dimensions including
// the DB-cost proxy. A difference is confirmed only if it REPLAYS identically 3 times (robust to
// async deny-audit noise). Confirmed ENUMERATION-class (client-observable) differences fail the
// test; ENUMERATION-COST (DB round-trip) and ARTIFACT differences are reported, not gated.
func TestEX1ExistenceCostCensus(t *testing.T) {
	osLoadSpec(t)
	w := osBuildWorld(t)
	meter := resguard.NewDBMeter()
	if err := meter.Install(w.db); err != nil {
		t.Fatalf("install DBMeter: %v", err)
	}

	type agg struct {
		op, dims string
		class    string
		detail   string
	}
	var enumeration, cost, artifact []agg
	checked := 0

	for i := range osOps {
		o := &osOps[i]
		if !o.requiresAuth || (o.method != http.MethodGet && o.method != http.MethodDelete) {
			continue
		}
		var idParam *osPathParam
		numeric := 0
		for j := range o.pathParams {
			if !osStringPathParam(o.pathParams[j].name) {
				numeric++
				idParam = &o.pathParams[j]
			}
		}
		if numeric != 1 || idParam == nil {
			continue
		}
		pool := w.seedPools[idParam.preceding]
		if len(pool) == 0 {
			continue
		}
		existID := strconv.FormatUint(uint64(pool[0]), 10)

		for _, princ := range []int{osPrincNoRole, osPrincExpired} {
			buildE := func() *http.Request { r, _ := w.osBuildIDRequest(o, princ, existID); return r }
			buildA := func() *http.Request { r, _ := w.osBuildIDRequest(o, princ, "2000000001"); return r }
			if r, ok := w.osBuildIDRequest(o, princ, existID); !ok || r == nil {
				continue
			}

			// Replay the whole pair 3x; keep only the differences present in all 3 runs.
			var common map[string]ex1Finding
			allDenied := true
			for rep := 0; rep < 3; rep++ {
				pe := ex1RunProbe(w, meter, buildE)
				pa := ex1RunProbe(w, meter, buildA)
				if osIs2xx(pe.code) || osIs2xx(pa.code) {
					allDenied = false
					break
				}
				round := map[string]ex1Finding{}
				for _, fnd := range ex1Compare(pe, pa) {
					round[fnd.dim] = fnd
				}
				if common == nil {
					common = round
				} else {
					for k := range common {
						if _, ok := round[k]; !ok {
							delete(common, k)
						}
					}
				}
			}
			if !allDenied {
				continue // at least one probe was allowed: an authz question, not existence
			}
			checked++
			for dim, fnd := range common {
				a := agg{op: o.opID, dims: dim, class: ex1Classify(dim),
					detail: fmt.Sprintf("princ=%d exist=%q absent=%q", princ, fnd.exist, fnd.absent)}
				switch a.class {
				case "ENUMERATION":
					enumeration = append(enumeration, a)
				case "ENUMERATION-COST":
					cost = append(cost, a)
				default:
					artifact = append(artifact, a)
				}
			}
		}
	}

	t.Logf("EX1 EXISTENCE-COST CENSUS: %d metamorphic pairs checked (both-denied, replayed 3x)", checked)
	t.Logf("  ENUMERATION (client-observable) differences: %d", len(enumeration))
	t.Logf("  ENUMERATION-COST (DB round-trip) differences: %d", len(cost))
	t.Logf("  ARTIFACT (rows-scanned / server-side) differences: %d", len(artifact))
	for _, a := range cost {
		t.Logf("    COST: op=%s dim=%s %s", a.op, a.dims, a.detail)
	}
	for _, a := range artifact {
		t.Logf("    ARTIFACT: op=%s dim=%s %s", a.op, a.dims, a.detail)
	}
	for _, a := range enumeration {
		t.Logf("    ENUMERATION: op=%s dim=%s %s", a.op, a.dims, a.detail)
	}
	if checked == 0 {
		t.Fatal("census vacuous: no both-denied single-id GET/DELETE pairs were exercised")
	}
	if len(enumeration) != 0 {
		t.Fatalf("EX1: %d client-observable existence-oracle difference(s) found (see log)", len(enumeration))
	}
}

// ---------------------------------------------------------------------------
// Account-existence oracle on POST /auth/login
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Fuzz: id encodings/forms must not break existence-indistinguishability
// ---------------------------------------------------------------------------

// ex1EncodeID renders the integer id n in one of several on-the-wire forms a tolerant path
// parser might accept — the attacker controls the bytes, so a form that is accepted for an
// EXISTING id but rejected (or routed differently) for an ABSENT id of the same form would be an
// existence oracle. Both sides of a metamorphic pair always use the SAME form index.
func ex1EncodeID(n uint64, form byte) string {
	dec := strconv.FormatUint(n, 10)
	switch form % 8 {
	case 0:
		return dec // canonical decimal
	case 1:
		return "0000000" + dec // leading zeros
	case 2:
		return "+" + dec // explicit plus sign
	case 3:
		// URL-encoded decimal digits (%3N per digit).
		var b strings.Builder
		for _, c := range []byte(dec) {
			fmt.Fprintf(&b, "%%3%c", c)
		}
		return b.String()
	case 4:
		// Fullwidth Unicode digits (U+FF10..U+FF19); NFKC folds them to ASCII.
		var b strings.Builder
		for _, c := range dec {
			b.WriteRune('０' + (c - '0'))
		}
		return b.String()
	case 5:
		return " " + dec + " " // surrounding whitespace
	case 6:
		return "0x" + strconv.FormatUint(n, 16) // hex form
	default:
		return dec + "#frag" // trailing fragment-like junk
	}
}

// ex1BuildEncodedIDRequest substitutes an arbitrary raw id string into the single numeric path
// param of o WITHOUT url-escaping it (the fuzzer controls the exact on-the-wire bytes); string
// path params get the same fixed samples osBuildIDRequest uses.
func (w *osWorld) ex1BuildEncodedIDRequest(o *osOp, princ int, idRaw string) (*http.Request, bool) {
	path := o.tmpl
	numeric := 0
	for _, pp := range o.pathParams {
		var val string
		if osStringPathParam(pp.name) {
			if pp.name == "ref" {
				val = "osproja/prod/oscanary"
			} else {
				val = "osfx"
			}
			path = strings.ReplaceAll(path, "{"+pp.name+"}", url.PathEscape(val))
			continue
		}
		numeric++
		path = strings.ReplaceAll(path, "{"+pp.name+"}", idRaw)
	}
	if numeric != 1 || strings.Contains(path, "{") {
		return nil, false
	}
	// Some fuzzed encodings (embedded space, '#') cannot form a valid HTTP request target;
	// httptest.NewRequest panics on those. A real client could not send them literally in the
	// path either, so recover and skip — a malformed target is not a product existence oracle.
	req, ok := ex1NewRequestSafe(o.method, path)
	if !ok {
		return nil, false
	}
	if tok := w.tokens[princ]; tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return req, true
}

func ex1NewRequestSafe(method, path string) (req *http.Request, ok bool) {
	defer func() {
		if recover() != nil {
			req, ok = nil, false
		}
	}()
	return httptest.NewRequest(method, path, nil), true
}

// ex1SingleIDGetDeleteOps returns the enumerated single-numeric-id GET/DELETE ops whose preceding
// collection is seeded (the population oracle 7 / the census operate over).
func ex1SingleIDGetDeleteOps(w *osWorld) []*osOp {
	var out []*osOp
	for i := range osOps {
		o := &osOps[i]
		if !o.requiresAuth || (o.method != http.MethodGet && o.method != http.MethodDelete) {
			continue
		}
		var idParam *osPathParam
		numeric := 0
		for j := range o.pathParams {
			if !osStringPathParam(o.pathParams[j].name) {
				numeric++
				idParam = &o.pathParams[j]
			}
		}
		if numeric != 1 || idParam == nil {
			continue
		}
		if len(w.seedPools[idParam.preceding]) == 0 {
			continue
		}
		out = append(out, o)
	}
	return out
}

// FuzzEX1ExistenceCost fuzzes the id ENCODING, the op and the zero-authority principal, and
// re-asserts the metamorphic existence-indistinguishability (client-observable dimensions) for
// an existing-forbidden id vs a same-encoding absent id. The DB-cost proxy is observed but not
// gated (it varies by route by design; the census reports it). This widens oracle 7 along the
// encoding axis an enumeration attacker actually controls.
func FuzzEX1ExistenceCost(f *testing.F) {
	// The router logs every request via the std logger; over a long fuzz that is pure noise.
	log.SetOutput(io.Discard)
	f.Cleanup(func() { log.SetOutput(os.Stderr) })
	osLoadSpec(f)
	w := osBuildWorld(f)
	meter := resguard.NewDBMeter()
	if err := meter.Install(w.db); err != nil {
		f.Fatalf("install DBMeter: %v", err)
	}
	candidates := ex1SingleIDGetDeleteOps(w)
	if len(candidates) == 0 {
		f.Skip("no single-id GET/DELETE ops seeded")
	}
	princ := []int{osPrincNoRole, osPrincExpired}

	f.Add(byte(0), byte(0), byte(0)) // canonical decimal, first op, no-role
	f.Add(byte(3), byte(1), byte(1)) // url-encoded, second op, expired
	f.Add(byte(4), byte(5), byte(0)) // fullwidth unicode
	f.Add(byte(1), byte(9), byte(1)) // leading zeros

	f.Fuzz(func(t *testing.T, opSel, form, princSel byte) {
		o := candidates[int(opSel)%len(candidates)]
		p := princ[int(princSel)%len(princ)]
		var idParam *osPathParam
		for j := range o.pathParams {
			if !osStringPathParam(o.pathParams[j].name) {
				idParam = &o.pathParams[j]
			}
		}
		pool := w.seedPools[idParam.preceding]
		existRaw := ex1EncodeID(uint64(pool[0]), form)
		absentRaw := ex1EncodeID(2000000001, form)

		buildE := func() *http.Request { r, _ := w.ex1BuildEncodedIDRequest(o, p, existRaw); return r }
		buildA := func() *http.Request { r, _ := w.ex1BuildEncodedIDRequest(o, p, absentRaw); return r }
		re, okE := w.ex1BuildEncodedIDRequest(o, p, existRaw)
		ra, okA := w.ex1BuildEncodedIDRequest(o, p, absentRaw)
		if !okE || re == nil || !okA || ra == nil {
			return // encoding cannot form a valid request target for this op — skip
		}
		pe := ex1RunProbe(w, meter, buildE)
		pa := ex1RunProbe(w, meter, buildA)
		if osIs2xx(pe.code) || osIs2xx(pa.code) {
			return // at least one allowed: an authz question, not existence
		}
		for _, fnd := range ex1Compare(pe, pa) {
			if ex1Classify(fnd.dim) == "ENUMERATION" {
				t.Errorf("EX1 ENUMERATION via id-encoding form=%d op=%s princ=%d dim=%s: exist(%q)=%q absent(%q)=%q",
					form%8, o.opID, p, fnd.dim, existRaw, fnd.exist, absentRaw, fnd.absent)
			}
		}
	})
}

func ex1LoginReq(username, password, remoteAddr string) *http.Request {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	// The login route is in the PUBLIC auth group mounted at root (router.go:189-190),
	// NOT under /api/v1 — using /api/v1/auth/login falls through to the authenticated
	// group and returns 401 "missing authorization header", a vacuous pair.
	r := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = remoteAddr // isolate the per-IP login-attempt budget (INV-HTTP-19)
	return r
}

// TestEX1AccountExistenceOracle compares a login attempt against a KNOWN username (osadmin) with
// a wrong password vs an UNKNOWN username with the same wrong password. The client-observable
// response (status, error text, body length bucket, info headers) MUST be identical — otherwise
// the endpoint is an account-enumeration oracle. The DB-cost proxy is reported separately: the
// known-user path runs recordFailedLogin (a WithTransaction write) that the unknown-user path
// skips, which the dummy-bcrypt equalizer does NOT cover — recorded as ENUMERATION-COST, with its
// (usually bcrypt-masked) severity assessed in the report.
func TestEX1AccountExistenceOracle(t *testing.T) {
	osLoadSpec(t)
	w := osBuildWorld(t)
	meter := resguard.NewDBMeter()
	if err := meter.Install(w.db); err != nil {
		t.Fatalf("install DBMeter: %v", err)
	}

	const wrongPass = "definitely-not-the-password-123!"
	// Distinct RemoteAddr per probe so neither consumes the other's per-IP budget, and a fresh
	// address each run so replays do not accumulate into the limiter.
	ipN := 0
	nextIP := func() string { ipN++; return "198.51.100." + strconv.Itoa(ipN) + ":5000" }

	var known, unknown ex1Probe
	for rep := 0; rep < 3; rep++ {
		known = ex1RunProbe(w, meter, func() *http.Request { return ex1LoginReq("osadmin", wrongPass, nextIP()) })
		unknown = ex1RunProbe(w, meter, func() *http.Request { return ex1LoginReq("nosuchuser-"+strconv.Itoa(rep), wrongPass, nextIP()) })

		diffs := ex1Compare(known, unknown)
		var clientObservable []ex1Finding
		for _, d := range diffs {
			if ex1Classify(d.dim) == "ENUMERATION" {
				clientObservable = append(clientObservable, d)
			}
		}
		if len(clientObservable) != 0 {
			t.Fatalf("ACCOUNT-EXISTENCE ORACLE (rep %d): known-user and unknown-user login differ in client-observable dimension(s): %+v\n known=%+v\n unknown=%+v",
				rep, clientObservable, known, unknown)
		}
	}
	t.Logf("EX1 ACCOUNT-EXISTENCE: known-vs-unknown login client-observable response IDENTICAL (status=%d len-bucket=%d errtext=%q) — the gated conclusion",
		known.code, ex1LenBucket(known.bodyLen), known.errText)
	// The DB-cost delta on the login path is INFORMATIONAL ONLY, not a reliable proxy here:
	// the deny-path audit writes (LogAuthFailure / LogAuthNotEvaluated) are async (goSafe,
	// handlers/auth.go:289-293), so a synchronous snapshot taken when ServeHTTP returns may
	// or may not include them. We therefore do not gate on it and do not ascribe a specific
	// cause. Both paths spend the equalizing dummy bcrypt (auth.go:54), so any residual
	// DB-round-trip asymmetry is dominated by the (prod cost-12) hash and not independently
	// observable over the network.
	if known.dbQ != unknown.dbQ || known.dbRows != unknown.dbRows {
		t.Logf("EX1 ACCOUNT-EXISTENCE DB-cost delta (informational, async-audit-confounded, bcrypt-masked): known dbQ=%d dbRows=%d vs unknown dbQ=%d dbRows=%d",
			known.dbQ, known.dbRows, unknown.dbQ, unknown.dbRows)
	}
}
