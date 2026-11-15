package http

// SW1 oracles 6 and 7 for FuzzOpenAPIStateful (base harness: openapi_stateful_fuzz_test.go;
// swarm generator: openapi_swarm_fuzz_test.go):
//
//	6. typed error mapper        (osOracleTypedError)      — every error body is leak-free and
//	                                                          carries the documented typed envelope.
//	7. denial existence-indep.   (osOracleDenialExistence) — a zero-authority actor's denial status
//	                                                          does not reveal whether the target exists.
//
// Each is accompanied by a deterministic, repo-wide census test that enumerates every operation
// (TestOSFErrorMapperCensus / TestOSFDenialExistenceCensus), so the property is proven over the
// whole surface, not only where the fuzzer happens to reach. All TEST code; no production change.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// ---------------------------------------------------------------------------
// Oracle 6: typed error mapper
// ---------------------------------------------------------------------------

// VERIFIES, for every error response (status >= 400):
//
//	(A) LEAK SCAN (always fatal): the body never contains a Go stack frame / panic text, an
//	    internal filesystem path or the repo module path, raw SQL/driver text, or planted
//	    secret material. These are client-safe-error hygiene violations (information
//	    disclosure). Sound: the patterns cannot occur in a correctly client-safe error body.
//	(B) TYPED SHAPE (fatal for a JSON object body): the uniform error envelope
//	    sendError writes — a non-empty string `error` label and an integer `code` — is present.
//	    This is the documented shape (openapi.yaml components.responses.Error;
//	    httpx.SendError) and INV-HTTP-error-responses-uniform.
//	(C) UNDECLARED STATUS (candidate, non-fatal): a non-2xx status the spec does not declare
//	    for the operation is recorded once for the report as a HARDENING candidate. Oracle 1
//	    separately handles undeclared 5xx; oracle 2 undeclared 2xx. Many 4xx are legitimately
//	    undeclared across this API, so this is enumerated, not gated.
//
// Does NOT verify: that the `message` text is itself the documented sentence (only that it is
// not a leak); that `code` equals the HTTP status (recorded as a candidate mismatch, not
// gated, because a handler may legitimately carry an app-level code); error bodies that are
// empty or non-JSON (recorded as a candidate, since INV-HTTP-error-responses-uniform says they
// should not occur but net/http's own pre-handler 400/431 are out of this harness's scope);
// leakage in an encoded/transformed form that the literal substring scan cannot see.
var osTypedErrLeaks = []struct {
	name string
	re   *regexp.Regexp
}{
	{"go-stack-frame", regexp.MustCompile(`goroutine \d+ \[|\.go:\d+`)},
	{"panic-text", regexp.MustCompile(`panic:|runtime error:|runtime\.gopanic`)},
	{"sql-text", regexp.MustCompile(`SQLSTATE|pq: |sql: |syntax error at or near|no such table|no such column|UNIQUE constraint failed|duplicate key value violates|SELECT \*|INSERT INTO `)},
}

// osInternalPathRe matches an absolute filesystem path prefix that should never reach a
// client error body. The repo module path is added below (ClientSafe / ErrorMessageFor exist
// precisely to keep these out of 5xx bodies).
var osInternalPathRe = regexp.MustCompile(`/root/|/home/[a-z]|/Users/[A-Za-z]|/var/lib/|/mnt/data/|github\.com/keyorixhq/keyorix/`)

var (
	osUndeclaredNon2xx sync.Map // "opID|code" -> struct{} (candidate list)
	osErrNoTypedShape  sync.Map // "opID|code" -> struct{} (non-json / empty error body)
	osErrCodeMismatch  sync.Map // "opID|code" -> struct{} (code field != http status)
)

func osOracleTypedError(t *testing.T, o *osOp, princ int, req *http.Request, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code < 400 {
		return
	}
	body := rec.Body.String()

	// (A) leak scan — always fatal.
	for _, lk := range osTypedErrLeaks {
		if lk.re.MatchString(body) {
			osReport(t, "typederr-leak|"+lk.name+"|"+o.opID,
				"TYPED-ERROR LEAK (%s): %s %s (op=%s princ=%d code=%d) error body contains disallowed text\nbody=%s",
				lk.name, req.Method, req.URL.Path, o.opID, princ, rec.Code, osTrunc(body))
			return
		}
	}
	if osInternalPathRe.MatchString(body) || strings.Contains(body, srcpath.RepoRoot()) {
		osReport(t, "typederr-path|"+o.opID,
			"TYPED-ERROR LEAK (internal-path): %s %s (op=%s princ=%d code=%d) error body contains an internal path\nbody=%s",
			req.Method, req.URL.Path, o.opID, princ, rec.Code, osTrunc(body))
		return
	}
	if strings.Contains(body, osCanary) {
		osReport(t, "typederr-secret|"+o.opID,
			"TYPED-ERROR LEAK (secret): %s %s (op=%s princ=%d code=%d) error body echoed secret material\nbody=%s",
			req.Method, req.URL.Path, o.opID, princ, rec.Code, osTrunc(body))
		return
	}

	// (C) undeclared non-2xx status — candidate, recorded once.
	if !osDeclaresStatus(o, rec.Code) {
		osUndeclaredNon2xx.LoadOrStore(o.opID+"|"+strconv.Itoa(rec.Code), struct{}{})
	}

	// (B) typed shape — only when there is a JSON object body.
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "json") || strings.TrimSpace(body) == "" {
		osErrNoTypedShape.LoadOrStore(o.opID+"|"+strconv.Itoa(rec.Code), struct{}{})
		return
	}
	var obj map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &obj); err != nil {
		// A JSON array or scalar error body is not the documented envelope.
		osErrNoTypedShape.LoadOrStore(o.opID+"|"+strconv.Itoa(rec.Code), struct{}{})
		return
	}
	errLabel, hasErr := obj["error"].(string)
	if !hasErr || strings.TrimSpace(errLabel) == "" {
		osReport(t, "typederr-noerrlabel|"+o.opID,
			"TYPED-ERROR SHAPE: %s %s (op=%s code=%d) JSON error body has no non-empty string `error` label (documented envelope: {success,error,message,code})\nbody=%s",
			req.Method, req.URL.Path, o.opID, rec.Code, osTrunc(body))
		return
	}
	codeVal, hasCode := obj["code"]
	if !hasCode {
		osReport(t, "typederr-nocode|"+o.opID,
			"TYPED-ERROR SHAPE: %s %s (op=%s code=%d) JSON error body has no `code` field (documented envelope: {success,error,message,code})\nbody=%s",
			req.Method, req.URL.Path, o.opID, rec.Code, osTrunc(body))
		return
	}
	// code mismatch is recorded, not gated (a handler may legitimately carry an app code).
	if f, ok := codeVal.(float64); ok && int(f) != rec.Code {
		osErrCodeMismatch.LoadOrStore(o.opID+"|"+strconv.Itoa(rec.Code), struct{}{})
	}
}

// ---------------------------------------------------------------------------
// Oracle 7: authorization-denial existence independence (no existence oracle)
// ---------------------------------------------------------------------------

// VERIFIES (soundly): for an actor with NO authority over the target (osPrincNoRole: a logged-
// in user with zero grants; osPrincExpired: a user whose only grant has expired), a denied
// GET-by-id or DELETE-by-id returns the SAME status whether the target id exists or not. A
// 403-for-exists / 404-for-absent split is an existence oracle (information disclosure): it
// lets an unauthorized caller probe which ids exist. Keyorix documents the opposite property
// (components.responses.SecretReadRefused: "any other caller gets the same 403/404 as for a
// secret it cannot see") and INV-HTTP-zero-grant-reads-nothing / INV-HTTP-scim-failure-never-
// not-found are the enforced instances; this oracle fuzzes it across every single-id GET/DELETE.
//
// Non-vacuous: the scoped-secret routes (GET /secrets/{id}, its versions/ACL/audit siblings,
// DELETE /secrets/{id}) have NO coarse group-permission gate — RequireScopedSecretPermission
// IS their gate, and it looks up the secret before authorizing, so a zero-grant actor reaches
// that lookup and the exists-vs-absent comparison is a real test of the lookup-then-authz
// ordering (see the oracle-7 red proof). Group-gated routes (roles, users, …) are denied
// uniformly by the coarse gate, which this oracle also (correctly) accepts as equal.
//
// Sound because: the oracle issues its OWN two probes (existing id vs a guaranteed-absent id)
// under the SAME unauthorized actor and only fires when BOTH are denials (non-2xx). If either
// probe is a 2xx the actor was actually authorized for that id and the existence comparison
// does not apply (that is oracle 3's / authz's concern, not this one), so it is skipped.
//
// Does NOT verify: existence independence for AUTHORIZED actors (for them 200-vs-404 is
// correct and intended); the fine-grained case of an actor who passes a coarse gate but is
// denied a specific object in ANOTHER tenant (the viewer→project-B case; covered by the
// SecretReadRefused contract tests, not re-driven here because it needs per-op target
// knowledge the schema does not express); operations with zero or multiple numeric id path
// params; POST/PUT/PATCH (a body-shape 400 would precede the id lookup and mask the
// comparison); which of the two equal statuses is the "right" one (only that they are equal);
// timing/length side channels (status code only).
func osOracleDenialExistence(t *testing.T, w *osWorld, o *osOp, princ int, _ *http.Request, _ *httptest.ResponseRecorder) {
	t.Helper()
	if princ != osPrincNoRole && princ != osPrincExpired {
		return
	}
	if !o.requiresAuth || (o.method != http.MethodGet && o.method != http.MethodDelete) {
		return
	}
	// Exactly one numeric id path param, whose preceding collection is seeded.
	var idParam *osPathParam
	numeric := 0
	for i := range o.pathParams {
		if !osStringPathParam(o.pathParams[i].name) {
			numeric++
			idParam = &o.pathParams[i]
		}
	}
	if numeric != 1 || idParam == nil {
		return
	}
	pool := w.seedPools[idParam.preceding]
	if len(pool) == 0 {
		return
	}
	existID := strconv.FormatUint(uint64(pool[0]), 10)

	reqE, ok := w.osBuildIDRequest(o, princ, existID)
	if !ok {
		return
	}
	recE := osExec(w, reqE)
	reqA, _ := w.osBuildIDRequest(o, princ, "2000000001") // guaranteed-absent id
	recA := osExec(w, reqA)

	if osIs2xx(recE.Code) || osIs2xx(recA.Code) {
		return // at least one was allowed: an authz question, not an existence one
	}
	if recE.Code == recA.Code {
		return
	}
	key := "exist|" + o.opID
	if osStrict {
		osReport(t, key,
			"EXISTENCE ORACLE: zero-authority principal %d got %d for an EXISTING id but %d for an ABSENT id on %s %s (op=%s) — denial status reveals resource existence",
			princ, recE.Code, recA.Code, o.method, o.tmpl, o.opID)
		return
	}
	if _, seen := osExistenceSeen.LoadOrStore(key, struct{}{}); !seen {
		t.Logf("EXISTENCE ORACLE CANDIDATE: zero-authority principal %d got %d (exists) vs %d (absent) on %s %s (op=%s)",
			princ, recE.Code, recA.Code, o.method, o.tmpl, o.opID)
	}
}

var osExistenceSeen sync.Map

// osBuildIDRequest builds a bodyless request for an operation with exactly one numeric id path
// param set to idStr; other (string) path params get a fixed sample. Returns false if the op
// does not have exactly one numeric id path param.
func (w *osWorld) osBuildIDRequest(o *osOp, princ int, idStr string) (*http.Request, bool) {
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
		} else {
			numeric++
			val = idStr
		}
		path = strings.ReplaceAll(path, "{"+pp.name+"}", url.PathEscape(val))
	}
	if numeric != 1 {
		return nil, false
	}
	req := httptest.NewRequest(o.method, path, nil)
	if tok := w.tokens[princ]; tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return req, true
}

// ---------------------------------------------------------------------------
// Deterministic repo-wide census tests (proving tests for oracles 6 and 7)
// ---------------------------------------------------------------------------

// osErrorProbes builds a handful of error-inducing requests for one operation under the
// global admin and a zero-grant user: a bogus path id (not-found), a malformed path id, and
// an empty/garbage JSON body for a write. Deterministic — no fuzzing — so the census is a
// repo-wide enumeration, not a sample.
func (w *osWorld) osErrorProbes(o *osOp) []*http.Request {
	var reqs []*http.Request
	mk := func(method, path string, princ int, body string) {
		var r *http.Request
		if body != "" {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		if tok := w.tokens[princ]; tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		reqs = append(reqs, r)
	}
	subst := func(idVal string) (string, bool) {
		path := o.tmpl
		for _, pp := range o.pathParams {
			var v string
			if osStringPathParam(pp.name) {
				if pp.name == "ref" {
					v = "osproja/prod/nope"
				} else {
					v = "osfx"
				}
			} else {
				v = idVal
			}
			path = strings.ReplaceAll(path, "{"+pp.name+"}", url.PathEscape(v))
		}
		return path, !strings.Contains(path, "{")
	}
	// zero-grant user on the templated path (gets 401/403), and admin on a not-found id.
	if p, ok := subst("2000000001"); ok {
		mk(o.method, p, osPrincNoRole, "")
		mk(o.method, p, osPrincGlobalAdmin, "")
	}
	if p, ok := subst("notanumber"); ok {
		mk(o.method, p, osPrincGlobalAdmin, "")
	}
	// admin with an empty and a garbage body for writes (validation 400).
	if o.method == http.MethodPost || o.method == http.MethodPut || o.method == http.MethodPatch {
		if p, ok := subst("2000000001"); ok {
			mk(o.method, p, osPrincGlobalAdmin, "{}")
			mk(o.method, p, osPrincGlobalAdmin, "{not json")
		}
	}
	return reqs
}

// TestOSFErrorMapperCensus deterministically drives error-inducing requests across EVERY
// enumerated operation and asserts the typed-error-mapper invariants oracle 6 enforces:
// no error body leaks a stack frame / internal path / SQL text / secret, and every JSON
// error body carries the documented typed envelope (`error` label + `code`). It also reports
// (non-fatal) the undeclared-status / non-JSON-body / code-mismatch candidate counts. This is
// the committed, repo-wide proof that oracle 6 holds on real handlers.
func TestOSFErrorMapperCensus(t *testing.T) {
	osLoadSpec(t)
	w := osBuildWorld(t)

	leaks := 0
	noErrLabel, noCode := 0, 0
	nonJSON := map[string]struct{}{}
	undeclared := map[string]struct{}{}
	codeMismatch := map[string]struct{}{}
	var leakExamples, shapeExamples []string
	total := 0

	for i := range osOps {
		o := &osOps[i]
		if _, skip := osConformanceExceptions[o.opID]; skip {
			continue
		}
		for _, req := range w.osErrorProbes(o) {
			rec := osExec(w, req)
			if rec.Code < 400 {
				continue
			}
			total++
			body := rec.Body.String()
			leaked := false
			for _, lk := range osTypedErrLeaks {
				if lk.re.MatchString(body) {
					leaked = true
					if len(leakExamples) < 10 {
						leakExamples = append(leakExamples, o.opID+" ["+strconv.Itoa(rec.Code)+"] "+lk.name+": "+osTrunc(body))
					}
				}
			}
			if osInternalPathRe.MatchString(body) || strings.Contains(body, srcpath.RepoRoot()) || strings.Contains(body, osCanary) {
				leaked = true
				if len(leakExamples) < 10 {
					leakExamples = append(leakExamples, o.opID+" ["+strconv.Itoa(rec.Code)+"] path/secret: "+osTrunc(body))
				}
			}
			if leaked {
				leaks++
			}
			if !osDeclaresStatus(o, rec.Code) {
				undeclared[o.opID+"|"+strconv.Itoa(rec.Code)] = struct{}{}
			}
			ct := rec.Header().Get("Content-Type")
			if !strings.Contains(ct, "json") || strings.TrimSpace(body) == "" {
				nonJSON[o.opID+"|"+strconv.Itoa(rec.Code)] = struct{}{}
				continue
			}
			var obj map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &obj); err != nil {
				nonJSON[o.opID+"|"+strconv.Itoa(rec.Code)] = struct{}{}
				continue
			}
			if lbl, ok := obj["error"].(string); !ok || strings.TrimSpace(lbl) == "" {
				noErrLabel++
				if len(shapeExamples) < 10 {
					shapeExamples = append(shapeExamples, o.opID+" ["+strconv.Itoa(rec.Code)+"] no-error-label: "+osTrunc(body))
				}
			}
			cv, ok := obj["code"]
			if !ok {
				noCode++
				if len(shapeExamples) < 10 {
					shapeExamples = append(shapeExamples, o.opID+" ["+strconv.Itoa(rec.Code)+"] no-code: "+osTrunc(body))
				}
			} else if f, isF := cv.(float64); isF && int(f) != rec.Code {
				codeMismatch[o.opID+"|"+strconv.Itoa(rec.Code)] = struct{}{}
			}
		}
	}

	t.Logf("ERROR-MAPPER CENSUS over %d operations, %d error responses probed:", len(osOps), total)
	t.Logf("  leaks (stack/path/sql/secret): %d", leaks)
	t.Logf("  JSON error bodies missing `error` label: %d; missing `code`: %d", noErrLabel, noCode)
	t.Logf("  distinct non-JSON/empty error (op,status): %d", len(nonJSON))
	t.Logf("  distinct undeclared non-2xx (op,status): %d", len(undeclared))
	t.Logf("  distinct code!=status (op,status): %d", len(codeMismatch))
	for _, e := range leakExamples {
		t.Logf("    LEAK: %s", e)
	}
	for _, e := range shapeExamples {
		t.Logf("    SHAPE: %s", e)
	}

	// Oracle 6's sound, fatal invariants (the ones the fuzzer gates on):
	if leaks != 0 {
		t.Fatalf("typed-error leak oracle: %d error bodies leaked disallowed text", leaks)
	}
	if noErrLabel != 0 || noCode != 0 {
		t.Fatalf("typed-error shape oracle: %d JSON error bodies missing `error` label, %d missing `code`", noErrLabel, noCode)
	}
}

// TestOSFDenialExistenceCensus deterministically checks oracle 7's invariant across EVERY
// single-id GET/DELETE secured operation: a zero-authority actor (zero-grant user; expired
// grant) must get the SAME denial status for an existing id as for an absent id. Differences
// are an existence oracle. Non-fatal listing first so the real state is visible, then the
// invariant is asserted.
func TestOSFDenialExistenceCensus(t *testing.T) {
	osLoadSpec(t)
	w := osBuildWorld(t)

	type diff struct {
		op            string
		princ         int
		exist, absent int
	}
	var diffs []diff
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
			reqE, ok := w.osBuildIDRequest(o, princ, existID)
			if !ok {
				continue
			}
			recE := osExec(w, reqE)
			reqA, _ := w.osBuildIDRequest(o, princ, "2000000001")
			recA := osExec(w, reqA)
			if osIs2xx(recE.Code) || osIs2xx(recA.Code) {
				continue
			}
			checked++
			if recE.Code != recA.Code {
				diffs = append(diffs, diff{o.opID, princ, recE.Code, recA.Code})
			}
		}
	}
	t.Logf("DENIAL-EXISTENCE CENSUS: %d (op,principal) denial pairs checked, %d differ", checked, len(diffs))
	for _, d := range diffs {
		t.Logf("    DIFFERS: op=%s princ=%d exists=%d absent=%d", d.op, d.princ, d.exist, d.absent)
	}
	if len(diffs) != 0 {
		t.Fatalf("existence oracle: %d (op,principal) pairs return a different denial status for existing vs absent ids", len(diffs))
	}
}
