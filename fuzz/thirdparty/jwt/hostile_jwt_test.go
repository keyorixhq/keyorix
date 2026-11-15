// Differential + bounded-work fuzz harness for github.com/golang-jwt/jwt/v5
// (v5.3.1), the JWT parser Keyorix authenticates with on two LIVE paths:
//
//   - OIDC / machine-token federation: internal/oidcverify/oidc.go:186
//     (parser.ParseWithClaims), reached from middleware/auth.go handleAuthRequest.
//   - SSO human login (OIDC id_token): internal/core/sso.go:1422
//     (parser.ParseWithClaims), reached from GET /auth/sso/{provider}/callback.
//
// Both construct the parser with an ASYMMETRIC-ONLY method allowlist
// (RS/ES/PS 256/384/512 — HMAC and "none" are rejected), WithExpirationRequired,
// WithIssuedAt, WithLeeway(60s), WithTimeFunc, and reject any "crit" header.
//
// No second JWT implementation is in the offline module cache (no go-jose, no
// lestrrat/jwx), so oracle (a) — verdict parity — uses a STRICT RFC 7519 / 7515 /
// 8725 reference decoder written in this file (test-only; never shipped). It is
// deliberately STRICTER than golang-jwt: the differential surfaces exactly the
// places golang-jwt (hence Keyorix) is more lenient than a strict RFC 8725
// reading. Every such place is a named EXPECTED-DIFFERENCE class
// (see EXPECTED-DIFFERENCE.md); only a NEW, unclassified disagreement fails.
//
// What these oracles do NOT verify — stated so the green result is not mistaken
// for more than it is:
//   - NOT signature cryptography: the differential runs on ParseUnverified, so it
//     says nothing about RSA/ECDSA/PSS verification correctness. Alg-confusion is
//     covered separately by TestAlgConfusion_* with real keys.
//   - NOT Keyorix's post-parse claim policy (issuer allowlist, aud/azp, max-age,
//     nonce) — those are internal/oidcverify and internal/core tests' job.
//   - NOT JWE, NOT nested JWT, NOT unencoded-payload (RFC 7797): the compact JWS
//     3-segment shape only.
//   - The bounded-work oracle measures process-wide TotalAlloc deltas; it catches
//     order-of-magnitude blow-ups (the CVE-2025-30204 class), NOT small constant
//     over-allocation, and is not a tight per-byte accounting.
package jwthostile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// keyorixMethodAllowlist mirrors the exact WithValidMethods set used by both live
// Keyorix callers (oidc.go:152, sso.go:1391). Asymmetric only.
var keyorixMethodAllowlist = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"PS256": true, "PS384": true, "PS512": true,
}

// ---- EXPECTED-DIFFERENCE reason codes ----------------------------------------
//
// A reason tagged "leniency" is one where a strict RFC reading REJECTS but
// golang-jwt's ParseUnverified ACCEPTS. Its presence alone never fails the
// differential. An "agreement" reason is one both implementations reject on; if
// golang-jwt accepted while strict flagged an agreement reason, that is a NEW
// (interesting) disagreement. Keep this table in lockstep with
// EXPECTED-DIFFERENCE.md.
const (
	// agreement reasons (blocking; both implementations reject)
	rSegments   = "segments"     // not exactly 3 dot-separated parts
	rB64Invalid = "b64-invalid"  // header/payload not decodable base64url at all
	rHeaderJSON = "header-json"  // header not a JSON object
	rClaimsJSON = "payload-json" // payload not a JSON object

	// leniency reasons (non-blocking; strict rejects, golang-jwt accepts)
	rB64NonCanonical = "b64-noncanonical" // non-zero trailing bits (no WithStrictDecoding)
	rHeaderDup       = "header-dup"       // duplicate member name in header JSON
	rClaimsDup       = "payload-dup"      // duplicate member name in payload JSON
	rAlgMissing      = "alg-missing"      // no "alg" string in header
	rAlgNone         = "alg-none"         // alg == "none"
	rAlgNotAllowed   = "alg-not-allowed"  // alg not in Keyorix asymmetric allowlist
	rCrit            = "crit"             // "crit" header present (RFC 7515 §4.1.11)
	rExpType         = "exp-type"         // exp present but not a JSON number
	rNbfType         = "nbf-type"         // nbf present but not a JSON number
	rIatType         = "iat-type"         // iat present but not a JSON number
	rAudType         = "aud-type"         // aud present but not string/array-of-strings
)

// leniencyReasons is the closed set of differences a strict reading is ALLOWED to
// have over golang-jwt's structural parse. A disagreement outside this set fails.
var leniencyReasons = map[string]bool{
	rB64NonCanonical: true, rHeaderDup: true, rClaimsDup: true,
	rAlgMissing: true, rAlgNone: true, rAlgNotAllowed: true, rCrit: true,
	rExpType: true, rNbfType: true, rIatType: true, rAudType: true,
}

// strictResult is the strict reference decoder's verdict on a compact JWS string.
type strictResult struct {
	accept  bool
	reasons []string
}

func (s strictResult) has(r string) bool {
	for _, x := range s.reasons {
		if x == r {
			return true
		}
	}
	return false
}

// strictDecode applies a strict RFC 7515/7519/8725 structural reading. It does NOT
// verify signatures (no keys available for arbitrary fuzz input). It returns the
// full set of reasons it would reject on (not short-circuited past the leniency
// checks), so the classifier can tell leniency-only from agreement-level
// disagreements.
func strictDecode(token string) strictResult {
	res := strictResult{accept: true}
	add := func(r string) { res.accept = false; res.reasons = append(res.reasons, r) }

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		add(rSegments)
		return res // can't go further
	}

	headerBytes, ok := decodeSegment(parts[0], add)
	if !ok {
		return res
	}
	claimsBytes, ok := decodeSegment(parts[1], add)
	if !ok {
		return res
	}

	// Header must be a JSON object; detect duplicate member names.
	header, dup, objOK := decodeJSONObject(headerBytes)
	if !objOK {
		add(rHeaderJSON)
		return res
	}
	if dup {
		add(rHeaderDup)
	}
	// alg (RFC 7515 §4.1.1 + RFC 8725 §3.1). Must be present and a JSON string.
	if raw, ok := header["alg"]; !ok {
		add(rAlgMissing)
	} else {
		var alg string
		if err := json.Unmarshal(raw, &alg); err != nil {
			add(rAlgMissing) // present but not a string header param
		} else {
			switch {
			case alg == "none":
				add(rAlgNone)
			case !keyorixMethodAllowlist[alg]:
				add(rAlgNotAllowed)
			}
		}
	}
	// crit (RFC 7515 §4.1.11): this verifier understands no extensions.
	if _, ok := header["crit"]; ok {
		add(rCrit)
	}

	// Payload must be a JSON object; detect duplicate member names.
	claims, cdup, cOK := decodeJSONObject(claimsBytes)
	if !cOK {
		add(rClaimsJSON)
		return res
	}
	if cdup {
		add(rClaimsDup)
	}
	// golang-jwt's ParseUnverified base64-decodes the signature segment too and
	// rejects a non-base64url signature (observed differentially). RFC 7515: the
	// signature is BASE64URL(JWS Signature). An empty signature (alg=none shape)
	// decodes to empty bytes and is fine here; signature *verification* is out of
	// scope for the structural differential.
	decodeSegment(parts[2], add)
	// Numeric-date claims must be JSON numbers (RFC 7519 §2 NumericDate).
	checkNumeric(claims, "exp", rExpType, add)
	checkNumeric(claims, "nbf", rNbfType, add)
	checkNumeric(claims, "iat", rIatType, add)
	// aud must be a string or an array of strings (RFC 7519 §4.1.3).
	if raw, ok := claims["aud"]; ok {
		var a any
		if err := json.Unmarshal(raw, &a); err != nil || !validAudience(a) {
			add(rAudType)
		}
	}
	return res
}

// decodeSegment decodes one base64url segment the way RFC 7515 requires (no
// padding, canonical). It flags rB64Invalid when the bytes are not base64url at
// all (an agreement reason), and rB64NonCanonical when they decode leniently but
// carry non-zero trailing bits that golang-jwt's default (non-Strict) decoder
// silently accepts and a strict decoder rejects.
func decodeSegment(seg string, add func(string)) ([]byte, bool) {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		add(rB64Invalid)
		return nil, false
	}
	if _, serr := base64.RawURLEncoding.Strict().DecodeString(seg); serr != nil {
		add(rB64NonCanonical)
	}
	return b, true
}

// decodeJSONObject reports whether b is a single JSON object, and whether any
// object anywhere in it has a duplicate member name (RFC 8725 §2.1 / 7519 §4:
// member names must be unique; encoding/json silently keeps the last).
func decodeJSONObject(b []byte) (obj map[string]json.RawMessage, dup bool, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return nil, false, false
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim || d != '{' {
		return nil, false, false
	}
	// Re-scan for duplicate keys at any depth.
	dup = hasDuplicateKeys(b)
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, dup, false
	}
	// Reject trailing content after the top-level value.
	dec2 := json.NewDecoder(bytes.NewReader(b))
	var discard any
	if err := dec2.Decode(&discard); err != nil {
		return nil, dup, false
	}
	if _, err := dec2.Token(); err != io.EOF {
		return nil, dup, false
	}
	return obj, dup, true
}

// hasDuplicateKeys reports whether any JSON object anywhere in b has a repeated
// member name (RFC 8725 §2.1 / 7519 §4). It recursively consumes the token stream
// value-by-value, so key/value alternation is structural, not a flag it has to
// track. Any decode error is treated as "no duplicate" — malformed JSON is caught
// by the object checks in decodeJSONObject, not here.
func hasDuplicateKeys(b []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	dup, _ := scanValueForDup(dec)
	return dup
}

// scanValueForDup consumes exactly one JSON value from dec. It returns whether a
// duplicate key was seen inside it, and any decoder error.
func scanValueForDup(dec *json.Decoder) (bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim {
		return false, nil // scalar
	}
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return false, err
			}
			key, _ := keyTok.(string)
			if seen[key] {
				return true, nil
			}
			seen[key] = true
			if dup, err := scanValueForDup(dec); err != nil || dup {
				return dup, err
			}
		}
		_, err := dec.Token() // consume '}'
		return false, err
	case '[':
		for dec.More() {
			if dup, err := scanValueForDup(dec); err != nil || dup {
				return dup, err
			}
		}
		_, err := dec.Token() // consume ']'
		return false, err
	default:
		return false, nil
	}
}

func checkNumeric(obj map[string]json.RawMessage, key, reason string, add func(string)) {
	raw, ok := obj[key]
	if !ok {
		return
	}
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&n); err != nil {
		add(reason)
	}
}

func validAudience(a any) bool {
	switch v := a.(type) {
	case string:
		return true
	case []any:
		for _, e := range v {
			if _, ok := e.(string); !ok {
				return false
			}
		}
		return true
	default:
		_ = v
		return false
	}
}

// ---- Oracle A: structural differential --------------------------------------

func differentialCheck(t *testing.T, token string) {
	t.Helper()

	// golang-jwt side: structural parse with Keyorix's real parser options.
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	var jwtErr error
	fuzzutil.Guard(t.Fatalf, "jwt.ParseUnverified", func() {
		_, _, jwtErr = parser.ParseUnverified(token, jwt.MapClaims{})
	})
	jwtAccept := jwtErr == nil

	strict := strictDecode(token)

	if jwtAccept == strict.accept {
		return // agree
	}

	if jwtAccept && !strict.accept {
		// golang-jwt lenient. Every strict reason must be a known leniency class.
		for _, r := range strict.reasons {
			if !leniencyReasons[r] {
				t.Errorf("NEW disagreement: golang-jwt ACCEPTED but strict rejected on non-leniency reason %q (reasons=%v)\n token=%q", r, strict.reasons, token)
				return
			}
		}
		return // all reasons are EXPECTED-DIFFERENCE classes
	}

	// strict accepted but golang-jwt rejected: strict found nothing wrong, golang-jwt did.
	t.Errorf("NEW disagreement: strict ACCEPTED but golang-jwt rejected: %v\n token=%q", jwtErr, token)
}

func FuzzJWTDifferential(f *testing.F) {
	seedJWTCorpus(f)
	f.Fuzz(func(t *testing.T, token string) {
		differentialCheck(t, token)
	})
}

// seedJWTCorpus adds structurally interesting seeds: canonical tokens, each known
// EXPECTED-DIFFERENCE class, and pathological shapes.
func seedJWTCorpus(f *testing.F) {
	h := func(obj string) string { return base64.RawURLEncoding.EncodeToString([]byte(obj)) }
	seeds := []string{
		"",
		".",
		"..",
		"a.b.c",
		h(`{"alg":"RS256","typ":"JWT"}`) + "." + h(`{"sub":"x","exp":1,"iat":1}`) + ".sig",
		h(`{"alg":"none"}`) + "." + h(`{"sub":"x"}`) + ".",
		h(`{"alg":"HS256"}`) + "." + h(`{"sub":"x"}`) + ".sig",
		h(`{"alg":"RS256","crit":["b64"]}`) + "." + h(`{"sub":"x"}`) + ".sig",
		h(`{"alg":"RS256","alg":"none"}`) + "." + h(`{"sub":"x"}`) + ".sig", // dup key
		h(`{"alg":"RS256"}`) + "." + h(`{"exp":"not-a-number"}`) + ".sig",   // exp string
		h(`{"alg":"RS256"}`) + "." + h(`{"aud":["a","b"]}`) + ".sig",        // aud array
		h(`{"alg":"RS256"}`) + "." + h(`{"aud":{"x":1}}`) + ".sig",          // aud object -> type err
		h(`{"alg":"ES256"}`) + "." + h(`[1,2,3]`) + ".sig",                  // payload array
		h(`{}`) + "." + h(`{}`) + ".sig",                                    // alg missing
		strings.Repeat(".", 1024),                                           // many segments
	}
	for _, s := range seeds {
		f.Add(s)
	}
}

// ---- Oracle C: bounded work (CVE-2025-30204 class) --------------------------
//
// A short attacker-supplied token must not drive super-linear allocation in the
// parser (the many-periods header-memory CVE, fixed upstream in v5.2.2+; this
// pins the fix and guards against regression in a vendored bump). The oracle:
// allocation is bounded by a generous linear function of input length, and each
// parse returns inside the fuzzutil.Guard wall-clock budget.
func FuzzJWTBoundedWork(f *testing.F) {
	f.Add(strings.Repeat(".", 100000))
	f.Add(strings.Repeat("A", 100000))
	f.Add(strings.Repeat("A.", 50000))
	f.Add("eyJhbGciOiJSUzI1NiJ9." + strings.Repeat("A", 50000) + ".sig")
	f.Fuzz(func(t *testing.T, token string) {
		parser := jwt.NewParser()
		var before, after runtime.MemStats
		old := debug.SetGCPercent(-1)
		defer debug.SetGCPercent(old)
		runtime.ReadMemStats(&before)
		fuzzutil.Guard(t.Fatalf, "jwt.ParseUnverified(bounded)", func() {
			_, _, _ = parser.ParseUnverified(token, jwt.MapClaims{})
		})
		runtime.ReadMemStats(&after)
		alloc := after.TotalAlloc - before.TotalAlloc
		// Generous linear ceiling: 64 KiB fixed + 512 bytes per input byte.
		ceiling := uint64(64*1024) + 512*uint64(len(token))
		if alloc > ceiling {
			t.Errorf("super-linear allocation: input=%d bytes allocated=%d bytes ceiling=%d (possible amplification)", len(token), alloc, ceiling)
		}
	})
}
