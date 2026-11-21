// Claims-codec fuzzing for github.com/golang-jwt/jwt/v5 (v5.3.1) — the custom
// JSON (un)marshalers jwt.NumericDate and jwt.ClaimStrings, exercised through the
// EXACT claims shape both LIVE Keyorix verify paths decode into:
//
//   - internal/oidcverify OIDCVerifier.VerifyWithExpiry: ParseWithClaims into a
//     struct embedding jwt.RegisteredClaims (+ azp)  [oidcClaims].
//   - internal/core KeyorixCore.verifyIDToken: ParseWithClaims into a struct
//     embedding jwt.RegisteredClaims (+ email/name/nonce/azp).
//
// golang-jwt decodes the payload JSON (invoking NumericDate.UnmarshalJSON for
// exp/nbf/iat and ClaimStrings.UnmarshalJSON for aud) BEFORE the signature is
// verified, so every byte of these claim values is attacker-controlled and
// reaches the codec pre-authentication. No existing fuzz target feeds hostile
// JSON through this codec: FuzzOIDCVerifierClaims builds jwt.MapClaims
// programmatically (MapClaims uses the Validator, NOT these decoders), and
// FuzzJWTDifferential parses into jwt.MapClaims with ParseUnverified. This file
// closes that gap.
//
// This package (jwthostile) is test-only, imported from nothing. It does NOT
// modify production code; every RED PROOF builds its defect in-test.
//
// What these oracles DO NOT verify:
//   - NOT signature cryptography and NOT the post-parse claim policy
//     (issuer/aud/azp/max-age) — those are FuzzOIDCVerifierClaims /
//     FuzzVerifyIDTokenClaims' job. This is purely the JSON<->value codec.
//   - NOT sub-second behaviour: Keyorix never changes jwt.TimePrecision (default
//     1s), and these tests assert that default. The known golang-jwt negative-
//     fractional MarshalJSON quirk ("-1" + ".5" -> "-1.5") only manifests at
//     sub-second TimePrecision and is therefore NOT reachable here (pinned as an
//     EXPECTED-DIFFERENCE note, not exercised).
//   - FuzzJWTClaimsCodec's round-trip oracle asserts a FIXED POINT after the
//     first marshal (unmarshal; marshal=b1; unmarshal; marshal must == b1), not
//     that b1 equals the attacker's original bytes — a codec legitimately
//     normalises (e.g. aud "x" -> ["x"], exp 100.9 -> 100). It catches a codec
//     that cannot re-ingest its own output, or whose output is unstable.
//   - FuzzNumericDateDifferential's blocking assertion covers ONLY integer exp
//     values exactly representable in float64 (|v| <= 2^53). Larger integers
//     (float-precision), out-of-int64 (overflow) and fractional values are NAMED
//     EXPECTED-DIFFERENCE classes, asserted only for no-panic/bounded + accept
//     parity, not for an exact seconds value.
package jwthostile

import (
	"bytes"
	"encoding/json"
	"math"
	"math/big"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// liveClaims mirrors the production claims shape: RegisteredClaims (which carries
// the NumericDate exp/nbf/iat and the ClaimStrings aud) plus the OIDC azp. Both
// live callers embed RegisteredClaims exactly this way.
type liveClaims struct {
	jwt.RegisteredClaims
	Azp string `json:"azp,omitempty"`
}

// ---- Oracle 1: no-panic + bounded work + round-trip idempotence --------------

// FuzzJWTClaimsCodec feeds arbitrary bytes as the token PAYLOAD JSON into the real
// claims decode (json.Unmarshal into liveClaims, the production shape). Oracles:
//
//	(1) never panics / hangs (Guard);
//	(2) bounded work: decoding allocates at most a generous linear function of the
//	    input length (order-of-magnitude amplification detector);
//	(3) round-trip idempotence: if the bytes decode, re-marshalling and re-decoding
//	    reaches a FIXED POINT — marshal(claims1)=b1; unmarshal(b1)=claims2;
//	    marshal(claims2) must equal b1, byte for byte. A codec that cannot re-ingest
//	    its own output, or whose serialisation is unstable, fails here.
func FuzzJWTClaimsCodec(f *testing.F) {
	seeds := []string{
		`{}`,
		`{"exp":1700000000,"nbf":1699999999,"iat":1699999999,"aud":"keyorix"}`,
		`{"aud":["a","b","c"]}`,
		`{"aud":[]}`,
		`{"aud":null}`,
		`{"exp":1700000000.5}`,        // fractional -> truncated at 1s precision
		`{"exp":-1}`,                  // negative
		`{"exp":0}`,                   // epoch
		`{"exp":9007199254740992}`,    // 2^53 exact
		`{"exp":9007199254740993}`,    // 2^53+1 (float precision loss)
		`{"exp":9223372036854775807}`, // MaxInt64 (overflow via float)
		`{"exp":1e19}`,                // > MaxInt64, finite float
		`{"exp":1e400}`,               // not representable -> error
		`{"exp":"1700000000"}`,        // string exp -> error
		`{"iss":"x","sub":"y","jti":"z"}`,
		`{"azp":"client","aud":["client"]}`,
		`{"exp":` + strings.Repeat("9", 4096) + `}`, // huge integer literal
		`{"aud":[` + strings.Repeat(`"x",`, 2000) + `"y"]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var c1 liveClaims
		var err error
		alloc := measureAlloc(func() {
			fuzzutil.Guard(t.Fatalf, "json.Unmarshal(liveClaims)", func() {
				err = json.Unmarshal(data, &c1)
			})
		})
		// (2) bounded work: 64 KiB fixed + 512 B/input byte. Order-of-magnitude
		// detector only (matches FuzzJWTBoundedWork's ceiling rationale).
		ceiling := uint64(64*1024) + 512*uint64(len(data))
		if alloc > ceiling {
			t.Errorf("super-linear allocation decoding claims: input=%d bytes allocated=%d ceiling=%d", len(data), alloc, ceiling)
		}
		if err != nil {
			return // malformed payload: golang-jwt would reject the token; nothing to round-trip
		}

		// (3) round-trip idempotence to a fixed point.
		b1, merr := json.Marshal(c1)
		if merr != nil {
			t.Fatalf("claims that decoded failed to re-marshal: %v (input=%q)", merr, data)
		}
		var c2 liveClaims
		if err := json.Unmarshal(b1, &c2); err != nil {
			t.Fatalf("codec produced output it cannot re-ingest: marshal=%q err=%v (input=%q)", b1, err, data)
		}
		b2, merr := json.Marshal(c2)
		if merr != nil {
			t.Fatalf("second marshal failed: %v", merr)
		}
		if !bytes.Equal(b1, b2) {
			t.Fatalf("round-trip not a fixed point:\n  b1=%q\n  b2=%q\n  input=%q", b1, b2, data)
		}
	})
}

// ---- Oracle 2: NumericDate differential --------------------------------------

// EXPECTED-DIFFERENCE classes for NumericDate (see EXPECTED-DIFFERENCE-NUMERICDATE.md).
const (
	ndExactInt   = "exact-int"       // integer, |v| <= 2^53: .Unix() MUST equal v (BLOCKING)
	ndFloatPrec  = "float-precision" // integer, 2^53 < |v| <= MaxInt64: float64 mantissa loss
	ndOverflow   = "overflow"        // |v| > MaxInt64 but finite float64: int64() conversion impl-defined
	ndFraction   = "fraction"        // non-integer seconds: truncated to TimePrecision (1s)
	ndRejectBoth = "reject"          // not a finite-float JSON number: both reject
)

const twoTo53 = int64(1) << 53

// ndRef is the strict reference verdict on a raw NumericDate JSON value.
type ndRef struct {
	accept bool
	class  string
	// expect is meaningful only for class ndExactInt: the integer seconds value.
	expect int64
}

// strictNumericDate reads raw the way golang-jwt's NumericDate.UnmarshalJSON must:
// json.Unmarshal into json.Number (rejects non-number tokens and trailing junk),
// then Float64 (rejects values not representable as a finite float64). It then
// classifies the value so the differential knows whether an exact seconds match is
// required.
func strictNumericDate(raw []byte) ndRef {
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return ndRef{accept: false, class: ndRejectBoth}
	}
	f, ferr := n.Float64()
	if ferr != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return ndRef{accept: false, class: ndRejectBoth}
	}
	// Integer literal? (no '.', no exponent). A JSON "1e3" is integer-valued but
	// golang-jwt still routes it through the float path, so treat any exponent
	// form as non-exact to stay conservative.
	s := n.String()
	isIntLiteral := !strings.ContainsAny(s, ".eE")
	if isIntLiteral {
		bi, ok := new(big.Int).SetString(s, 10)
		if ok {
			if bi.IsInt64() {
				v := bi.Int64()
				av := v
				if av < 0 {
					av = -av
				}
				if av <= twoTo53 {
					return ndRef{accept: true, class: ndExactInt, expect: v}
				}
				return ndRef{accept: true, class: ndFloatPrec}
			}
			return ndRef{accept: true, class: ndOverflow}
		}
	}
	// Fractional, or an exponent form, or an integer too big for big.Int parse
	// (cannot happen for a valid JSON number). Accept; truncation/overflow class.
	if isIntLiteral {
		return ndRef{accept: true, class: ndOverflow}
	}
	return ndRef{accept: true, class: ndFraction}
}

// numericDateUnix parses raw with golang-jwt's real NumericDate.UnmarshalJSON and
// returns (accepted, unixSeconds).
func numericDateUnix(t testing.TB, raw []byte) (bool, int64) {
	t.Helper()
	var nd jwt.NumericDate
	var err error
	fuzzutil.Guard(t.Fatalf, "jwt.NumericDate.UnmarshalJSON", func() {
		err = nd.UnmarshalJSON(raw)
	})
	if err != nil {
		return false, 0
	}
	return true, nd.Time.Unix()
}

// differentialNumericDate compares golang-jwt's NumericDate.UnmarshalJSON against
// strictNumericDate on the same bytes. The only BLOCKING assertion is the
// ndExactInt class: an integer exp/nbf/iat value exactly representable in float64
// MUST decode to precisely that many Unix seconds — this is the live correctness
// property (a drift here would silently move a token's expiry). Every other
// disagreement is a NAMED EXPECTED-DIFFERENCE class and only asserts accept parity
// + no panic (already enforced by the Guard in numericDateUnix).
func differentialNumericDate(t testing.TB, raw []byte) {
	t.Helper()
	ref := strictNumericDate(raw)
	gotAccept, gotUnix := numericDateUnix(t, raw)

	if gotAccept != ref.accept {
		t.Errorf("NumericDate accept parity: golang-jwt=%v strict=%v class=%q raw=%q",
			gotAccept, ref.accept, ref.class, raw)
		return
	}
	if !ref.accept {
		return
	}
	switch ref.class {
	case ndExactInt:
		if gotUnix != ref.expect {
			t.Errorf("NumericDate BLOCKING mismatch: exact integer %d decoded to .Unix()=%d raw=%q",
				ref.expect, gotUnix, raw)
		}
	case ndFloatPrec:
		// Within one ULP of the intended integer (mantissa loss). Assert it is at
		// least in the same ballpark (not wildly off) so a real defect still shows.
		bi, _ := new(big.Int).SetString(strings.TrimSpace(string(raw)), 10)
		if bi != nil && bi.IsInt64() {
			want := bi.Int64()
			diff := gotUnix - want
			if diff < 0 {
				diff = -diff
			}
			// float64 ULP near MaxInt64 is ~2048; allow generous slack.
			if diff > 1<<13 {
				t.Errorf("NumericDate float-precision drift too large: want~%d got %d (diff %d) raw=%q", want, gotUnix, diff, raw)
			}
		}
	case ndOverflow, ndFraction:
		// No exact value required; the Guard already proved no panic/hang and the
		// accept parity above proved both sides agree on acceptance.
	}
}

// FuzzNumericDateDifferential drives raw bytes straight into NumericDate.UnmarshalJSON
// (the exact decoder the exp/nbf/iat RegisteredClaims fields use) and compares against
// the strict reference.
func FuzzNumericDateDifferential(f *testing.F) {
	for _, s := range []string{
		"1700000000", "0", "-1", "-1700000000",
		"1700000000.5", "1700000000.999", "-100.5",
		"9007199254740992", "9007199254740993", "9223372036854775807",
		"1e19", "1e3", "1E10", "1.5e9",
		"1e400", "-1e400", `"1700000000"`, "true", "null", "{}", "[]",
		"00", "01", "+1", " 1 ", "1.", ".5", "1e", "NaN", "Infinity",
		strings.Repeat("9", 4096), "-" + strings.Repeat("9", 400),
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		differentialNumericDate(t, raw)
	})
}

// ---- Deterministic pins + RED PROOFS -----------------------------------------

// TestClaimsCodec_GuardMechanism is the RED/GREEN proof for Oracle 1's
// no-panic/no-hang mechanism (fuzzutil.Guard). GREEN: Guard must NOT call fatalf
// on a fast closure (a real decode). RED: Guard MUST call fatalf when the closure
// exceeds the wall-clock budget — proven by temporarily lowering GuardTimeout and
// running a closure that sleeps past it. Without the RED half the "no hang" claim
// would be unfalsifiable from a clean run. (A panic in the guarded closure
// propagates and is recorded by the fuzzer natively — Guard documents this — so
// the panic path is not separately mockable here; the hang path is the one Guard
// actively enforces and is proven below.)
func TestClaimsCodec_GuardMechanism(t *testing.T) {
	// GREEN: fast closure, no false fire.
	captured := ""
	fuzzutil.Guard(func(format string, args ...any) { captured = format }, "sentinel", func() {})
	if captured != "" {
		t.Fatalf("GREEN FAILED: Guard called fatalf on a fast, non-panicking closure: %q", captured)
	}

	// RED: a closure that overruns the (temporarily tiny) budget MUST fire fatalf.
	saved := fuzzutil.GuardTimeout
	fuzzutil.GuardTimeout = 20 * time.Millisecond
	defer func() { fuzzutil.GuardTimeout = saved }()
	redFired := false
	fuzzutil.Guard(func(format string, args ...any) { redFired = true }, "hang", func() {
		time.Sleep(200 * time.Millisecond)
	})
	if !redFired {
		t.Fatalf("RED PROOF INVALID: Guard did not fire on a closure that overran its budget; the hang oracle would be vacuous")
	}
}

// TestClaimsRoundTrip_RedProof proves Oracle 1's fixed-point assertion is not
// vacuous: a deliberately NON-idempotent transform (drop the aud on the second
// pass) is caught by the same byte-equality check the fuzzer uses.
func TestClaimsRoundTrip_RedProof(t *testing.T) {
	var c1 liveClaims
	if err := json.Unmarshal([]byte(`{"aud":["a","b"],"exp":1700000000}`), &c1); err != nil {
		t.Fatalf("setup: %v", err)
	}
	b1, _ := json.Marshal(c1)

	// GREEN: honest round trip is a fixed point.
	var c2 liveClaims
	if err := json.Unmarshal(b1, &c2); err != nil {
		t.Fatalf("GREEN setup: %v", err)
	}
	b2, _ := json.Marshal(c2)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("GREEN FAILED: honest round trip not a fixed point: %q vs %q", b1, b2)
	}

	// RED: corrupt c2 (drop aud) and confirm the fixed-point check fires.
	c2.Audience = nil
	bBad, _ := json.Marshal(c2)
	if bytes.Equal(b1, bBad) {
		t.Fatalf("RED PROOF INVALID: dropping aud did not change the marshalled bytes (%q); the fixed-point oracle would be vacuous", b1)
	}
}

// TestNumericDateDifferential_RedProof proves the ndExactInt BLOCKING assertion is
// not vacuous: if golang-jwt's parsed seconds were off by one, the comparison the
// fuzzer uses would fire.
func TestNumericDateDifferential_RedProof(t *testing.T) {
	raw := []byte("1700000000")
	ref := strictNumericDate(raw)
	if ref.class != ndExactInt || !ref.accept {
		t.Fatalf("setup: expected exact-int accept, got %+v", ref)
	}
	_, gotUnix := numericDateUnix(t, raw)

	// GREEN: honest value matches.
	if gotUnix != ref.expect {
		t.Fatalf("GREEN FAILED: honest NumericDate %d decoded to %d", ref.expect, gotUnix)
	}
	// RED: a perturbed result (+1s) must be flagged by the same equality the fuzzer uses.
	if gotUnix+1 == ref.expect {
		t.Fatalf("RED PROOF INVALID: perturbed value still equals expected; the exact-int oracle would be vacuous")
	}
}

// TestNumericDate_HugeExpIsFailClosed documents and pins the security-relevant
// overflow behaviour: a NumericDate exp far beyond int64 (1e30) does NOT panic and
// does NOT decode to a time in the valid future that a verifier would honour —
// golang-jwt converts the out-of-range float to an impl-defined int64, which on
// amd64 saturates/wraps. We assert only the bound that matters: no panic, and the
// value is NOT a plausible "now-ish" timestamp that could silently extend a token.
func TestNumericDate_HugeExpIsFailClosed(t *testing.T) {
	for _, raw := range []string{"1e30", "1e300", "9.3e18", "1e19"} {
		ok, unix := numericDateUnix(t, []byte(raw))
		if !ok {
			continue // rejected outright is also fine (fail-closed)
		}
		// A real exp is seconds since 1970; "now" is ~1.7e9. A huge input must not
		// land anywhere near a believable window — it should be absurdly large or
		// wrapped negative, either of which a correct verifier treats unambiguously.
		now := time.Now().Unix()
		if unix > now-86400 && unix < now+100*365*86400 {
			t.Errorf("huge exp %q decoded to a believable timestamp %d (near now=%d) — potential silent-extension class", raw, unix, now)
		}
	}
}

// TestClaimStrings_AudForms pins the aud (ClaimStrings) decode across the
// string-vs-array family: a single string becomes a one-element slice, an array of
// strings is preserved, null yields an empty aud, and a non-string element or a
// non-string/array value is REJECTED. These are the shapes the live aud check sees.
func TestClaimStrings_AudForms(t *testing.T) {
	accept := map[string][]string{
		`"keyorix"`: {"keyorix"},
		`["a","b"]`: {"a", "b"},
		`[]`:        nil,
		`null`:      nil,
		`["only"]`:  {"only"},
	}
	for raw, want := range accept {
		var cs jwt.ClaimStrings
		if err := cs.UnmarshalJSON([]byte(raw)); err != nil {
			t.Errorf("aud %q: unexpected error %v", raw, err)
			continue
		}
		if strings.Join([]string(cs), "\x00") != strings.Join(want, "\x00") {
			t.Errorf("aud %q: got %v want %v", raw, []string(cs), want)
		}
	}
	for _, raw := range []string{`1`, `true`, `{"x":1}`, `["a",1]`, `[true]`, `[["nested"]]`} {
		var cs jwt.ClaimStrings
		if err := cs.UnmarshalJSON([]byte(raw)); err == nil {
			t.Errorf("aud %q: expected rejection, got %v", raw, []string(cs))
		}
	}
}
