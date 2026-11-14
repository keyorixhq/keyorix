// RFC-vector + boundary oracles for github.com/pquerna/otp (v1.5.0), the HOTP/TOTP
// library Keyorix uses for MFA. LIVE callers:
//   - MFA enrolment: internal/core/mfa.go:126 totp.Generate (Period=30, Digits=6, SHA1).
//   - MFA activation / login / step-up: internal/core/mfa.go:825
//     totp.GenerateCodeCustom via validateTOTPStep, with Keyorix's OWN ±1-step window
//     (it loops delta ∈ {0,-1,+1} at Period=30, Skew=0, Digits=6, SHA1) and a
//     constant-time compare; the matched step is returned for single-use/anti-replay.
//
// These tests pin the library's RFC 4226 / RFC 6238 conformance and the boundary
// behaviour Keyorix relies on. The fuzz targets live in otp_fuzz_test.go.
//
// What these oracles do NOT verify:
//   - NOT Keyorix's single-use/anti-replay bookkeeping (that is internal/core's job);
//     here we only pin the library primitive and Keyorix's window arithmetic.
//   - NOT the QR-image (key.Image) path.
//   - NOT constant-time comparison of the passcode (Keyorix does that itself with
//     subtle.ConstantTimeCompare; pquerna's own Validate uses subtle too, asserted
//     only indirectly).
//   - NOT FIPS behaviour (Keyorix refuses TOTP under FIPS before the call).
package otphostile

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

// b32 encodes a raw secret the way pquerna expects (standard base32, upper, padded).
func b32(seed string) string {
	return base32.StdEncoding.EncodeToString([]byte(seed))
}

const (
	rfcSHA1Seed   = "12345678901234567890"
	rfcSHA256Seed = "12345678901234567890123456789012"
	rfcSHA512Seed = "1234567890123456789012345678901234567890123456789012345678901234"
)

// Oracle: RFC 4226 Appendix D HOTP test vectors (6-digit, SHA1).
func TestRFC4226Vectors(t *testing.T) {
	secret := b32(rfcSHA1Seed)
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for c, w := range want {
		got, err := hotp.GenerateCodeCustom(secret, uint64(c), hotp.ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			t.Fatalf("counter %d: %v", c, err)
		}
		if got != w {
			t.Errorf("RFC4226 counter %d: got %s want %s", c, got, w)
		}
		// pquerna's own Validate must agree with the vector.
		if !hotp.Validate(w, uint64(c), secret) {
			t.Errorf("RFC4226 counter %d: hotp.Validate rejected the RFC vector %s", c, w)
		}
	}
}

type totpVec struct {
	t                   int64
	sha1, sha256, sha512 string
}

// RFC 6238 Appendix B TOTP test vectors (8-digit), T0=0, step=30.
var rfc6238 = []totpVec{
	{59, "94287082", "46119246", "90693936"},
	{1111111109, "07081804", "68084774", "25091201"},
	{1111111111, "14050471", "67062674", "99943326"},
	{1234567890, "89005924", "91819424", "93441116"},
	{2000000000, "69279037", "90698825", "38618901"},
	{20000000000, "65353130", "77737706", "47863826"},
}

func TestRFC6238Vectors(t *testing.T) {
	cases := []struct {
		name string
		seed string
		alg  otp.Algorithm
		pick func(totpVec) string
	}{
		{"SHA1", rfcSHA1Seed, otp.AlgorithmSHA1, func(v totpVec) string { return v.sha1 }},
		{"SHA256", rfcSHA256Seed, otp.AlgorithmSHA256, func(v totpVec) string { return v.sha256 }},
		{"SHA512", rfcSHA512Seed, otp.AlgorithmSHA512, func(v totpVec) string { return v.sha512 }},
	}
	for _, c := range cases {
		secret := b32(c.seed)
		for _, v := range rfc6238 {
			got, err := totp.GenerateCodeCustom(secret, time.Unix(v.t, 0).UTC(), totp.ValidateOpts{
				Period:    30,
				Digits:    otp.DigitsEight,
				Algorithm: c.alg,
			})
			if err != nil {
				t.Fatalf("%s t=%d: %v", c.name, v.t, err)
			}
			if w := c.pick(v); got != w {
				t.Errorf("RFC6238 %s t=%d: got %s want %s", c.name, v.t, got, w)
			}
		}
	}
}

// RED PROOF: the vector oracle is not vacuous — computing a SHA1 vector with the
// wrong algorithm (SHA256) or the wrong digit count yields a value that does NOT
// match the RFC vector, so a regression that silently changed the HMAC or digit
// handling would be caught.
func TestRFC6238_OracleFiresOnWrongParams(t *testing.T) {
	secret := b32(rfcSHA1Seed)
	v := rfc6238[0] // t=59, SHA1 => 94287082
	wrongAlg, err := totp.GenerateCodeCustom(secret, time.Unix(v.t, 0).UTC(), totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsEight, Algorithm: otp.AlgorithmSHA256,
	})
	if err != nil {
		t.Fatalf("wrong-alg compute: %v", err)
	}
	if wrongAlg == v.sha1 {
		t.Fatalf("RED PROOF INVALID: SHA256 produced the SHA1 vector %s — oracle cannot tell algorithms apart", v.sha1)
	}
	wrongDigits, err := totp.GenerateCodeCustom(secret, time.Unix(v.t, 0).UTC(), totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("wrong-digits compute: %v", err)
	}
	if wrongDigits == v.sha1 {
		t.Fatalf("RED PROOF INVALID: 6-digit output equalled the 8-digit vector")
	}
}

// Oracle: Keyorix's ±1-step window (mfa.go:822 loops delta ∈ {0,-1,+1}) accepts a
// code from the previous, current, and next 30s step, and REJECTS a code two steps
// away. Modelled here against the library primitive exactly as validateTOTPStep does.
func TestKeyorixWindow_PlusMinusOneStep(t *testing.T) {
	const period = 30
	secret := b32(rfcSHA1Seed)
	now := time.Unix(1700000000, 0).UTC()

	gen := func(ts time.Time) string {
		code, err := totp.GenerateCodeCustom(secret, ts, totp.ValidateOpts{
			Period: period, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			t.Fatalf("gen: %v", err)
		}
		return code
	}
	// Keyorix's acceptance predicate: matches any of {0,-1,+1}.
	accepts := func(code string) bool {
		for _, d := range []int64{0, -1, 1} {
			ts := now.Add(time.Duration(d*period) * time.Second)
			exp := gen(ts)
			if code == exp {
				return true
			}
		}
		return false
	}
	for _, d := range []int64{-1, 0, 1} {
		code := gen(now.Add(time.Duration(d*period) * time.Second))
		if !accepts(code) {
			t.Errorf("window: code at delta %d step not accepted", d)
		}
	}
	for _, d := range []int64{-2, 2, 3} {
		code := gen(now.Add(time.Duration(d*period) * time.Second))
		if accepts(code) {
			t.Errorf("window: code at delta %d step WAS accepted (should be outside ±1)", d)
		}
	}
}

// Oracle: totp.ValidateCustom's Skew window boundary — Skew=1 accepts ±1 period,
// rejects ±2; Skew=0 rejects any neighbour.
func TestSkewWindowBoundary(t *testing.T) {
	const period = 30
	secret := b32(rfcSHA1Seed)
	base := time.Unix(1700000000, 0).UTC()
	optsAt := func(skew uint) totp.ValidateOpts {
		return totp.ValidateOpts{Period: period, Skew: skew, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	}
	codeAt := func(d int64) string {
		c, err := totp.GenerateCodeCustom(secret, base.Add(time.Duration(d*period)*time.Second), optsAt(0))
		if err != nil {
			t.Fatalf("gen: %v", err)
		}
		return c
	}
	// Skew=1: ±1 accepted, ±2 rejected.
	for _, d := range []int64{-1, 0, 1} {
		ok, err := totp.ValidateCustom(codeAt(d), secret, base, optsAt(1))
		if err != nil || !ok {
			t.Errorf("Skew=1 delta %d: accepted=%v err=%v (want accepted)", d, ok, err)
		}
	}
	for _, d := range []int64{-2, 2} {
		ok, _ := totp.ValidateCustom(codeAt(d), secret, base, optsAt(1))
		if ok {
			t.Errorf("Skew=1 delta %d: accepted (want rejected)", d)
		}
	}
	// Skew=0: neighbours rejected.
	for _, d := range []int64{-1, 1} {
		ok, _ := totp.ValidateCustom(codeAt(d), secret, base, optsAt(0))
		if ok {
			t.Errorf("Skew=0 delta %d: accepted (want rejected)", d)
		}
	}
}
