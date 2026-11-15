package libconformance

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

// This file pins the RFC 4226 (HOTP) and RFC 6238 (TOTP) known-answer vectors against
// github.com/pquerna/otp — the library Keyorix's MFA uses to validate every
// user-supplied TOTP code (internal/core/mfa.go: BeginMFAEnrollment -> totp.Generate,
// validateTOTPStep -> totp.GenerateCodeCustom with Algorithm=SHA1, Digits=6, Period=30).
// It then fuzzes the one property that layer must hold: a code that does not match any
// code in the accepted time-skew window is rejected. Accepting a mutated (wrong) code
// that is not a window code would mean a wrong one-time password authenticates — a
// bypass. These are lib-contract targets (they link only pquerna/otp, no keyorix code),
// per this package's doc.go.

// b32 is the exact secret encoding pquerna/otp expects (upper-case base32, no padding).
func b32(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// RFC 4226 Appendix D test vectors: secret = ASCII "12345678901234567890", SHA1, 6 digits.
var rfc4226Secret = []byte("12345678901234567890")
var rfc4226Codes = []string{
	"755224", "287082", "359152", "969429", "338314",
	"254676", "287922", "162583", "399871", "520489",
}

func TestHOTP_RFC4226_KnownAnswers(t *testing.T) {
	secret := b32(rfc4226Secret)
	opts := hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	for counter, want := range rfc4226Codes {
		got, err := hotp.GenerateCodeCustom(secret, uint64(counter), opts)
		if err != nil {
			t.Fatalf("counter %d: GenerateCodeCustom error: %v", counter, err)
		}
		if got != want {
			t.Fatalf("HOTP RFC4226 counter %d: got %q want %q (pquerna/otp diverges from RFC 4226)", counter, got, want)
		}
		// And the library must validate its own answer at that counter.
		if ok, _ := hotp.ValidateCustom(got, uint64(counter), secret, opts); !ok {
			t.Fatalf("HOTP RFC4226 counter %d: library rejects its own correct code %q", counter, got)
		}
	}
}

// RFC 6238 Appendix B test vectors. Per the RFC, the SHA1/SHA256/SHA512 cases use secrets
// of 20/32/64 bytes built by repeating "1234567890". 8-digit codes, 30s period.
var rfc6238 = []struct {
	t    int64
	sha1 string
	s256 string
	s512 string
}{
	{59, "94287082", "46119246", "90693936"},
	{1111111109, "07081804", "68084774", "25091201"},
	{1111111111, "14050471", "67062674", "99943326"},
	{1234567890, "89005924", "91819424", "93441116"},
	{2000000000, "69279037", "90698825", "38618901"},
	{20000000000, "65353130", "77737706", "47863826"},
}

func rfc6238Secret(n int) []byte {
	base := []byte("1234567890")
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, base...)
	}
	return out[:n]
}

func TestTOTP_RFC6238_KnownAnswers(t *testing.T) {
	cases := []struct {
		name   string
		alg    otp.Algorithm
		secret []byte
		pick   func(i int) string
	}{
		{"SHA1", otp.AlgorithmSHA1, rfc6238Secret(20), func(i int) string { return rfc6238[i].sha1 }},
		{"SHA256", otp.AlgorithmSHA256, rfc6238Secret(32), func(i int) string { return rfc6238[i].s256 }},
		{"SHA512", otp.AlgorithmSHA512, rfc6238Secret(64), func(i int) string { return rfc6238[i].s512 }},
	}
	for _, c := range cases {
		secret := b32(c.secret)
		opts := totp.ValidateOpts{Period: 30, Digits: otp.DigitsEight, Algorithm: c.alg}
		for i := range rfc6238 {
			tm := time.Unix(rfc6238[i].t, 0).UTC()
			got, err := totp.GenerateCodeCustom(secret, tm, opts)
			if err != nil {
				t.Fatalf("%s t=%d: error: %v", c.name, rfc6238[i].t, err)
			}
			if want := c.pick(i); got != want {
				t.Fatalf("TOTP RFC6238 %s t=%d: got %q want %q (pquerna/otp diverges from RFC 6238)", c.name, rfc6238[i].t, got, want)
			}
		}
	}
}

// keyorixTOTPWindow reproduces the acceptance window of internal/core/mfa.go's
// validateTOTPStep: the current time-step and ±1 step (Skew=0 generation, manual ±1
// check), SHA1/6-digit/30s. A code authenticates iff it equals one of these three.
func keyorixTOTPWindow(secret string, t time.Time) (codes [3]string, ok bool) {
	gen := totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	for i, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		c, err := totp.GenerateCodeCustom(secret, t.Add(d), gen)
		if err != nil {
			return codes, false
		}
		codes[i] = c
	}
	return codes, true
}

// FuzzTOTPMutation is the fail-closed mutation oracle for the TOTP verify path.
//
// Property: with the verifier configured exactly as Keyorix configures it (SHA1, 6
// digits, 30s period, ±1 step window), a code is accepted ONLY if it equals one of the
// three window codes. The fuzzer takes a valid code and mutates one digit; the mutated
// code must be rejected UNLESS it collides with a window code (the precise definition of
// a "semantically neutral" mutation for a 6-digit truncated HMAC: a value that happens to
// equal another accepted code). Acceptance of any other mutated code is a VULNERABILITY.
//
// Sound by construction: the only "must-accept" assertion is the baseline (a genuine
// window code must verify); every mutation assertion is "must-reject".
func FuzzTOTPMutation(f *testing.F) {
	f.Add([]byte("12345678901234567890"), int64(59), uint8(0), uint8(1))
	f.Add([]byte("12345678901234567890"), int64(1111111111), uint8(5), uint8(7))
	f.Add(rfc6238Secret(20), int64(2000000000), uint8(2), uint8(3))

	f.Fuzz(func(t *testing.T, secretBytes []byte, unixT int64, digitPos uint8, digitDelta uint8) {
		// A TOTP secret is an HMAC key; reject degenerate keys the library would too.
		if len(secretBytes) < 10 {
			return
		}
		secret := b32(secretBytes)
		// Bound time to a sane range so time.Unix and the ±30s neighbours stay valid.
		if unixT < 0 {
			unixT = -unixT
		}
		unixT %= 4102444800 // year 2100
		tm := time.Unix(unixT, 0).UTC()

		verifyOpts := totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
		window, ok := keyorixTOTPWindow(secret, tm)
		if !ok {
			return
		}
		valid := window[1] // the current-step code

		// Baseline: the genuine current-step code MUST verify in the ±1 window.
		accepted, err := totp.ValidateCustom(valid, secret, tm, verifyOpts)
		if err != nil {
			return // a validation error is not the property under test
		}
		if !accepted {
			t.Fatalf("BASELINE: the correct current-step TOTP code %q was rejected (secretLen=%d, t=%d)", valid, len(secretBytes), unixT)
		}

		// Mutate one digit of the valid code.
		code := []byte(valid)
		pos := int(digitPos) % len(code)
		delta := int(digitDelta)%9 + 1 // 1..9, guarantees a different digit
		code[pos] = byte('0' + (int(code[pos]-'0')+delta)%10)
		mutated := string(code)
		if mutated == valid {
			return // defensive; delta guarantees difference
		}

		// Semantically neutral iff the mutated code collides with a window code.
		for _, wc := range window {
			if mutated == wc {
				return
			}
		}

		// Fail-closed oracle: a non-window code must be rejected.
		bad, err := totp.ValidateCustom(mutated, secret, tm, verifyOpts)
		if err != nil {
			return
		}
		if bad {
			t.Fatalf("TOTP MUTATION ACCEPTED: mutated code %q (from %q) is not a window code %v yet verified (secretLen=%d, t=%d)",
				mutated, valid, window, len(secretBytes), unixT)
		}
	})
}
