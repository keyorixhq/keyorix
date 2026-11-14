package otphostile

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// ---- Oracle: otpauth:// URL round-trip stability ----------------------------
//
// NewKeyFromURL(s) then k.URL() then NewKeyFromURL again must be stable in every
// field a verifier reads (secret, algorithm, digits, period, type). A URL that
// parses once but whose re-serialisation parses differently would be a finding.
// This exercises percent-encoding, issuer/account edge cases and unknown params.
func FuzzOTPURLRoundTrip(f *testing.F) {
	// Seeds: canonical URLs from the library's own generator, plus edge shapes.
	if k, err := totp.Generate(totp.GenerateOpts{Issuer: "Keyorix", AccountName: "alice@example.com"}); err == nil {
		f.Add(k.URL())
	}
	f.Add("otpauth://totp/Keyorix:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Keyorix&algorithm=SHA1&digits=6&period=30")
	f.Add("otpauth://hotp/ACME%20Co:john?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&counter=0&digits=8")
	f.Add("otpauth://totp/foo?secret=JBSWY3DPEHPK3PXP&unknown=param&digits=7&algorithm=SHA512")
	f.Add("otpauth://totp/:name?secret=JBSWY3DPEHPK3PXP") // empty issuer label
	f.Fuzz(func(t *testing.T, url string) {
		var k1 *otp.Key
		var err error
		fuzzutil.Guard(t.Fatalf, "otp.NewKeyFromURL", func() {
			k1, err = otp.NewKeyFromURL(url)
		})
		if err != nil || k1 == nil {
			return // not a valid otpauth URL; nothing to round-trip
		}
		ser := k1.URL()
		var k2 *otp.Key
		fuzzutil.Guard(t.Fatalf, "otp.NewKeyFromURL(reparse)", func() {
			k2, err = otp.NewKeyFromURL(ser)
		})
		if err != nil || k2 == nil {
			t.Errorf("round-trip: re-serialised URL failed to parse\n in=%q\n ser=%q\n err=%v", url, ser, err)
			return
		}
		if k1.Secret() != k2.Secret() {
			t.Errorf("round-trip secret drift: %q -> %q (url=%q ser=%q)", k1.Secret(), k2.Secret(), url, ser)
		}
		if k1.Type() != k2.Type() {
			t.Errorf("round-trip type drift: %q -> %q", k1.Type(), k2.Type())
		}
		if k1.Algorithm() != k2.Algorithm() {
			t.Errorf("round-trip algorithm drift: %v -> %v (url=%q)", k1.Algorithm(), k2.Algorithm(), url)
		}
		if k1.Digits() != k2.Digits() {
			t.Errorf("round-trip digits drift: %v -> %v (url=%q)", k1.Digits(), k2.Digits(), url)
		}
		if k1.Period() != k2.Period() {
			t.Errorf("round-trip period drift: %d -> %d (url=%q)", k1.Period(), k2.Period(), url)
		}
	})
}

// ---- Oracle: base32 secret leniency vs a strict decoder ----------------------
//
// pquerna decodes a secret by TrimSpace, pad-to-%8 with '=', ToUpper, then
// base32.StdEncoding.DecodeString. It is therefore a SUPERSET of a strict decoder.
// Classes (EXPECTED-DIFFERENCE.md): surrounding whitespace, missing padding,
// lowercase. The oracle fails if (a) strict accepts but pquerna rejects, or
// (b) pquerna accepts something NOT explained by {trim, pad, upper}.
func FuzzOTPBase32Secret(f *testing.F) {
	f.Add("JBSWY3DPEHPK3PXP")       // valid, unpadded (len 16, %8==0)
	f.Add("jbswy3dpehpk3pxp")       // lowercase
	f.Add("  JBSWY3DPEHPK3PXP  ")   // surrounding whitespace
	f.Add("ME")                     // needs padding
	f.Add("MFRA====")               // padded
	f.Add("JBSWY3DP0189")           // invalid base32 chars 0,1,8,9
	f.Add("MFRGG ZDFMZTWQ2L")       // internal whitespace
	f.Fuzz(func(t *testing.T, secret string) {
		var pErr error
		fuzzutil.Guard(t.Fatalf, "hotp.GenerateCodeCustom(secret)", func() {
			_, pErr = hotp.GenerateCodeCustom(secret, 0, hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		})
		pOK := pErr == nil
		sOK := strictBase32OK(secret)

		if sOK && !pOK {
			t.Errorf("strict base32 accepted but pquerna rejected: %q (%v)", secret, pErr)
			return
		}
		if pOK && !sOK {
			if !base32LeniencyExplained(secret) {
				t.Errorf("NEW base32 leniency: pquerna accepted %q, not explained by trim/pad/upper", secret)
			}
		}
	})
}

// strictBase32OK is a truly strict, CANONICAL RFC 4648 base32 acceptance test. Go's
// stdlib base32 decoder is lenient in two ways a strict reading forbids: it silently
// skips '\r'/'\n' (RFC 4648 §3.3: a strict decoder MUST reject non-alphabet bytes),
// and it tolerates some non-canonical '=' padding placements. A canonical base32
// string has: length a multiple of 8; alphabet chars A-Z/2-7 in the body; padding
// '=' ONLY as a trailing run whose length is a valid base32 pad count (0,1,3,4,6).
// Enforcing this keeps the reference STRICTLY a subset of pquerna's acceptance, so
// the only surviving differences are pquerna's documented leniencies
// (lowercase / surrounding whitespace / missing padding) — see EXPECTED-DIFFERENCE.md.
func strictBase32OK(secret string) bool {
	if len(secret)%8 != 0 {
		return false
	}
	i, pad := len(secret), 0
	for i > 0 && secret[i-1] == '=' {
		i--
		pad++
	}
	for j := 0; j < i; j++ {
		c := secret[j]
		if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) {
			return false
		}
	}
	switch pad {
	case 0, 1, 3, 4, 6:
	default:
		return false
	}
	_, err := base32.StdEncoding.DecodeString(secret)
	return err == nil
}

// base32LeniencyExplained reproduces pquerna's exact pre-decode normalisation
// (TrimSpace, pad-to-%8 with '=', ToUpper). If the normalised form decodes under a
// strict decoder, the acceptance is one of the documented leniencies, not a new one.
func base32LeniencyExplained(secret string) bool {
	s := strings.TrimSpace(secret)
	if n := len(s) % 8; n != 0 {
		s += strings.Repeat("=", 8-n)
	}
	s = strings.ToUpper(s)
	_, err := base32.StdEncoding.DecodeString(s)
	return err == nil
}

// ---- Oracle: HOTP generation robustness + determinism -----------------------
//
// For any secret/counter/digits/algorithm, GenerateCodeCustom must not hang (Guard)
// and must be deterministic; when it succeeds with a standard digit count the output
// length matches. A panic is recorded natively by the fuzzer.
func FuzzHOTPGenerate(f *testing.F) {
	f.Add([]byte("12345678901234567890"), uint64(0), uint8(6), uint8(0))
	f.Add([]byte("12345678901234567890"), ^uint64(0), uint8(8), uint8(2)) // counter overflow edge
	f.Add([]byte{}, uint64(1), uint8(0), uint8(1))                         // empty secret, digits 0
	f.Add([]byte("x"), uint64(5), uint8(20), uint8(0))                     // digits out of range
	f.Fuzz(func(t *testing.T, secret []byte, counter uint64, digitsSel uint8, algSel uint8) {
		s := base32.StdEncoding.EncodeToString(secret)
		digits := otp.Digits(digitsSel)
		alg := []otp.Algorithm{otp.AlgorithmSHA1, otp.AlgorithmSHA256, otp.AlgorithmSHA512}[algSel%3]
		opts := hotp.ValidateOpts{Digits: digits, Algorithm: alg}

		var code string
		var err error
		fuzzutil.Guard(t.Fatalf, "hotp.GenerateCodeCustom", func() {
			code, err = hotp.GenerateCodeCustom(s, counter, opts)
		})
		if err != nil {
			return
		}
		var code2 string
		fuzzutil.Guard(t.Fatalf, "hotp.GenerateCodeCustom(repeat)", func() {
			code2, _ = hotp.GenerateCodeCustom(s, counter, opts)
		})
		if code != code2 {
			t.Errorf("non-deterministic HOTP: %q vs %q (counter=%d digits=%d alg=%d)", code, code2, counter, digitsSel, algSel)
		}
		if digitsSel == 6 || digitsSel == 7 || digitsSel == 8 {
			if len(code) != digits.Length() {
				t.Errorf("digit-length mismatch: digits=%d len(code)=%d code=%q", digitsSel, len(code), code)
			}
		}
	})
}

// ---- Robustness boundary tests (documented, non-fuzz) -----------------------

// Period 0 must not panic (float64 division by zero inside pquerna produces a
// degenerate counter, but no crash). Documents the behaviour Keyorix never hits
// (it hardcodes Period=30), classified EXPECTED/robustness.
func TestPeriodZeroDoesNotPanic(t *testing.T) {
	secret := b32(rfcSHA1Seed)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Period=0 panicked: %v", r)
		}
	}()
	_, _ = totp.GenerateCodeCustom(secret, time.Unix(59, 0).UTC(), totp.ValidateOpts{
		Period: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
}

// Counter overflow (max uint64) must not panic and stays deterministic.
func TestCounterOverflowDoesNotPanic(t *testing.T) {
	secret := b32(rfcSHA1Seed)
	a, errA := hotp.GenerateCodeCustom(secret, ^uint64(0), hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	b, errB := hotp.GenerateCodeCustom(secret, ^uint64(0), hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if errA != nil || errB != nil {
		t.Fatalf("overflow counter errored: %v / %v", errA, errB)
	}
	if a != b {
		t.Fatalf("overflow counter non-deterministic: %q vs %q", a, b)
	}
}

// Digits out of range (0 and a large value) must not panic.
func TestDigitsOutOfRangeDoesNotPanic(t *testing.T) {
	secret := b32(rfcSHA1Seed)
	for _, d := range []otp.Digits{otp.Digits(0), otp.Digits(1), otp.Digits(20)} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Digits=%d panicked: %v", int(d), r)
				}
			}()
			_, _ = hotp.GenerateCodeCustom(secret, 1, hotp.ValidateOpts{Digits: d, Algorithm: otp.AlgorithmSHA1})
		}()
	}
}
