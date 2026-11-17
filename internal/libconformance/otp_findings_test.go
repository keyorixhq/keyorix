package libconformance

import (
	"crypto/md5"  //nolint:gosec // pins a pquerna/otp MD5 defect, test-only
	"crypto/sha1" //nolint:gosec // RFC 6238 vectors, test-only
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TestRFC6238Vectors validates FuzzTOTPDifferential's reference implementation
// against RFC 6238 Appendix B, so O1 compares pquerna/otp with a reference that is
// itself known correct.
func TestRFC6238Vectors(t *testing.T) {
	keys := map[string][]byte{
		"SHA1":   []byte("12345678901234567890"),
		"SHA256": []byte("12345678901234567890123456789012"),
		"SHA512": []byte("1234567890123456789012345678901234567890123456789012345678901234"),
	}
	hs := map[string]func() hash.Hash{"SHA1": sha1.New, "SHA256": sha256.New, "SHA512": sha512.New}
	for _, v := range []struct {
		unix int64
		alg  string
		code string
	}{
		{59, "SHA1", "94287082"}, {59, "SHA256", "46119246"}, {59, "SHA512", "90693936"},
		{1111111109, "SHA1", "07081804"}, {1111111109, "SHA256", "68084774"}, {1111111109, "SHA512", "25091201"},
		{1111111111, "SHA1", "14050471"}, {1111111111, "SHA256", "67062674"}, {1111111111, "SHA512", "99943326"},
		{1234567890, "SHA1", "89005924"}, {1234567890, "SHA256", "91819424"}, {1234567890, "SHA512", "93441116"},
		{2000000000, "SHA1", "69279037"}, {2000000000, "SHA256", "90698825"}, {2000000000, "SHA512", "38618901"},
		{20000000000, "SHA1", "65353130"}, {20000000000, "SHA256", "77737706"}, {20000000000, "SHA512", "47863826"},
	} {
		if got, _ := rfcTOTP(keys[v.alg], v.unix, 30, 8, hs[v.alg]); got != v.code {
			t.Errorf("rfcTOTP(%s, %d) = %s, RFC 6238 says %s", v.alg, v.unix, got, v.code)
		}
	}
}

// TestOTPFindingIssuerQuery pins finding LF1-OTP-issuer-query in pquerna/otp v1.5.0:
// totp.Generate escapes query values with url.PathEscape, which leaves '&' and '+'
// alone, so the issuer is not carried as data. An issuer "Evil&secret=AAAAAAAA" makes
// the URI's first secret parameter the injected one, and that is the secret
// NewKeyFromURL (and any authenticator reading the first value) uses. This test goes
// red when the library escapes the issuer; then drop otpIssuerBreaksQuery's
// exception together with this test.
//
// What this does NOT verify: keyorix reachability, which is none: internal/core passes
// the constant issuer "Keyorix", and the user-chosen username travels in the URI path,
// which is escaped correctly (O3 checks it for every input).
func TestOTPFindingIssuerQuery(t *testing.T) {
	genuine := []byte("0123456789abcdefghij")
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Evil&secret=AAAAAAAA", AccountName: "alice", Secret: genuine})
	if err != nil {
		t.Fatal(err)
	}
	back, err := otp.NewKeyFromURL(key.URL())
	if err != nil {
		t.Fatal(err)
	}
	if back.Secret() == b32NoPad.EncodeToString(genuine) {
		t.Fatalf("injected secret no longer wins (URI %q): finding fixed, remove the exception", key.URL())
	}
	if back.Secret() != "AAAAAAAA" || back.Issuer() != "Evil" {
		t.Fatalf("URI %q re-parses as issuer %q secret %q", key.URL(), back.Issuer(), back.Secret())
	}
	plus, err := totp.Generate(totp.GenerateOpts{Issuer: "A+B", AccountName: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if iss := plus.Issuer(); iss != "A B" {
		t.Fatalf("issuer \"A+B\" re-parses as %q: finding fixed or changed", iss)
	}
}

// TestOTPFindingMD5TruncationPanic pins finding LF1-OTP-md5-truncation-panic in
// pquerna/otp v1.5.0: hotp.GenerateCodeCustom applies RFC 4226 dynamic truncation to an
// HMAC-MD5 digest, whose 16 bytes are too short for offsets 13-15, and indexes past the
// end, so roughly 3 in 16 time steps panic for an AlgorithmMD5 key. Any program that
// takes the algorithm from an untrusted otpauth:// URI (algorithm=md5) can be crashed
// with it. This test goes red when the library stops panicking.
//
// What this does NOT verify: keyorix reachability, which is none: keyorix pins
// AlgorithmSHA1 on every call (internal/core/mfa.go) and never parses a user-supplied
// otpauth URI.
func TestOTPFindingMD5TruncationPanic(t *testing.T) {
	secret := b32NoPad.EncodeToString([]byte("x"))
	opts := totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmMD5}
	for step := range int64(256) {
		if _, ok := rfcTOTP([]byte("x"), step*30, 30, 6, md5.New); ok {
			continue
		}
		at := time.Unix(step*30, 0)
		if v := otpCodePanics(totp.GenerateCodeCustom, secret, at, opts); v == nil {
			t.Fatalf("GenerateCodeCustom(MD5, step %d) no longer panics: finding fixed, remove the special case", step)
		} else {
			t.Logf("step %d (t=%d): panic %v", step, step*30, v)
		}
		return
	}
	t.Fatal("no MD5 step with offset > 12 in 256 steps (harness)")
}

// TestOTPKeyorixShapeRoundTrips is the reachability half: the exact Generate call
// internal/core makes, with usernames from every class validateUsernameCharset admits
// (space, '.', '_', '@', '+', '-') and a legacy name it would not, round-trips.
func TestOTPKeyorixShapeRoundTrips(t *testing.T) {
	for _, name := range []string{"alice", "john.developer", "user@example.com", "a+b c_d-e", "legacy:name?&#%"} {
		key, err := totp.Generate(totp.GenerateOpts{Issuer: "Keyorix", AccountName: name})
		if err != nil {
			t.Fatal(err)
		}
		back, err := otp.NewKeyFromURL(key.URL())
		if err != nil {
			t.Fatal(err)
		}
		if back.Issuer() != "Keyorix" || back.AccountName() != name || back.Secret() != key.Secret() {
			t.Fatalf("username %q: URI %q re-parses as issuer %q account %q", name, key.URL(), back.Issuer(), back.AccountName())
		}
	}
}
