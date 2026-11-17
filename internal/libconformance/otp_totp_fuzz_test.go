package libconformance

import (
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // RFC 4226 reference for pquerna's AlgorithmMD5, test-only
	"crypto/sha1" //nolint:gosec // RFC 6238 default algorithm, test-only reference
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// FuzzTOTPDifferential pins what keyorix relies on in pquerna/otp. internal/core's MFA
// enrolment calls totp.Generate(Issuer: "Keyorix", AccountName: user.Username) and hands
// key.URL() (the otpauth:// URI) to the user's authenticator; every MFA login and
// step-up then calls totp.GenerateCodeCustom(secret, t, SHA1/6 digits/30 s) and compares
// the code itself. Two programs must agree for MFA to work and stay single-factor-proof:
// keyorix's code computation and the authenticator's reading of the URI.
//
//   - O1 CODE DIFFERENTIAL: GenerateCodeCustom equals an independent RFC 4226/6238
//     implementation (rfcTOTP, checked against the RFC 6238 Appendix B vectors by
//     TestRFC6238Vectors) for every secret, time in [0, 2^53), period, digit count
//     and algorithm, and for the secret in lower case, unpadded and padded form.
//   - O2 VALIDATE AGREES: ValidateCustom (Skew 0) accepts the reference code and
//     rejects a code differing in one digit.
//   - O3 URI ROUND-TRIP: for Generate's output, re-parsing key.URL() gives back the
//     issuer, the account name, the secret, period, digits and algorithm, the URI
//     carries each parameter exactly once, and the re-parsed key yields the same codes.
//     An issuer holding ':' is modelled exactly (LF1-OTP-issuer-colon).
//
// What this does NOT verify: the query fields (issuer, secret, period, digits,
// algorithm) when the issuer holds '&' or '+' (finding LF1-OTP-issuer-query; only the
// account name is checked then; keyorix's issuer is the constant "Keyorix"); how a specific authenticator app parses the label (some
// decode '+' as a space; that is app-side); Steam encoding; HOTP counters; times
// before 1970 or at or above 2^53 s (keyorix's clock never produces them, and
// GenerateCodeCustom divides in float64, exact only below 2^53); secret-size policy;
// the constant-time comparison keyorix does itself.
func FuzzTOTPDifferential(f *testing.F) {
	f.Add([]byte("12345678901234567890"), int64(59), uint16(30), uint8(8), uint8(0), "Keyorix", "alice")
	f.Add([]byte("12345678901234567890123456789012"), int64(1111111109), uint16(30), uint8(8), uint8(1), "Keyorix", "user@example.com")
	f.Add([]byte{0xff, 0, 1}, int64(1<<53-1), uint16(1), uint8(6), uint8(2), "Keyorix", "a+b c")
	f.Add([]byte("x"), int64(1763000000), uint16(60), uint8(9), uint8(3), "Acme:Corp", "bob:ops")
	f.Add([]byte("y"), int64(0), uint16(30), uint8(6), uint8(0), "A&secret=AAAAAAAA", "x")
	f.Add([]byte("z"), int64(30), uint16(30), uint8(6), uint8(0), "Keyorix", "?#%/;&=é")
	f.Fuzz(func(t *testing.T, secret []byte, unix int64, period uint16, digits, alg uint8, issuer, account string) {
		if len(secret) == 0 || len(secret) > 256 || len(issuer) > 512 || len(account) > 512 {
			return
		}
		checkTOTP(t, secret, unix, period, digits, alg, issuer, account, totp.GenerateCodeCustom)
	})
}

type totpCodeFunc func(string, time.Time, totp.ValidateOpts) (string, error)

var otpAlgorithms = [4]struct {
	alg otp.Algorithm
	h   func() hash.Hash
}{
	{otp.AlgorithmSHA1, sha1.New},
	{otp.AlgorithmSHA256, sha256.New},
	{otp.AlgorithmSHA512, sha512.New},
	{otp.AlgorithmMD5, md5.New},
}

// rfcTOTP is RFC 6238 over RFC 4226's dynamic truncation, written from the RFCs. ok is
// false when truncation is undefined: RFC 4226 §5.3 assumes a digest of at least 19
// bytes (offset nibble up to 15, four bytes read), which a 16-byte MD5 digest is not.
func rfcTOTP(key []byte, unix int64, period uint64, digits int, h func() hash.Hash) (code string, ok bool) {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(unix)/period)
	mac := hmac.New(h, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := int(sum[len(sum)-1] & 0x0f)
	if off+4 > len(sum) {
		return "", false
	}
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint64(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, uint64(bin)%mod), true
}

// otpCodePanics reports whether code panics, returning the panic value.
func otpCodePanics(code totpCodeFunc, secret string, at time.Time, opts totp.ValidateOpts) (v any) {
	defer func() { v = recover() }()
	_, _ = code(secret, at, opts)
	return nil
}

var b32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func checkTOTP(t *testing.T, secret []byte, unix int64, period16 uint16, digits8, alg8 uint8, issuer, account string, code totpCodeFunc) {
	t.Helper()
	if unix < 0 || unix >= 1<<53 {
		unix &= 1<<53 - 1
	}
	period := uint(max(period16, 1))
	digits := int(digits8%9) + 1 // 1..9: 10 digits exceed the 31-bit truncated value's range
	a := otpAlgorithms[alg8%4]
	opts := totp.ValidateOpts{Period: period, Digits: otp.Digits(digits), Algorithm: a.alg}
	at := time.Unix(unix, 0)
	want, defined := rfcTOTP(secret, unix, uint64(period), digits, a.h)
	enc := b32NoPad.EncodeToString(secret)
	if !defined {
		// Known finding LF1-OTP-md5-truncation-panic: pquerna/otp reads past the
		// 16-byte MD5 digest and panics (TestOTPFindingMD5TruncationPanic). Nothing
		// else is comparable for this (secret, time).
		_ = otpCodePanics(code, enc, at, opts)
		return
	}

	// O1 for each secret spelling GenerateCodeCustom documents it accepts.
	for _, s := range []string{enc, strings.ToLower(enc), base32.StdEncoding.EncodeToString(secret), " " + enc + "\n"} {
		got, err := code(s, at, opts)
		if err != nil || got != want {
			t.Fatalf("O1 CODE: GenerateCodeCustom(%q, t=%d, period=%d, digits=%d, %v) = %q, %v; RFC 6238 gives %q", s, unix, period, digits, a.alg, got, err, want)
		}
	}

	// O2 ValidateCustom agrees with the reference.
	vopts := opts
	vopts.Skew = 0
	if ok, err := totp.ValidateCustom(want, enc, at, vopts); err != nil || !ok {
		t.Fatalf("O2 VALIDATE: ValidateCustom rejects the RFC code %q (err %v)", want, err)
	}
	wrong := []byte(want)
	wrong[0] = '0' + (wrong[0]-'0'+1)%10
	if ok, _ := totp.ValidateCustom(string(wrong), enc, at, vopts); ok {
		t.Fatalf("O2 VALIDATE: ValidateCustom accepts %q, the RFC code is %q", wrong, want)
	}

	// O3 URI round-trip.
	if issuer == "" || account == "" {
		return // Generate rejects these by contract
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: issuer, AccountName: account, Period: period, Digits: otp.Digits(digits),
		Algorithm: a.alg, Secret: secret,
	})
	if err != nil {
		t.Fatalf("O3 URI: Generate(issuer %q, account %q) failed: %v", issuer, account, err)
	}
	back, err := otp.NewKeyFromURL(key.URL())
	if err != nil {
		t.Fatalf("O3 URI: key.URL() %q does not re-parse: %v", key.URL(), err)
	}
	// The label is "issuer:account" and AccountName splits at the first ':', so an
	// issuer holding ':' moves its tail into the account name (finding
	// LF1-OTP-issuer-colon, modelled exactly).
	wantAccount := account
	if _, tail, ok := strings.Cut(issuer, ":"); ok {
		wantAccount = tail + ":" + account
	}
	if back.AccountName() != wantAccount {
		t.Fatalf("O3 URI: account %q re-parses as %q (want %q) from %q", account, back.AccountName(), wantAccount, key.URL())
	}
	if otpIssuerBreaksQuery(issuer) {
		// Known finding LF1-OTP-issuer-query: the query is not carried as data, so
		// only the path-carried account name above is checked for this issuer.
		return
	}
	u, err := url.Parse(key.URL())
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range u.Query() {
		if len(vs) != 1 {
			t.Fatalf("O3 URI: parameter %q appears %d times in %q", k, len(vs), key.URL())
		}
	}
	switch {
	case back.Issuer() != issuer:
		t.Fatalf("O3 URI: issuer %q re-parses as %q from %q", issuer, back.Issuer(), key.URL())
	case back.Secret() != enc:
		t.Fatalf("O3 URI: secret %q re-parses as %q from %q", enc, back.Secret(), key.URL())
	case back.Period() != uint64(period) || back.Digits() != otp.Digits(digits) || back.Algorithm() != a.alg:
		t.Fatalf("O3 URI: parameters re-parse as period=%d digits=%d alg=%v from %q", back.Period(), back.Digits(), back.Algorithm(), key.URL())
	}
	got, err := code(back.Secret(), at, totp.ValidateOpts{Period: uint(back.Period()), Digits: back.Digits(), Algorithm: back.Algorithm()})
	if err != nil || got != want {
		t.Fatalf("O3 URI: the re-parsed key computes %q (err %v), keyorix computes %q", got, err, want)
	}
}

// otpIssuerBreaksQuery reports whether the issuer contains a byte url.PathEscape leaves
// alone but a query string treats as structure: '&' separates parameters and '+'
// decodes as a space. pquerna/otp's internal.EncodeQuery escapes query values with
// PathEscape, so such an issuer is not carried as data (finding LF1-OTP-issuer-query,
// pinned by TestOTPFindingIssuerQuery): "A&secret=X" makes the re-parsed key's
// secret X, because the sorted query puts issuer before secret and Get returns the
// first value.
func otpIssuerBreaksQuery(issuer string) bool { return strings.ContainsAny(issuer, "&+") }
