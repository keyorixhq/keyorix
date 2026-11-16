package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 reference implementation, mirrors the verifier under test
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/pquerna/otp"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// LIB-FUZZ-1 item 4: pquerna/otp as keyorix's MFA uses it.
//
// INVENTORY. Two uses of the library, both in internal/core/mfa.go:
//   - totp.Generate (BeginMFAEnrollment): builds the otpauth:// URI that becomes the QR
//     code. Its AccountName is the account's USERNAME. Local usernames are restricted
//     to [a-zA-Z0-9 ._@+-] on create, SSO/SCIM usernames to [a-z0-9]; but an older
//     account (created before the rule) can hold any string, and the URI is built from
//     whatever is stored. The URI is therefore a string builder over a semi-trusted
//     value, which is the one place keyorix output could carry a parameter injection.
//   - totp.GenerateCodeCustom (validateTOTPStep): every verifier (login, step-up,
//     reauth, activation) funnels through it, with the user's typed code (untrusted),
//     the stored base32 secret (trusted, but read from storage), and the core's clock.
//     keyorix does the compare and the +-1 step window itself; the library only
//     generates. otp.NewKeyFromURL / totp.Validate are not called by keyorix.
// Replay protection (MarkTOTPStepUsed) is storage-level and already covered by
// TestVerifyMFALogin_RejectsReplay, TestVerifyMFAStepUp_AntiReplay,
// TestRequireReauth_TOTPCodeNotReplay and the cross-replica fuzzers; it is not
// re-fuzzed here. What IS checked is the value replay protection keys on: the step
// validateTOTPStep returns must be the step that really produced the code.
//
// The oracle is an independent RFC 4226 implementation (HMAC-SHA1 + dynamic
// truncation, written here from the RFC, not from the library), so it also pins the
// library against the RFC at keyorix's exact configuration.
//
// What this does NOT verify: constant-time comparison (a timing property), the FIPS
// refusal path (totpFIPSEnforced is process state), and the 30 s period being the
// value the authenticator app uses (that is the URI oracle's job, below).

type validateStepFn func(secret, code string, now time.Time) (int64, bool)

func realValidateStep(secret, code string, now time.Time) (int64, bool) {
	c := &KeyorixCore{now: func() time.Time { return now }}
	return c.validateTOTPStep(secret, code)
}

// refHOTP is RFC 4226 section 5 with 6 digits.
func refHOTP(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key) // #nosec G401
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) | (uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	return fmt.Sprintf("%06d", v%1_000_000)
}

func b32secret(key []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
}

// libDecode mirrors the secret tolerance the library documents (surrounding space,
// missing padding, lower case) so the oracle accepts exactly the secrets it should.
func libDecode(secret string) ([]byte, bool) {
	secret = strings.TrimSpace(secret)
	if n := len(secret) % 8; n != 0 {
		secret += strings.Repeat("=", 8-n)
	}
	b, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	return b, err == nil
}

// checkTOTPWindow: for a secret and a clock, a code is accepted exactly when it is
// the code of the current step or of one step either side; the returned step is the
// step that code belongs to; and codes from further away are refused.
func checkTOTPWindow(validate validateStepFn, key []byte, nowSec int64) error {
	secret := b32secret(key)
	now := time.Unix(nowSec, 0).UTC()
	s := nowSec / totpPeriod
	window := map[string]bool{}
	for d := int64(-1); d <= 1; d++ {
		window[refHOTP(key, uint64(s+d))] = true
	}
	for j := int64(-4); j <= 4; j++ {
		step := s + j
		if step < 0 {
			continue
		}
		code := refHOTP(key, uint64(step))
		got, ok := validate(secret, code, now)
		want := window[code]
		if ok != want {
			return fmt.Errorf("step offset %+d (code %s, now=%d, keyLen=%d): accepted=%v, want %v", j, code, nowSec, len(key), ok, want)
		}
		if ok {
			if got < s-1 || got > s+1 {
				return fmt.Errorf("accepted code %s but returned step %d is outside the window around %d", code, got, s)
			}
			if refHOTP(key, uint64(got)) != code {
				return fmt.Errorf("returned step %d does not produce code %s: replay protection would mark the wrong step", got, code)
			}
		}
	}
	return nil
}

// checkTOTPCodeShape: whatever text is typed, it is accepted only if it is a
// TOTP-shaped code (six ASCII digits after trimming: the disjointness from recovery
// codes that the MFA verifiers route on) equal to a window code.
func checkTOTPCodeShape(validate validateStepFn, key []byte, nowSec int64, typed string) error {
	secret := b32secret(key)
	now := time.Unix(nowSec, 0).UTC()
	s := nowSec / totpPeriod
	if _, ok := validate(secret, typed, now); !ok {
		return nil
	}
	if !isTOTPShaped(typed) {
		return fmt.Errorf("accepted %q, which is not a six-digit ASCII code", typed)
	}
	trimmed := strings.TrimSpace(typed)
	for d := int64(-1); d <= 1; d++ {
		if s+d >= 0 && refHOTP(key, uint64(s+d)) == trimmed {
			return nil
		}
	}
	return fmt.Errorf("accepted %q which is not a code of steps %d..%d", typed, s-1, s+1)
}

// checkTOTPStoredSecret: a malformed or unusual STORED secret never panics and never
// accepts a code the reference does not derive from the same decoded bytes.
func checkTOTPStoredSecret(validate validateStepFn, rawSecret, typed string, nowSec int64) error {
	now := time.Unix(nowSec, 0).UTC()
	_, ok := validate(rawSecret, typed, now)
	if !ok {
		return nil
	}
	key, decodable := libDecode(rawSecret)
	if !decodable {
		return fmt.Errorf("accepted a code against the undecodable secret %q", rawSecret)
	}
	s := nowSec / totpPeriod
	trimmed := strings.TrimSpace(typed)
	for d := int64(-1); d <= 1; d++ {
		if s+d >= 0 && refHOTP(key, uint64(s+d)) == trimmed {
			return nil
		}
	}
	return fmt.Errorf("accepted %q against secret %q, which the reference does not derive", typed, rawSecret)
}

func FuzzValidateTOTPStep(f *testing.F) {
	k20 := []byte("12345678901234567890") // RFC 4226 / 6238 test key
	f.Add(k20, int64(59), int8(0), "94287082", b32secret(k20))
	f.Add(k20, int64(1111111109), int8(1), " 081804\n", b32secret(k20))
	f.Add(k20, int64(1111111111), int8(-1), "\u0660\u0661\u0662\u0663\u0664\u0665", strings.ToLower(b32secret(k20)))
	f.Add(k20, int64(2000000000), int8(2), "+12345", b32secret(k20)+"==")
	f.Add([]byte{0x00}, int64(0), int8(0), "000000", "")
	f.Add(make([]byte, 64), int64(4102444799), int8(-3), "0000000", "!!!")
	f.Add(k20, int64(30), int8(0), "\u00a0123456\u00a0", "MFRGGZDF")
	f.Fuzz(func(t *testing.T, key []byte, nowSec int64, offset int8, typed, rawSecret string) {
		if len(key) == 0 || len(key) > 128 {
			return
		}
		if nowSec < 0 {
			nowSec = -(nowSec + 1)
		}
		nowSec %= 4102444800 // year 2100
		fuzzutil.Guard(t.Fatalf, "validateTOTPStep", func() {
			if err := checkTOTPWindow(realValidateStep, key, nowSec); err != nil {
				t.Errorf("TOTP WINDOW ORACLE: %v", err)
			}
			// the typed text, tried alone and as the code of a neighbouring step
			cands := []string{typed}
			if st := nowSec/totpPeriod + int64(offset)%4; st >= 0 {
				code := refHOTP(key, uint64(st))
				cands = append(cands, code, " "+code+"\t", typed+code, code+typed)
			}
			for _, cand := range cands {
				if err := checkTOTPCodeShape(realValidateStep, key, nowSec, cand); err != nil {
					t.Errorf("TOTP CODE-SHAPE ORACLE: %v", err)
				}
				if err := checkTOTPStoredSecret(realValidateStep, rawSecret, cand, nowSec); err != nil {
					t.Errorf("TOTP STORED-SECRET ORACLE: %v", err)
				}
			}
		})
	})
}

// ---- otpauth:// URI, driven through the real BeginMFAEnrollment -------------------

// newEnrollmentCore mirrors newMFATestCore (mfa_test.go) for a *testing.F: a real
// SQLite-backed core with an enabled encryptor and user id 1.
func newEnrollmentCore(f *testing.F) (*KeyorixCore, *gorm.DB) {
	f.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		f.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.MFASecret{}, &models.AuditEvent{}); err != nil {
		f.Fatal(err)
	}
	if err := db.Create(&models.User{ID: 1, Username: "alice", UsernameFolded: "alice", Email: "a@b.com", EmailFolded: "a@b.com",
		PasswordHash: "x", AccountState: "active"}).Error; err != nil {
		f.Fatal(err)
	}
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, f.TempDir())
	if err := enc.Initialize("test-passphrase"); err != nil {
		f.Fatal(err)
	}
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now, passwordPolicy: DefaultPasswordPolicy()}
	c.SetAuthEncryptor(enc)
	return c, db
}

// checkEnrollmentURI: whatever the username, the URI keyorix hands out parses back to
// the same account and issuer, carries exactly the five parameters keyorix set (no
// parameter can be injected through the username), the period/digits/algorithm the
// verifier is hard-wired to (a drift here would make every code the app shows wrong),
// and a 20-byte secret that equals the one stored.
func checkEnrollmentURI(username, uri, secret string) error {
	for i := 0; i < len(uri); i++ {
		if uri[i] <= 0x20 || uri[i] >= 0x7f {
			return fmt.Errorf("URI has a raw control/space/non-ASCII byte 0x%02x at %d (not safe as QR payload or in a link): %q", uri[i], i, uri)
		}
	}
	key, err := otp.NewKeyFromURL(uri)
	if err != nil {
		return fmt.Errorf("the URI does not parse back: %w", err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		return err
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		return fmt.Errorf("scheme/host = %q/%q, want otpauth/totp", u.Scheme, u.Host)
	}
	q := u.Query()
	if len(q) != 5 {
		return fmt.Errorf("URI carries %d parameters %v, want exactly secret, issuer, period, algorithm, digits", len(q), q)
	}
	for _, name := range []string{"secret", "issuer", "period", "algorithm", "digits"} {
		if len(q[name]) != 1 {
			return fmt.Errorf("parameter %q occurs %d times in %q", name, len(q[name]), uri)
		}
	}
	if key.Issuer() != mfaIssuer {
		return fmt.Errorf("issuer = %q, want %q", key.Issuer(), mfaIssuer)
	}
	if utf8.ValidString(username) && key.AccountName() != username {
		return fmt.Errorf("account name = %q, want %q", key.AccountName(), username)
	}
	if key.Period() != totpPeriod || key.Digits() != otp.DigitsSix || key.Algorithm() != otp.AlgorithmSHA1 {
		return fmt.Errorf("period/digits/algorithm = %d/%v/%v, the verifier is fixed at %d/6/SHA1", key.Period(), key.Digits(), key.Algorithm(), totpPeriod)
	}
	if key.Secret() != secret {
		return fmt.Errorf("the URI secret %q differs from the returned manual-entry secret %q", key.Secret(), secret)
	}
	if raw, ok := libDecode(secret); !ok || len(raw) != 20 {
		return fmt.Errorf("secret %q does not decode to 20 bytes", secret)
	}
	return nil
}

func FuzzMFAEnrollmentURI(f *testing.F) {
	c, db := newEnrollmentCore(f)
	for _, s := range []string{
		"alice", "alice.smith@example.com", "a b", "a+b", "a_b-c", "x@y@z", "a:b", "Keyorix:alice",
		"a&secret=AAAAAAAA", "a?x=y", "a#frag", "a%20b", "a%", "a/b", "../x", "a\\b", "\u00e9", "\u65e5\u672c",
		"a\tb", "a\nb", "a\x00b", "\x7f", "a b  c", "\u202eadmin", "\xef\xbb\xbfx", strings.Repeat("a", 300),
		"a;b", "a,b", "a\"b", "a'b", "a<b>", "a|b", "a`b", "a$b", "a=b", "a[1]",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, username string) {
		if len(username) > 2048 {
			return
		}
		fuzzutil.Guard(t.Fatalf, "BeginMFAEnrollment", func() {
			if err := db.Model(&models.User{}).Where("id = ?", 1).Update("username", username).Error; err != nil {
				t.Errorf("seed username: %v", err)
				return
			}
			uri, secret, err := c.BeginMFAEnrollment(context.Background(), 1)
			if err != nil {
				// A refusal is a legal answer for a name no rule would let in; but a name
				// the create rule accepts must be enrollable.
				if validateUsernameCharset(username) == nil && username != "" {
					t.Errorf("ENROLLMENT: username %q passes validateUsernameCharset but cannot enrol MFA: %v", username, err)
				}
				return
			}
			if err := checkEnrollmentURI(username, uri, secret); err != nil {
				t.Errorf("OTPAUTH URI ORACLE (username %q): %v", username, err)
			}
		})
	})
}

// ---- red-proof -----------------------------------------------------------------

func TestTOTPOracles_RedGreen(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, now := range []int64{59, 1111111109, 1234567890, 2000000000} {
		if err := checkTOTPWindow(realValidateStep, key, now); err != nil {
			t.Fatalf("real validator, now=%d: %v", now, err)
		}
	}
	// RFC 6238 appendix B, SHA1, truncated to 6 digits: the reference itself is right.
	if got := refHOTP(key, 1); got != "287082" {
		t.Fatalf("reference HOTP(1) = %s, RFC 4226 says 287082", got)
	}

	// Broken validators, each a plausible regression. step() is what the real code
	// does for one offset; the broken ones change the window or the returned step.
	wrap := func(offsets []int64, stepOf func(s, d int64) int64) validateStepFn {
		return func(secret, code string, now time.Time) (int64, bool) {
			raw, _ := libDecode(secret)
			s := now.Unix() / totpPeriod
			for _, d := range offsets {
				if refHOTP(raw, uint64(s+d)) == strings.TrimSpace(code) {
					return stepOf(s, d), true
				}
			}
			return 0, false
		}
	}
	same := func(s, d int64) int64 { return s + d }
	broken := map[string]validateStepFn{
		"window-plus-minus-2": wrap([]int64{0, -1, 1, -2, 2}, same),
		"no-skew":             wrap([]int64{0}, same),
		"future-only-skew":    wrap([]int64{0, 1}, same),
		"returns-current-step": wrap([]int64{0, -1, 1}, func(s, _ int64) int64 {
			return s
		}),
		"accepts-everything": func(string, string, time.Time) (int64, bool) { return 0, true },
		"rejects-everything": func(string, string, time.Time) (int64, bool) { return 0, false },
	}
	for name, bad := range broken {
		red := false
		for _, now := range []int64{59, 1111111109, 2000000000} {
			if checkTOTPWindow(bad, key, now) != nil {
				red = true
			}
		}
		if !red {
			t.Errorf("window oracle stayed GREEN on %q", name)
		}
	}

	// shape oracle: a numeric-value compare accepts "12345" for "012345" (and "+..").
	numeric := func(secret, code string, now time.Time) (int64, bool) {
		raw, _ := libDecode(secret)
		s := now.Unix() / totpPeriod
		for d := int64(-1); d <= 1; d++ {
			want := refHOTP(raw, uint64(s+d))
			if strings.TrimLeft(strings.TrimSpace(code), "0+") == strings.TrimLeft(want, "0") && code != "" {
				return s + d, true
			}
		}
		return 0, false
	}
	found := false
	for now := int64(30); now < 30*2000 && !found; now += 30 {
		s := now / totpPeriod
		if want := refHOTP(key, uint64(s)); want[0] == '0' {
			found = checkTOTPCodeShape(numeric, key, now, want[1:]) != nil
		}
	}
	if !found {
		t.Error("code-shape oracle stayed GREEN on a validator that compares codes numerically")
	}
	if err := checkTOTPCodeShape(realValidateStep, key, 59, "\u0669\u0664\u0662\u0668\u0667\u0660"); err != nil {
		t.Errorf("real validator, non-ASCII digits: %v", err)
	}

	// stored-secret oracle: a validator that decodes leniently accepts what the
	// reference cannot derive.
	lenient := func(secret, code string, now time.Time) (int64, bool) { return 0, code != "" }
	if checkTOTPStoredSecret(lenient, "!!!", "123456", 59) == nil {
		t.Error("stored-secret oracle stayed GREEN on a validator that accepts against an undecodable secret")
	}
	if err := checkTOTPStoredSecret(realValidateStep, "!!!", "123456", 59); err != nil {
		t.Errorf("real validator, undecodable secret: %v", err)
	}
}

func TestEnrollmentURIOracle_RedGreen(t *testing.T) {
	good := "otpauth://totp/Keyorix:alice?algorithm=SHA1&digits=6&issuer=Keyorix&period=30&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	if err := checkEnrollmentURI("alice", good, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"); err != nil {
		// the sample secret is 32 chars = 20 bytes
		t.Fatalf("known-good URI rejected: %v", err)
	}
	cases := map[string]string{
		"injected-parameter": "otpauth://totp/Keyorix:a?algorithm=SHA1&digits=6&issuer=Keyorix&period=30&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&secret=AAAAAAAA",
		"period-60":          "otpauth://totp/Keyorix:alice?algorithm=SHA1&digits=6&issuer=Keyorix&period=60&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
		"digits-8":           "otpauth://totp/Keyorix:alice?algorithm=SHA1&digits=8&issuer=Keyorix&period=30&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
		"sha256":             "otpauth://totp/Keyorix:alice?algorithm=SHA256&digits=6&issuer=Keyorix&period=30&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
		"other-issuer":       "otpauth://totp/Keyorix:alice?algorithm=SHA1&digits=6&issuer=Evil&period=30&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
		"hotp":               "otpauth://hotp/Keyorix:alice?algorithm=SHA1&digits=6&issuer=Keyorix&period=30&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
		"raw-space":          "otpauth://totp/Keyorix:a lice?algorithm=SHA1&digits=6&issuer=Keyorix&period=30&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
		"other-account":      "otpauth://totp/Keyorix:bob?algorithm=SHA1&digits=6&issuer=Keyorix&period=30&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
		"short-secret":       "otpauth://totp/Keyorix:alice?algorithm=SHA1&digits=6&issuer=Keyorix&period=30&secret=JBSWY3DP",
	}
	for name, uri := range cases {
		secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
		if name == "short-secret" {
			secret = "JBSWY3DP"
		}
		if checkEnrollmentURI("alice", uri, secret) == nil {
			t.Errorf("URI oracle stayed GREEN on %q", name)
		}
	}
}
