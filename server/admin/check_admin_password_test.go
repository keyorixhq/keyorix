package admin

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/rules"
)

// runCheckAdminPasswordCaptured runs `admin check-admin-password` with pw on
// stdin. Every flag is passed explicitly: cobra flag values persist between runs.
func runCheckAdminPasswordCaptured(t *testing.T, pw, username, email string) (string, int) {
	t.Helper()
	t.Chdir(t.TempDir()) // no keyorix.yaml here: the default policy applies
	rootCmd.SetIn(strings.NewReader(pw))
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	code := Execute([]string{"check-admin-password", "--username", username, "--email", email, "--display-name", "Administrator"})
	os.Stdout, os.Stderr = origOut, origErr
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String(), code
}

// #3201: the password from the issue ("Dw5-Admin-Passphrase#2026" contains the
// username "admin") must be refused with the policy's real reason, and the
// password itself must never be echoed.
func TestCheckAdminPassword_ContainingUsernameIsRefusedWithTheReason(t *testing.T) {
	const pw = "Dw5-Admin-Passphrase#2026"
	out, code := runCheckAdminPasswordCaptured(t, pw+"\n", "admin", "admin@keyorix.local")
	if code == 0 {
		t.Fatalf("a password containing the username was accepted:\n%s", out)
	}
	if !strings.Contains(out, "admin password rejected: password must") ||
		!strings.Contains(out, "not contain your username, email, or display name") {
		t.Fatalf("output does not state the real refusal reason:\n%s", out)
	}
	if strings.Contains(out, pw) {
		t.Fatalf("the password was printed:\n%s", out)
	}
}

func TestCheckAdminPassword_ContainingDisplayNameIsRefused(t *testing.T) {
	out, code := runCheckAdminPasswordCaptured(t, "Dw5-Administrator-Pass#2026", "root", "root@keyorix.local")
	if code == 0 || !strings.Contains(out, "not contain your username, email, or display name") {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

func TestCheckAdminPassword_CustomUsernameIsChecked(t *testing.T) {
	out, code := runCheckAdminPasswordCaptured(t, "Correct-Horse-Alice-2026", "alice", "a@keyorix.local")
	if code == 0 || !strings.Contains(out, "not contain your username") {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

func TestCheckAdminPassword_ValidPasswordIsAccepted(t *testing.T) {
	out, code := runCheckAdminPasswordCaptured(t, "Correct-Horse-Battery-2026\r\n", "admin", "admin@keyorix.local")
	if code != 0 || !strings.Contains(out, "accepted") {
		t.Fatalf("a valid password was refused (code=%d):\n%s", code, out)
	}
}

// The other rules still apply: the pre-check is the server's policy, not a
// username-only filter.
func TestCheckAdminPassword_OtherPolicyRulesStillRefuse(t *testing.T) {
	out, code := runCheckAdminPasswordCaptured(t, "short1!A", "admin", "admin@keyorix.local")
	if code == 0 || !strings.Contains(out, "at least 16 characters") {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

func TestCheckAdminPassword_EmptyStdinIsRefused(t *testing.T) {
	out, code := runCheckAdminPasswordCaptured(t, "\n", "admin", "admin@keyorix.local")
	if code == 0 || !strings.Contains(out, "admin password rejected") {
		t.Fatalf("code=%d out=%s", code, out)
	}
}

// ResolvePasswordPolicy with no password_policy block is exactly the built-in
// default (#G37), so a partial config can never zero a rule.
func TestResolvePasswordPolicy_EmptyBlockIsTheDefault(t *testing.T) {
	if got, want := ResolvePasswordPolicy(config.PasswordPolicyConfig{}), rules.DefaultPasswordPolicy(); got != want {
		t.Fatalf("ResolvePasswordPolicy(empty) = %+v, want %+v", got, want)
	}
}

// A generated admin password must never embed the admin's username, whatever
// KEYORIX_ADMIN_USERNAME says (#3201).
func TestGenerateSecrets_AdminPasswordAvoidsConfiguredUsername(t *testing.T) {
	// A 3-letter username shows up in about 1 of 800 random 43-character tokens,
	// so 5000 draws exercise the regenerate path several times.
	t.Setenv("KEYORIX_ADMIN_USERNAME", "abc")
	policy := rules.DefaultPasswordPolicy()
	for i := 0; i < 5000; i++ {
		pw, err := randomAdminPassword()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(pw), "abc") {
			t.Fatalf("generated password embeds the username: %q", pw)
		}
		if err := policy.Validate(pw, nil); err != nil {
			t.Fatal(err)
		}
	}
}
