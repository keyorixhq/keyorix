package core

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordPolicy_Default(t *testing.T) {
	p := DefaultPasswordPolicy()
	user := &models.User{Username: "alice", Email: "alice@example.com", DisplayName: "Alice Smith"}

	cases := []struct {
		name    string
		pw      string
		wantErr string // substring expected in the error; "" means must pass
	}{
		{"compliant", "Str0ng#Passphrase!", ""},
		{"too short", "Ab1!xyz", "at least 16 characters"},
		{"no uppercase", "str0ng#passphrase!", "uppercase"},
		{"no lowercase", "STR0NG#PASSPHRASE!", "lowercase"},
		{"no digit", "Strong#Passphrase!", "digit"},
		{"no special", "Str0ngPassphrase00", "special character"},
		{"contains username", "alice#Str0ngPassword", "username, email, or display name"},
		{"contains email local part", "Str0ng#alicePassword", "username, email, or display name"},
		{"contains display-name word", "Str0ng#smithPassword", "username, email, or display name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := p.Validate(tc.pw, user)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// All unmet requirements are reported together, not just the first.
func TestPasswordPolicy_ReportsAllFailures(t *testing.T) {
	p := DefaultPasswordPolicy()
	err := p.Validate("abc", nil) // short, no upper, no digit, no special
	require.Error(t, err)
	for _, want := range []string{"16 characters", "uppercase", "digit", "special"} {
		assert.Contains(t, err.Error(), want)
	}
	// Personal-info check is skipped when user is nil.
	assert.NotContains(t, err.Error(), "display name")
}

// A relaxed (lab) policy accepts a simple password and skips disabled checks.
func TestPasswordPolicy_Relaxed(t *testing.T) {
	p := PasswordPolicy{MinLength: 8} // complexity + personal-info off
	user := &models.User{Username: "alice"}
	assert.NoError(t, p.Validate("simplepw", user))
	assert.NoError(t, p.Validate("aliceeee", user), "personal-info check off → username allowed")

	err := p.Validate("short", user)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 8 characters")
	assert.False(t, strings.Contains(err.Error(), "uppercase"), "disabled checks not reported")
}

// The common-password rule rejects denylisted passwords (case-insensitive) and
// is independent of the complexity checks.
func TestPasswordPolicy_RejectsCommonPasswords(t *testing.T) {
	p := PasswordPolicy{RejectCommonPasswords: true}
	for _, pw := range []string{"password", "PASSWORD", "Keyorix123", "letmein"} {
		err := p.Validate(pw, nil)
		require.Error(t, err, "expected %q to be rejected", pw)
		assert.Contains(t, err.Error(), "commonly-used password")
	}
	// A strong, non-listed password passes the common-password rule.
	assert.NoError(t, p.Validate("Z6!txQ9mAe2vПЛh", nil))
}

func TestIsCommonPassword(t *testing.T) {
	assert.True(t, isCommonPassword("qwerty"))
	assert.True(t, isCommonPassword("  Admin  "), "trimmed + lowercased")
	assert.False(t, isCommonPassword("a-genuinely-unusual-passphrase-42"))
}
