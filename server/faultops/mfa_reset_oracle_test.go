// mfa_reset_oracle_test.go — MFA-RESET-TESTS-1 item 3, oracle (g): an MFA reset
// that dies half-way must never leave the target with a second factor gone while
// the OLD password still works or a session / personal access token still lives.
//
// That state is the takeover the reset is designed against: whoever holds the old
// password (or a stolen session) no longer faces the second factor. The reset
// replaces the password with a one-time password and revokes every session and PAT
// in the same transaction as it removes the factors, so any fault must leave
// either everything or nothing. Oracle (a) compares tables with a reference world
// and cannot see this: password hashes are presence-only in the snapshot, so "the
// old password still works" and "a new password was set" canonicalize identically.
// This oracle reads the target's rows directly and checks the old password with
// bcrypt.
//
// "Factor gone" is deliberately broad: ANY of the TOTP secret, the MFA flag or the
// passkey rows missing counts, because the fixture starts the target with all of
// them. A half-cleared target is exactly what a partial commit would leave.
//
// No tolerance and no by-design table (like oracle (f)): reported through Errorf
// directly. It runs on every input of the fuzzer and of every deterministic driver
// via checkOraclesReporting, and is gated to the three MFA reset ops.
//
// What it does not see: a reset that fails closed by never clearing anything is
// fine here by construction (nothing cleared, so no violation); that the request
// stays pending or is retired is oracle (a)'s business. Nor does it see the HTTP
// auth cache holding a revoked session; that eviction is covered in
// internal/core (TestMFAReset_TwoAdmins_FullCredentialReset_EverySessionAndPATDead).
package faultops

import (
	"slices"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var mfaResetOps = []string{
	"REST POST /api/v1/mfa-reset-requests",
	"REST POST /api/v1/mfa-reset-requests/{id}/approve",
	"REST POST /api/v1/mfa-reset-requests/{id}/cancel",
}

// mfaResetTargetState is what the oracle reads about the target.
type mfaResetTargetState struct {
	hasSecret        bool // an mfa_secrets row exists
	mfaFlag          bool // users.mfa_enabled
	passkeys         int  // webauthn_credentials rows
	oldPasswordWorks bool
	sessions         int // session rows
	livePATs         int // personal access tokens not revoked
}

func (s mfaResetTargetState) factorCleared() bool {
	return !s.hasSecret || !s.mfaFlag || s.passkeys == 0
}

// mfaResetLiveCredentialViolations returns one line per way the target is exposed:
// empty unless a factor is cleared AND an old credential still works.
func mfaResetLiveCredentialViolations(s mfaResetTargetState) []string {
	if !s.factorCleared() {
		return nil
	}
	var out []string
	if s.oldPasswordWorks {
		out = append(out, "the OLD password still works")
	}
	if s.sessions > 0 {
		out = append(out, "a session is still live")
	}
	if s.livePATs > 0 {
		out = append(out, "a personal access token is still live")
	}
	return out
}

func readMFAResetTargetState(db *gorm.DB) (mfaResetTargetState, bool, error) {
	var u models.User
	if err := db.Where("username = ?", mfaResetFuzzTarget).Limit(1).Find(&u).Error; err != nil {
		return mfaResetTargetState{}, false, err
	}
	if u.ID == 0 {
		return mfaResetTargetState{}, false, nil
	}
	s := mfaResetTargetState{mfaFlag: u.MFAEnabled}
	s.oldPasswordWorks = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(fuzzUserPassword)) == nil
	var n int64
	if err := db.Model(&models.MFASecret{}).Where("user_id = ?", u.ID).Count(&n).Error; err != nil {
		return s, true, err
	}
	s.hasSecret = n > 0
	if err := db.Model(&models.WebAuthnCredential{}).Where("user_id = ?", u.ID).Count(&n).Error; err != nil {
		return s, true, err
	}
	s.passkeys = int(n)
	if err := db.Model(&models.Session{}).Where("user_id = ?", u.ID).Count(&n).Error; err != nil {
		return s, true, err
	}
	s.sessions = int(n)
	if err := db.Model(&models.PersonalAccessToken{}).Where("user_id = ? AND revoked = ?", u.ID, false).Count(&n).Error; err != nil {
		return s, true, err
	}
	s.livePATs = int(n)
	return s, true, nil
}

// checkMFAResetNeverClearedWithLiveCredential is oracle (g). Called from
// checkOraclesReporting.
func checkMFAResetNeverClearedWithLiveCredential(t fuzzVerdict, label string, in oracleInput) {
	t.Helper()
	if in.world == nil || !slices.Contains(mfaResetOps, in.op) {
		return
	}
	s, found, err := readMFAResetTargetState(in.world.db)
	if err != nil {
		t.Errorf("%s: ORACLE (g): cannot read the MFA reset target's state: %v", label, err)
		return
	}
	if !found {
		t.Errorf("%s: ORACLE (g): the MFA reset target %q does not exist: the fixture is broken and the oracle checks nothing", label, mfaResetFuzzTarget)
		return
	}
	for _, v := range mfaResetLiveCredentialViolations(s) {
		t.Errorf("%s: ORACLE (g) VIOLATION (MFA-RESET-TESTS-1) — the second factor of the reset target is gone (TOTP secret=%v flag=%v passkeys=%d) but %s: "+
			"clearing the factor without replacing the password and revoking sessions and PATs in the same transaction is a takeover primitive",
			label, s.hasSecret, s.mfaFlag, s.passkeys, v)
	}
}

// TestMFAResetOracle_Calibration: red on every exposed shape, green on the three
// legitimate end states (untouched, fully reset, and not reset at all).
func TestMFAResetOracle_Calibration(t *testing.T) {
	intact := mfaResetTargetState{hasSecret: true, mfaFlag: true, passkeys: 1, oldPasswordWorks: true, sessions: 1, livePATs: 1}
	reset := mfaResetTargetState{}
	cases := []struct {
		name string
		s    mfaResetTargetState
		want int
	}{
		{"untouched target", intact, 0},
		{"fully reset target", reset, 0},
		{"factors gone, old password and session and PAT live", mfaResetTargetState{oldPasswordWorks: true, sessions: 1, livePATs: 1}, 3},
		{"TOTP secret gone only, everything else live", mfaResetTargetState{mfaFlag: true, passkeys: 1, oldPasswordWorks: true, sessions: 1, livePATs: 1}, 3},
		{"passkey gone only, old password live", mfaResetTargetState{hasSecret: true, mfaFlag: true, oldPasswordWorks: true}, 1},
		{"MFA flag cleared, session live", mfaResetTargetState{hasSecret: true, passkeys: 1, sessions: 1}, 1},
		{"factors gone, only a PAT live", mfaResetTargetState{livePATs: 2}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := len(mfaResetLiveCredentialViolations(c.s)); got != c.want {
				t.Errorf("violations = %d, want %d", got, c.want)
			}
		})
	}
}
