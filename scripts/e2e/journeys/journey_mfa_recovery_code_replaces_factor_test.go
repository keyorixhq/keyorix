//go:build e2e

package journeys

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_RecoveryCodeReplacesLostTOTP is #4224, driven the way a user who lost
// their phone drives it (docs/operator/lost-totp-runbook.md section 2): sign in with
// the password and a recovery code, re-authenticate the factor change with another
// unused recovery code, and enrol a new device. Red on main: every recovery-code
// call to mfa/recovery-codes/regenerate and mfa/disable answered 400.
func TestJourney_RecoveryCodeReplacesLostTOTP(t *testing.T) {
	serverBin, _ := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const user = "smoketestadmin"
	pw := harness.BootstrapAdminPassword

	// The phone that is about to be lost: enrol TOTP on it, keep its session.
	phoneToken := adminLogin(t, s, user, pw)
	secret := beginMFAEnrollment(t, s, phoneToken)
	codes, _ := activateMFA(t, s, phoneToken, secret, pw)
	if len(codes) < 4 {
		t.Fatalf("activation returned %d recovery codes, want at least 4", len(codes))
	}

	// The phone is gone. Sign in from a laptop with the password and a recovery code.
	laptop := loginWithRecoveryCode(t, s, user, pw, codes[0])

	t.Run("a wrong or already-used recovery code is refused like a wrong code", func(t *testing.T) {
		for _, code := range []string{"ZZZZZ-ZZZZZ", codes[0]} {
			env := restCall(t, s, laptop, http.MethodPost, "/api/v1/auth/mfa/disable", map[string]string{"code": code})
			if env.StatusCode != http.StatusBadRequest || !strings.Contains(string(env.Raw), "invalid code or password") {
				t.Fatalf("disable with %q: want 400 invalid code or password, got %d: %s", code, env.StatusCode, env.Raw)
			}
		}
		env := restCall(t, s, laptop, http.MethodPost, "/api/v1/auth/mfa/disable", map[string]string{"password": pw})
		if env.StatusCode != http.StatusBadRequest {
			t.Fatalf("the password alone must still be refused on a TOTP account, got %d: %s", env.StatusCode, env.Raw)
		}
	})

	var fresh []string
	t.Run("regenerate with an unused recovery code replaces the set", func(t *testing.T) {
		env := restExpect(t, s, laptop, http.MethodPost, "/api/v1/auth/mfa/recovery-codes/regenerate",
			map[string]string{"code": strings.ToLower(codes[1])}, http.StatusOK)
		var data struct {
			RecoveryCodes []string `json:"recovery_codes"`
		}
		if err := json.Unmarshal(env.Data, &data); err != nil || len(data.RecoveryCodes) == 0 {
			t.Fatalf("regenerate returned no codes (err %v): %s", err, env.Raw)
		}
		fresh = data.RecoveryCodes
		old := restCall(t, s, laptop, http.MethodPost, "/api/v1/auth/mfa/disable", map[string]string{"code": codes[2]})
		if old.StatusCode != http.StatusBadRequest {
			t.Fatalf("a code from the replaced set must stop working, got %d: %s", old.StatusCode, old.Raw)
		}
	})

	t.Run("disable with an unused recovery code, then the lost phone's session is gone", func(t *testing.T) {
		if len(fresh) == 0 {
			t.Skip("regenerate step failed")
		}
		env := restExpect(t, s, laptop, http.MethodPost, "/api/v1/auth/mfa/disable",
			map[string]string{"code": fresh[0]}, http.StatusOK)
		if !strings.Contains(string(env.Data), `"mfa_enabled":false`) {
			t.Fatalf("disable: unexpected body %s", env.Raw)
		}
		if gone := restCall(t, s, phoneToken, http.MethodGet, "/api/v1/auth/mfa/recovery-codes", nil); gone.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the lost phone's session must be revoked, got %d: %s", gone.StatusCode, gone.Raw)
		}
		// The laptop session survives and can enrol the new device.
		newSecret := beginMFAEnrollment(t, s, laptop)
		if newSecret == secret {
			t.Fatal("the new enrolment must have a new secret")
		}
		if newCodes, _ := activateMFA(t, s, laptop, newSecret, pw); len(newCodes) == 0 {
			t.Fatal("activating the new device returned no recovery codes")
		}
	})
}

// loginWithRecoveryCode completes /auth/login + /auth/mfa/verify with a recovery
// code and returns the session token.
func loginWithRecoveryCode(t *testing.T, s *harness.Server, username, password, code string) string {
	t.Helper()
	env := restExpect(t, s, "", http.MethodPost, "/auth/login",
		map[string]string{"username": username, "password": password}, http.StatusOK)
	var challenge struct {
		MFAChallenge string `json:"mfa_challenge"`
	}
	if err := json.Unmarshal(env.Data, &challenge); err != nil || challenge.MFAChallenge == "" {
		t.Fatalf("POST /auth/login: expected an mfa_challenge (err %v): %s", err, env.Raw)
	}
	env = restExpect(t, s, "", http.MethodPost, "/auth/mfa/verify",
		map[string]string{"mfa_challenge": challenge.MFAChallenge, "code": code}, http.StatusOK)
	var session struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(env.Data, &session); err != nil || session.Token == "" {
		t.Fatalf("POST /auth/mfa/verify with a recovery code returned no token (err %v): %s", err, env.Raw)
	}
	return session.Token
}
