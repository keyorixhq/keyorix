// remote_login_verify.go — the upstream half of the storage.type: remote
// proxy-login mechanism (#506).
//
// models.User.PasswordHash is deliberately `json:"-"` and never crosses the
// wire, so RemoteStorage can never itself compare a submitted password against
// a real hash — GetUserByUsername's decoded user always has an empty hash.
// VerifyLoginCredentials closes that gap not by relaxing the "never send a
// hash" rule, but by sending the PLAINTEXT password (the same trust boundary
// #499/#505 already established for CreateUser's password field: a bearer-
// authenticated, TLS-protected RemoteStorage↔upstream service call, not a
// public/unauthenticated route) to a dedicated upstream endpoint that performs
// the ENTIRE check — password compare, per-account lockout gating and
// accounting, and account-active/account-state — using the exact same
// core.VerifyPasswordCredentials function the upstream's own direct login uses,
// and returns only a pass/fail verdict plus the minimal fields core.Login needs
// to proceed (never the hash, never a lockout/account-state reason — see
// verifyCredentialsWireResponse below for why the failure path is a single,
// generic error regardless of the real reason).
package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// verifyCredentialsWireRequest carries the plaintext password deliberately
// (see the package doc above and #499's precedent) — the upstream server
// needs it to run its own bcrypt compare; there is no other way this check
// could ever work under storage.type: remote.
type verifyCredentialsWireRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// verifyCredentialsWireResponse is deliberately a NARROW, separate DTO from
// userWireResponse (remote_users.go) — it carries exactly what core.Login
// needs after a successful verdict (the MFA-required gate: user.MFAEnabled ||
// user.WebAuthnEnabled — fields userWireResponse does not even carry — plus
// enough identity to mint/describe the session) and nothing else: no
// password_hash (obviously), no lockout-accounting counters (meaningless
// here — the upstream already applied/cleared them before ever returning
// success), no other account fields core.Login has no use for once the
// upstream has already run every gate on its own real, authoritative record.
type verifyCredentialsWireResponse struct {
	ID              uint   `json:"id"`
	Username        string `json:"username"`
	Email           string `json:"email"`
	DisplayName     string `json:"display_name"`
	AccountState    string `json:"account_state"`
	MFAEnabled      bool   `json:"mfa_enabled"`
	WebAuthnEnabled bool   `json:"webauthn_enabled"`
}

func (w verifyCredentialsWireResponse) toModel() *models.User {
	return &models.User{
		ID:              w.ID,
		Username:        w.Username,
		Email:           w.Email,
		DisplayName:     w.DisplayName,
		AccountState:    w.AccountState,
		MFAEnabled:      w.MFAEnabled,
		WebAuthnEnabled: w.WebAuthnEnabled,
		// The upstream endpoint already enforced IsActive/AccountLoginBlocked
		// before ever returning success, and core.Login's remote-proxy branch
		// does not re-check them (see VerifyPasswordCredentials) — IsActive is
		// set true here only so nothing downstream that happens to read it
		// (e.g. an audit-log helper) sees a false "inactive" for an account
		// the upstream just proved was allowed to log in.
		IsActive: true,
	}
}

// VerifyLoginCredentials implements core.RemoteLoginVerifier: it proxies the
// ENTIRE password + lockout + account-state check to the upstream server via
// POST /api/v1/users/verify-credentials, gated by the same users.write
// permission CreateUser/UnlockUser already require of the RemoteStorage
// service credential (#506) — this is not a new, weaker trust boundary, it
// reuses the existing one.
//
// Every failure — wrong password, a tripped lockout, a suspended/inactive
// account, or a network/parse error — collapses to the SAME generic "invalid
// credentials" error. This is deliberate: the actual end-user-facing
// /auth/login handler (server/http/handlers/auth.go) already collapses every
// non-MFA-required Login error to one generic 401 regardless of the real
// reason, so no caller-visible behavior is lost; but it also means this proxy
// call cannot become a richer oracle than the direct path ever was — a
// compromised RemoteStorage credential learns nothing from this endpoint
// beyond "that attempt failed", not why. Fail-closed applies uniformly too: a
// transport error or a malformed response is treated exactly like a rejected
// credential, never as "let the caller in".
func (rs *RemoteStorage) VerifyLoginCredentials(ctx context.Context, username, password string) (*models.User, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/users/verify-credentials", verifyCredentialsWireRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	if !resp.Success {
		return nil, fmt.Errorf("invalid credentials")
	}
	var wire verifyCredentialsWireResponse
	if err := json.Unmarshal(resp.Data, &wire); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	return wire.toModel(), nil
}
