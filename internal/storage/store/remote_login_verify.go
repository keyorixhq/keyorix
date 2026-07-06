// remote_login_verify.go — the upstream half of the storage.type: remote
// proxy-login mechanism (#506/#508).
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
// core.Login function the upstream's own direct login uses.
//
// #508: that same upstream call ALSO mints the session, atomically, whenever
// the account needs no MFA/WebAuthn second factor. This is deliberate and
// load-bearing for security: there is no separate, independently-callable
// "create a session for this user_id" endpoint anywhere in this mechanism. A
// generic mint-any-session primitive would let anyone holding the
// RemoteStorage service credential (which this endpoint is already gated
// behind) mint a session for an ARBITRARY user without ever proving that
// user's actual credentials — a confused-deputy / privilege-escalation
// oracle. Tying issuance inseparably to a specific, just-completed
// verification (the same call, not a follow-up one) is what makes this safe —
// mirroring how OAuth/OIDC token-exchange flows avoid the identical class of
// bug by making verification and issuance one atomic, non-replayable
// operation.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// verifyCredentialsWireRequest carries the plaintext password deliberately
// (see the package doc above and #499's precedent) — the upstream server
// needs it to run its own bcrypt compare; there is no other way this check
// could ever work under storage.type: remote. UserAgent/IPAddress are the
// REAL end-user's values, forwarded from the spoke's own LoginRequest, so a
// session minted upstream (#508) carries accurate device metadata for the "My
// Account active sessions" view, and the upstream's own audit trail
// (LogAuthLogin/LogAuthFailure) attributes the attempt to the real caller
// rather than to the spoke server's own service-to-service connection.
type verifyCredentialsWireRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	UserAgent string `json:"user_agent"`
	IPAddress string `json:"ip_address"`
}

// verifyCredentialsWireResponse is deliberately a NARROW, separate DTO from
// userWireResponse (remote_users.go) — it carries exactly what core.Login
// needs after a successful verdict (the MFA-required gate: user.MFAEnabled ||
// user.WebAuthnEnabled — fields userWireResponse does not even carry — plus
// enough identity to describe the session) and nothing else: no
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
	// Session is populated (#508) if and only if MFAEnabled and WebAuthnEnabled
	// are both false — i.e. exactly when the upstream's own core.Login minted
	// one, atomically, as part of THIS SAME verification call. Never populated
	// on any failure path, and never obtainable via any other, separately
	// callable endpoint — see the package doc above for why that atomicity is
	// the whole point.
	Session *sessionMintWireDTO `json:"session,omitempty"`
}

// sessionMintWireDTO carries a freshly minted session's opaque bearer token
// back across the wire. Deliberately NOT models.Session (whose SessionToken
// field is tagged `json:"-"` specifically so a session can never be
// reconstituted or replayed from a generic read of that model, e.g. via
// RemoteStorage.GetSession's response) — this is a narrow, one-shot delivery
// of a newly minted secret to the one party that just proved, via THIS SAME
// call, that it is entitled to receive it.
type sessionMintWireDTO struct {
	ID                uint       `json:"id"`
	Token             string     `json:"token"`
	FamilyID          string     `json:"family_id"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         *time.Time `json:"expires_at"`
	AbsoluteExpiresAt *time.Time `json:"absolute_expires_at"`
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
// ENTIRE password + lockout + account-state check, AND (#508) atomic session
// minting, to the upstream server via POST /api/v1/users/verify-credentials,
// gated by the same users.write permission CreateUser/UnlockUser already
// require of the RemoteStorage service credential (#506) — this is not a
// new, weaker trust boundary, it reuses the existing one.
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
//
// The returned *models.Session is non-nil exactly when the upstream's
// response carries one (i.e. no MFA/WebAuthn gate applied) — core.Login uses
// it directly as the session for this login, rather than trying to persist a
// session of its own via a second, separately callable call.
func (rs *RemoteStorage) VerifyLoginCredentials(ctx context.Context, username, password, userAgent, ipAddress string) (*models.User, *models.Session, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/users/verify-credentials", verifyCredentialsWireRequest{
		Username:  username,
		Password:  password,
		UserAgent: userAgent,
		IPAddress: ipAddress,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("invalid credentials")
	}
	if !resp.Success {
		return nil, nil, fmt.Errorf("invalid credentials")
	}
	var wire verifyCredentialsWireResponse
	if err := json.Unmarshal(resp.Data, &wire); err != nil {
		return nil, nil, fmt.Errorf("invalid credentials")
	}
	user := wire.toModel()
	if wire.Session == nil {
		// MFA/WebAuthn required (or, for a malformed-but-Success response, a
		// defensive absence) — core.Login's MFA gate decides what happens next;
		// no session to return either way.
		return user, nil, nil
	}
	session := &models.Session{
		ID:                wire.Session.ID,
		UserID:            user.ID,
		SessionToken:      wire.Session.Token, // plaintext bearer token, handed to the caller
		FamilyID:          wire.Session.FamilyID,
		UserAgent:         userAgent,
		IPAddress:         ipAddress,
		CreatedAt:         wire.Session.CreatedAt,
		ExpiresAt:         wire.Session.ExpiresAt,
		AbsoluteExpiresAt: wire.Session.AbsoluteExpiresAt,
	}
	return user, session, nil
}
