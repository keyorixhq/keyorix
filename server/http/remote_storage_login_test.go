package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogin_RemoteStorage_ProxiesPasswordCredentialCheck proves the #506 fix
// for the credential-verification half of storage.type: remote password
// login: a "spoke" server backed by RemoteStorage, pointed at a real "hub"
// server backed by LocalStorage, can now run the ENTIRE password + per-account
// lockout + account-state check against the hub's real bcrypt hash and real,
// persisted lockout accounting — proxied via core.RemoteLoginVerifier
// (internal/core/auth.go) and POST /api/v1/users/verify-credentials
// (server/http/handlers/users_crud.go).
//
// #508 extends this: the correct-password case below now succeeds all the
// way through to a genuinely usable session (see
// TestLogin_RemoteStorage_SessionUsableEndToEnd for the full lifecycle:
// login → validate → logout → validate-fails). Before #508, this same call
// got PAST the credential check but then failed at session persistence
// (RemoteStorage's CreateSession had no corresponding server route at all) —
// this test used to pin that intermediate, still-broken state; it now pins
// the actual fix.
func TestLogin_RemoteStorage_ProxiesPasswordCredentialCheck(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	// --- upstream ("hub"): the real holder of the user record + password hash ---
	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)
	// A tight lockout policy (2 attempts) so this test can trip it in a
	// handful of calls below, proving the SAME per-account lockout gating the
	// direct LocalStorage path enforces also applies via this proxied path
	// (#506's primary security concern) — not a parallel, unprotected check.
	upstreamCore.SetLoginLockoutPolicy(core.LoginLockoutPolicy{
		Enabled: true, MaxAttempts: 2, Window: 15 * time.Minute,
		BaseCooldown: time.Hour, MaxCooldown: time.Hour,
	})

	cfg := &config.Config{
		Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"}},
	}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	defer upstreamSrv.Close()

	// --- downstream ("spoke"): storage.type: remote, pointed at the upstream ---
	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	downstreamCore := core.NewKeyorixCore(rs)

	ctx := context.Background()

	// A wrong password must fail through the proxied path exactly like it
	// always has — the credential check itself rejects it before ever
	// reaching session minting.
	_, _, err = downstreamCore.Login(ctx, &core.LoginRequest{
		Username: "definitely-the-wrong-password-user", Password: "irrelevant",
	})
	require.Error(t, err)
	assert.Equal(t, "invalid credentials", err.Error())

	_, _, err = downstreamCore.Login(ctx, &core.LoginRequest{
		Username: "testadmin", Password: "definitely-the-wrong-password",
	})
	require.Error(t, err)
	assert.Equal(t, "invalid credentials", err.Error())

	// The CORRECT password now succeeds end-to-end (#508): verification AND
	// session minting happen atomically on the upstream, and the minted
	// session's token comes back on this same call.
	session, user, err := downstreamCore.Login(ctx, &core.LoginRequest{
		Username: "testadmin", Password: "TestPassword123!",
	})
	require.NoError(t, err, "a correct password must now succeed all the way to a usable session")
	require.NotNil(t, session)
	assert.NotEmpty(t, session.SessionToken, "the upstream-minted session's token must be delivered to the caller")
	assert.Equal(t, "testadmin", user.Username)

	// --- lockout: repeated wrong passwords via THIS proxied path must trip
	// the SAME per-account lockout the direct path enforces (MaxAttempts=2
	// above), proving it is not a parallel, unprotected credential check —
	// #506's primary security concern. Verified directly against the
	// upstream's own (LocalStorage-backed) user record, since Login's return
	// error alone can't distinguish "wrong password" from "locked" through
	// this proxy (see remote_login_verify.go's doc for why that collapse is
	// deliberate).
	_, _, err = downstreamCore.Login(ctx, &core.LoginRequest{Username: "testadmin", Password: "wrong-1"})
	require.Error(t, err)
	_, _, err = downstreamCore.Login(ctx, &core.LoginRequest{Username: "testadmin", Password: "wrong-2"})
	require.Error(t, err)

	locked, err := upstreamCore.GetUserByUsername(ctx, "testadmin")
	require.NoError(t, err)
	require.NotNil(t, locked.LoginLockedUntil, "the account must be locked upstream after "+
		"MaxAttempts failures reached via the proxied path, exactly like the direct LocalStorage path")
	assert.True(t, locked.LoginLockedUntil.After(time.Now()))

	// While locked, even the CORRECT password must be refused (rejected at the
	// credential check, before ever reaching session minting) — proxied
	// through the identical path.
	_, _, err = downstreamCore.Login(ctx, &core.LoginRequest{Username: "testadmin", Password: "TestPassword123!"})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "locked") || err.Error() == "invalid credentials",
		"a locked account's correct password must still be refused at the credential check")
}

// TestLogin_RemoteStorage_SessionUsableEndToEnd proves #508's core security
// requirement (a): a storage.type: remote login produces a REAL, usable
// session — not just a verified credential with nowhere to go. It exercises
// the full lifecycle entirely through the downstream ("spoke") core, backed
// by RemoteStorage, against a real upstream ("hub") server:
//
//  1. Login succeeds and returns a session minted BY THE UPSTREAM.
//  2. That session validates (core.ValidateSessionToken proxies the lookup to
//     the upstream via the new GET /api/v1/sessions/{token} route, #508) —
//     proving the upstream remains the sole source of truth for session
//     validity, not merely for the login step.
//  3. Logout deletes it (proxied via the new DELETE /api/v1/sessions/{id}
//     route, #508) — requirement (c).
//  4. After logout, the same token no longer validates — the deletion
//     actually took effect upstream, not just locally.
func TestLogin_RemoteStorage_SessionUsableEndToEnd(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)

	cfg := &config.Config{
		Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"}},
	}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	defer upstreamSrv.Close()

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	downstreamCore := core.NewKeyorixCore(rs)

	ctx := context.Background()

	session, user, err := downstreamCore.Login(ctx, &core.LoginRequest{
		Username: "testadmin", Password: "TestPassword123!",
		UserAgent: "test-agent", IPAddress: "203.0.113.7",
	})
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NotEmpty(t, session.SessionToken)

	// The session validates through the SAME proxy path a real authenticated
	// request would use (core.ValidateSessionToken -> RemoteStorage.GetSession
	// -> GET /api/v1/sessions/{token} on the hub).
	validatedUser, _, err := downstreamCore.ValidateSessionToken(ctx, session.SessionToken)
	require.NoError(t, err, "a session minted by the atomic verify+mint call must actually validate afterward")
	assert.Equal(t, user.ID, validatedUser.ID)
	assert.Equal(t, "testadmin", validatedUser.Username)

	// The session genuinely lives on the upstream, not just in the spoke's
	// process: fetching it directly via the upstream's own core confirms a
	// real row was persisted there (not merely echoed back).
	upstreamSession, err := upstreamCore.GetSessionForRemoteProxy(ctx, session.SessionToken)
	require.NoError(t, err, "the minted session must be a REAL row on the upstream, not just a wire echo")
	assert.Equal(t, user.ID, upstreamSession.UserID)

	// Logout must actually revoke it upstream (requirement (c)).
	require.NoError(t, downstreamCore.Logout(ctx, session.SessionToken))

	_, _, err = downstreamCore.ValidateSessionToken(ctx, session.SessionToken)
	assert.Error(t, err, "a logged-out session must no longer validate")

	_, err = upstreamCore.GetSessionForRemoteProxy(ctx, session.SessionToken)
	assert.Error(t, err, "the session row must actually be gone upstream after logout, not just locally forgotten")
}

// TestVerifyCredentials_WrongPasswordNeverMintsSession proves #508's core
// security requirement (b): an attacker who does NOT have valid credentials
// for user X cannot obtain a session for user X — even while holding a fully
// valid RemoteStorage service credential (the same bearer token a compromised
// "spoke" deployment's credential would be) — by calling
// POST /api/v1/users/verify-credentials directly with a wrong password. This
// is the endpoint that atomically verifies AND mints (#508); it must never
// mint on a failed verification, and there must be no OTHER, separate
// endpoint that could mint one instead.
func TestVerifyCredentials_WrongPasswordNeverMintsSession(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)

	cfg := &config.Config{
		Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"}},
	}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	defer upstreamSrv.Close()

	// createTestToken already logged testadmin in once (to mint upstreamToken
	// itself) — capture that baseline so the assertion below proves this call
	// added NO new session, not merely that zero happen to exist.
	admin, err := upstreamCore.GetUserByUsername(context.Background(), "testadmin")
	require.NoError(t, err)
	before, err := upstreamCore.ListOwnSessions(context.Background(), admin.ID)
	require.NoError(t, err)

	body, err := json.Marshal(map[string]string{
		"username": "testadmin",
		"password": "definitely-not-the-real-password",
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, upstreamSrv.URL+"/api/v1/users/verify-credentials", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+upstreamToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"a wrong password must be rejected outright — never a 2xx with a session attached")

	var decoded map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&decoded))
	assert.Equal(t, false, decoded["success"])
	_, hasData := decoded["data"]
	assert.False(t, hasData, "a failed verification must never carry a data payload, let alone a session")

	// Confirm directly against the upstream's own record: this call added NO
	// new session on top of the pre-existing baseline.
	after, err := upstreamCore.ListOwnSessions(context.Background(), admin.ID)
	require.NoError(t, err)
	assert.Len(t, after, len(before), "a rejected verification attempt must mint NO session at all")
}
