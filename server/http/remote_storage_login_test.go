package http

import (
	"context"
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
// This SUPERSEDES TestLogin_RemoteStorage_StillFailsClosed_PasswordHashNeverOnWire
// (round 114's #828), which deliberately pinned the PRE-fix fail-ALWAYS
// behavior: before this fix, EVERY call below — including the CORRECT
// password — returned "invalid credentials" indistinguishably, because
// Login's bcrypt compare always ran against an empty hash. This test proves
// that is no longer true: a wrong password is rejected, a correct password's
// credential CHECK now genuinely succeeds (proceeding past that gate into
// mintSession — see below for why it does not go further YET), and repeated
// wrong passwords trip the SAME per-account lockout the direct LocalStorage
// path enforces, via the identical core.VerifyPasswordCredentials logic
// (reverting internal/core/auth.go's RemoteLoginVerifier/
// VerifyPasswordCredentials changes, or
// internal/storage/store/remote_login_verify.go, or the
// POST /api/v1/users/verify-credentials route/handler, makes this test fail
// exactly as the old #828 pinning test predicted — verified by hand while
// developing this fix).
//
// What this test deliberately does NOT prove — because it is not true yet —
// is a fully USABLE end-to-end login (a session the caller can actually
// authenticate subsequent requests with). That is blocked by a separate,
// pre-existing, larger gap this fix does not attempt to close: RemoteStorage's
// session persistence (CreateSession/GetSession/DeleteSession, remote_auth.go)
// has no corresponding server routes at all — POST /api/v1/sessions 404s
// unconditionally today, entirely independent of the password-hash problem
// #506 is about. A correct password's Login call below therefore still
// returns an error, but a DIFFERENT one than an incorrect password: it fails
// at mintSession (session persistence), not at the credential check — proving
// the two are now genuinely distinguishable, which they were not before this
// fix (every failure reason collapsed to the identical "invalid credentials").
// See the PR description for why closing the session-persistence gap safely
// (a naive "create a session for this user_id" wire primitive would be a
// privilege-escalation oracle far worse than today's "login doesn't work")
// needs its own dedicated design pass, not a rushed addition here.
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

	// The CORRECT password now gets PAST the credential check (the #506 fix) —
	// proceeding to mintSession, which fails on a DIFFERENT, session-specific
	// error (the separate, pre-existing session-persistence gap documented
	// above), not the generic "invalid credentials" every failure reason
	// collapsed to before this fix.
	_, _, err = downstreamCore.Login(ctx, &core.LoginRequest{
		Username: "testadmin", Password: "TestPassword123!",
	})
	require.Error(t, err, "session persistence is a separate, unimplemented gap (see test doc) — "+
		"but the error must no longer be the generic credential-check failure")
	assert.NotEqual(t, "invalid credentials", err.Error(),
		"a CORRECT password must be distinguishable from a wrong one: it should fail at session "+
			"minting, not at the credential check the #506 fix targets")
	assert.Contains(t, err.Error(), "session", "expected a session-persistence failure, not a credential-check failure")

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
