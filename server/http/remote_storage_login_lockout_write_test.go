// remote_storage_login_lockout_write_test.go — end-to-end regression coverage for
// backlog #529: RemoteStorage.UpdateLoginLockoutState (internal/storage/store/
// remote_users.go) used to be a hard, permanent remoteUnsupported(...) stub
// (#454) — every login-lockout accounting write in internal/core/login_lockout.go
// silently failed OPEN under storage.type: remote. It is now a genuine thin
// passthrough onto a new PUT /api/v1/system/users/{id}/login-lockout route
// (server/http/handlers/login_lockout_proxy.go).
//
// Driven against a REAL server (NewRouter), not a hand-rolled mock of the wire
// protocol — the internal/core-level coverage
// (internal/core/login_lockout_remote_test.go) already exercises
// recordFailedLogin/checkLockAndClearLoginFailures directly (unexported, only
// reachable from within package core); this file instead proves the ACTUAL
// production route/handler/permission-gating work, via UnlockUser (core's one
// EXPORTED entry point onto the same UpdateLoginLockoutState primitive).
package http

import (
	"context"
	"net/http/httptest"
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

// TestRemoteStorageLoginLockout_UnlockUserGenuinelyPersistsAcrossRealServer proves
// the #529 fix end-to-end against the REAL, production router and handlers — not a
// synthetic mock of the wire protocol. It builds two independent
// *core.KeyorixCore instances, each with its own SQLite-backed storage:
//
//   - "upstream": a normal Keyorix server, exercised through the ACTUAL
//     NewRouter(...)/handlers this package registers, including the new
//     PUT /api/v1/system/users/{id}/login-lockout route
//     (server/http/handlers/login_lockout_proxy.go).
//   - "downstream": a Keyorix server configured with storage.type: remote,
//     pointed at "upstream" over real HTTP via store.RemoteStorage — exactly the
//     deployment ADR-049/#454/#529 describe.
//
// Driving an admin UnlockUser call through the DOWNSTREAM core's real, exported
// entry point proves the write genuinely lands in the upstream's own storage —
// closing the gap where storage.type: remote used to make every login-lockout
// write a silent, permanent no-op.
func TestRemoteStorageLoginLockout_UnlockUserGenuinelyPersistsAcrossRealServer(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	// --- upstream: a real Keyorix server ---
	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	defer upstreamSrv.Close()

	// Seed a real user, upstream, already in a tripped-lockout state (simulating
	// prior failed logins) so UnlockUser has genuine state to clear.
	seeded, err := upstreamCore.CreateUser(context.Background(), &core.CreateUserRequest{
		Username: "e2e-lockout-write", Email: "e2e-lockout-write@example.com",
		Password: "Qr7#Kp2$Lm5@Vn9!", DisplayName: "Lockout Write Test User",
	})
	require.NoError(t, err)
	lockedUntil := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	lastFailed := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	require.NoError(t, upstreamCore.Storage().UpdateLoginLockoutState(
		context.Background(), seeded.ID, 3, &lastFailed, &lockedUntil, 1))

	// --- downstream: storage.type: remote, pointed at the upstream ---
	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	downstream := core.NewKeyorixCore(rs)

	// The admin action, driven entirely through the downstream client — exactly
	// what a server booted with storage.type: remote does when an admin unlocks a
	// user via its own API.
	require.NoError(t, downstream.UnlockUser(context.Background(), 1, seeded.ID),
		"UnlockUser must succeed against a real remote-storage upstream, not fail open silently")

	// Confirm the clear genuinely landed in the upstream's OWN storage (not just
	// "the client call didn't error") by reading directly against it.
	fresh, err := upstreamCore.Storage().GetUser(context.Background(), seeded.ID)
	require.NoError(t, err)
	assert.Zero(t, fresh.FailedLoginAttempts, "#529: the upstream's own row must show the lockout counters genuinely cleared")
	assert.Zero(t, fresh.LoginLockoutCount)
	assert.Nil(t, fresh.LoginLockedUntil, "the still-active lock must be genuinely lifted upstream, not merely left to expire")

	// NOTE: this deliberately does NOT also assert the admin-unlock audit event
	// landed in the UPSTREAM's audit log over this same HTTP hop: there is
	// currently no server route backing RemoteStorage.LogAuditEvent's
	// POST /api/v1/audit/events at all (a separate, pre-existing gap discovered
	// while building this test, out of scope for backlog #529 — the downstream
	// core's own emitAudit call fails best-effort, exactly as it does for any
	// other transient storage error, and does not affect UnlockUser's own
	// success above). The write-and-audit call sequence itself IS covered at the
	// internal/core level, against a hand-rolled stand-in server that DOES
	// implement that route (TestUnlockUser_RemoteStorageGenuinelyPersistsAndAudits,
	// internal/core/login_lockout_remote_test.go).
}
