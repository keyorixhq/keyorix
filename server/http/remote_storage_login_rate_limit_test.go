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

// TestRemoteStorageLoginRateLimit_ThrottlesAcrossRealServer proves the #452
// follow-up fix end-to-end against the REAL, production router and handlers — not
// a synthetic mock of the wire protocol. It builds two independent
// *core.KeyorixCore instances, each with its own SQLite-backed storage:
//
//   - "upstream": a normal Keyorix server, exercised through the ACTUAL
//     NewRouter(...)/handlers this package registers, including the new
//     /api/v1/system/login-attempts routes (server/http/handlers/
//     login_attempts_proxy.go).
//   - "downstream": a Keyorix server configured with storage.type: remote,
//     pointed at "upstream" over real HTTP via store.RemoteStorage — exactly the
//     deployment ADR-049/#452/#454 describe.
//
// Driving repeated failed logins through the DOWNSTREAM core's real
// IsLoginRateLimited/RecordFailedLogin (the exact code path server/http/handlers/
// auth.go's /auth/login handler uses) proves the Nth attempt is genuinely
// throttled — closing the gap where storage.type: remote used to make this rate
// limiter a silent, permanent no-op for the life of the process.
func TestRemoteStorageLoginRateLimit_ThrottlesAcrossRealServer(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	// --- upstream: a real Keyorix server ---
	upstreamCore := newTestCore(t)
	// createTestToken bootstraps an admin user/session — the admin role carries
	// system.read AND system.write (see internal/core/auth_bootstrap.go's
	// adminPermissions), the exact permissions the new routes require. This is
	// deliberately the SAME broad credential a RemoteStorage client already needs
	// for every OTHER proxied call (full user CRUD via /api/v1/users), so using it
	// here introduces no new privilege class.
	upstreamToken := createNodeToken(t, upstreamCore)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	defer upstreamSrv.Close()

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

	ctx := context.Background()
	ip := "203.0.113.77"

	// Below the budget: every attempt is still allowed.
	for i := 0; i < core.LoginMaxAttempts-1; i++ {
		downstream.RecordFailedLogin(ctx, ip)
	}
	assert.False(t, downstream.IsLoginRateLimited(ctx, ip),
		"under budget must still be allowed when the counter is proxied to a real upstream server")

	// Reaching the budget: the IP is genuinely throttled.
	downstream.RecordFailedLogin(ctx, ip)
	assert.True(t, downstream.IsLoginRateLimited(ctx, ip),
		"the Nth failed login from the same IP must be throttled under storage.type: remote against a real server")

	// A different IP sharing nothing with the sprayed one is unaffected.
	assert.False(t, downstream.IsLoginRateLimited(ctx, "9.9.9.9"))

	// Confirm the rows genuinely landed in the upstream's OWN storage (not just
	// "the client call didn't error") by counting directly against it.
	n, err := upstreamCore.Storage().CountRecentLoginAttempts(ctx, ip, time.Now().Add(-core.LoginWindow))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(core.LoginMaxAttempts),
		"the downstream's forwarded attempts are real rows in the upstream's own login_attempts table")
}
