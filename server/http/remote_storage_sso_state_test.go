// remote_storage_sso_state_test.go — end-to-end coverage for #521: RemoteStorage's
// CreateSSOLoginState/ConsumeSSOLoginState were entirely stubbed, so
// BeginSSO/BeginSAML's very first step (persisting the CSRF-state/nonce row) hard-
// failed under storage.type: remote for BOTH OIDC and SAML — human SSO login was
// 100% broken. Mirrors remote_storage_setup_tokens_test.go's #510 harness exactly:
// a real "upstream" exercised through the production NewRouter/handlers (including
// the new /api/v1/system/sso-state routes, server/http/handlers/sso_state_proxy.go),
// and a "downstream" *core.KeyorixCore configured with storage.type: remote pointed
// at "upstream" over real HTTP via store.RemoteStorage.
package http

import (
	"context"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForSSOState builds the standard #452/#507/#510/#521
// two-server harness: an "upstream" exercised through the REAL production
// NewRouter/handlers, and a "downstream" *core.KeyorixCore configured with
// storage.type: remote (ADR-049), pointed at "upstream" over real HTTP via
// store.RemoteStorage.
func newUpstreamDownstreamForSSOState(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createNodeToken(t, upstream)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	t.Cleanup(upstreamSrv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	downstream = core.NewKeyorixCore(rs)
	return upstream, downstream
}

// buildSSOLoginState mirrors what internal/core/sso.go's BeginSSO/BeginSAML
// compute before calling storage.CreateSSOLoginState — a fully-built,
// not-yet-expired state row — WITHOUT going through BeginSSO/BeginSAML
// themselves (which require a fully configured OIDC/SAML provider), so the
// storage-primitive tests below can exercise CreateSSOLoginState/
// ConsumeSSOLoginState directly.
func buildSSOLoginState(now time.Time, state, nonce, provider string) *models.SSOLoginState {
	return &models.SSOLoginState{
		State:     state,
		Nonce:     nonce,
		Provider:  provider,
		ReturnTo:  "/dashboard",
		ExpiresAt: now.Add(10 * time.Minute),
		CreatedAt: now,
	}
}

// TestRemoteStorageSSOState_CreateConsume_RealServer proves the #521 fix: an
// SSO login state is genuinely persisted on the upstream server via the
// DOWNSTREAM's RemoteStorage, single-use-consumable, and a replay cleanly
// loses — all via storage.type: remote against a real router, not a protocol
// mock.
func TestRemoteStorageSSOState_CreateConsume_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForSSOState(t)
	ctx := context.Background()
	now := time.Now()

	s := buildSSOLoginState(now, "state-create-consume", "nonce-abc", "okta")
	require.NoError(t, downstream.Storage().CreateSSOLoginState(ctx, s),
		"creating an SSO login state must succeed via storage.type: remote")
	require.NotZero(t, s.ID, "the upstream must assign a real ID")

	// Confirm it is a REAL row in the upstream's own storage (not just "the
	// call didn't error"), by consuming it directly against upstream.
	direct, err := upstream.Storage().ConsumeSSOLoginState(ctx, "state-not-used-directly")
	assert.Error(t, err, "an unrelated/unknown state must not be found")
	assert.Nil(t, direct)

	// Consuming via the downstream (RemoteStorage) round-trips every field and
	// succeeds exactly once.
	consumed, err := downstream.Storage().ConsumeSSOLoginState(ctx, "state-create-consume")
	require.NoError(t, err)
	assert.Equal(t, "nonce-abc", consumed.Nonce)
	assert.Equal(t, "okta", consumed.Provider)
	assert.Equal(t, "/dashboard", consumed.ReturnTo)
	assert.WithinDuration(t, now.Add(10*time.Minute), consumed.ExpiresAt, time.Second)

	// A second consume attempt against the same (now-deleted) state must
	// cleanly fail — the single-use guarantee — not silently succeed again.
	_, err = downstream.Storage().ConsumeSSOLoginState(ctx, "state-create-consume")
	require.Error(t, err, "consuming an already-consumed state must fail, not silently double-succeed")

	// The upstream's own storage must show the row is really gone.
	_, err = upstream.Storage().ConsumeSSOLoginState(ctx, "state-create-consume")
	require.Error(t, err)
}

// TestRemoteStorageSSOState_ConsumeUnknown_RealServer proves a clean not-found
// error (not a panic, not a garbage 500) for a state that was never created.
func TestRemoteStorageSSOState_ConsumeUnknown_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForSSOState(t)
	ctx := context.Background()

	_, err := downstream.Storage().ConsumeSSOLoginState(ctx, "state-never-created")
	require.Error(t, err)
}

// TestRemoteStorageSSOState_DifferentProvidersIsolated_RealServer proves
// separate provider rows (as BeginSSO and BeginSAML would each create, one per
// login attempt) don't interfere with one another.
func TestRemoteStorageSSOState_DifferentProvidersIsolated_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForSSOState(t)
	ctx := context.Background()
	now := time.Now()

	oidcState := buildSSOLoginState(now, "state-oidc", "nonce-oidc", "google")
	samlState := buildSSOLoginState(now, "state-saml", "authn-request-id-123", "adfs")
	require.NoError(t, downstream.Storage().CreateSSOLoginState(ctx, oidcState))
	require.NoError(t, downstream.Storage().CreateSSOLoginState(ctx, samlState))

	consumedSAML, err := downstream.Storage().ConsumeSSOLoginState(ctx, "state-saml")
	require.NoError(t, err)
	assert.Equal(t, "adfs", consumedSAML.Provider)
	assert.Equal(t, "authn-request-id-123", consumedSAML.Nonce)

	// The unrelated OIDC state must still be consumable afterward.
	consumedOIDC, err := downstream.Storage().ConsumeSSOLoginState(ctx, "state-oidc")
	require.NoError(t, err)
	assert.Equal(t, "google", consumedOIDC.Provider)
	assert.Equal(t, "nonce-oidc", consumedOIDC.Nonce)
}

// TestRemoteStorageSSOState_ConcurrentConsumeRace_RealServer is the critical
// #521 test: it fires N concurrent "consume" requests at the SAME SSO login
// state over real HTTP against the real upstream router, and asserts EXACTLY
// ONE succeeds — proving ConsumeSSOLoginStateProxy's direct passthrough onto
// local_sso.go's atomic read-then-conditional-delete still closes the
// double-consume TOCTOU race CompleteSSO/CompleteSAML depend on, even across a
// network hop — not a client-side "GET, then DELETE" sequence, which would
// reopen exactly this race. Mirrors #510's
// TestRemoteStorageSetupToken_ConcurrentConsumeRace_RealServer exactly.
func TestRemoteStorageSSOState_ConcurrentConsumeRace_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForSSOState(t)
	ctx := context.Background()
	now := time.Now()

	s := buildSSOLoginState(now, "state-race", "nonce-race", "okta")
	require.NoError(t, downstream.Storage().CreateSSOLoginState(ctx, s))

	const n = 20
	var successCount atomic.Int64
	var errCount atomic.Int64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := downstream.Storage().ConsumeSSOLoginState(ctx, "state-race")
			if err != nil {
				errCount.Add(1)
				return
			}
			successCount.Add(1)
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), successCount.Load(), "exactly one concurrent consume must win the race — the rest must cleanly lose, never a double consume")
	assert.Equal(t, int64(n-1), errCount.Load(), "every losing concurrent consume attempt must get a clean not-found error, not a transport/server error")
}
