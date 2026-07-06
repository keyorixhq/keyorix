// remote_storage_setup_tokens_test.go — end-to-end coverage for #510: RemoteStorage's
// SetupToken CRUD (CreateSetupToken/GetSetupTokenByHash/SupersedeActiveSetupTokens/
// MarkSetupTokenConsumed/MarkSetupTokenExpired/CountSetupTokensSince) was entirely
// stubbed, so CompleteSetup's very first step (inspectActiveSetupToken) hard-failed
// under storage.type: remote for EVERY setup-token purpose (account_setup,
// password_reset_link, invitation_accept) — not just invitations. Mirrors
// remote_storage_invitations_test.go's #507 harness exactly: a real "upstream"
// exercised through the production NewRouter/handlers (including the new
// /api/v1/system/setup-tokens routes, server/http/handlers/setup_tokens_proxy.go),
// and a "downstream" *core.KeyorixCore configured with storage.type: remote pointed
// at "upstream" over real HTTP via store.RemoteStorage.
package http

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForSetupTokens builds the standard #452/#507/#510
// two-server harness: an "upstream" exercised through the REAL production
// NewRouter/handlers, and a "downstream" *core.KeyorixCore configured with
// storage.type: remote (ADR-049), pointed at "upstream" over real HTTP via
// store.RemoteStorage.
func newUpstreamDownstreamForSetupTokens(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createTestToken(t, upstream)

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

// buildActiveSetupToken mirrors what internal/core/setup_token.go's IssueSetupToken
// computes before calling storage.CreateSetupToken — a fully-built, active token
// with a 24h TTL — WITHOUT going through IssueSetupToken itself, so the
// storage-primitive tests below can exercise CreateSetupToken/GetSetupTokenByHash/
// MarkSetupTokenConsumed directly, independent of the higher-level core API.
func buildActiveSetupToken(now time.Time, tokenHash, purpose, email string) *models.SetupToken {
	return &models.SetupToken{
		TokenHash:    tokenHash,
		Purpose:      purpose,
		SubjectEmail: email,
		State:        core.SetupTokenActive,
		ExpiresAt:    now.Add(24 * time.Hour),
		CreatedAt:    now,
	}
}

// TestRemoteStorageSetupToken_CreateGetConsume_RealServer proves the #510 fix for
// CreateSetupToken/GetSetupTokenByHash/MarkSetupTokenConsumed: a setup token is
// genuinely persisted on the upstream server via the DOWNSTREAM's RemoteStorage,
// fetchable by hash, single-use-consumable, and a replay cleanly loses — all via
// storage.type: remote against a real router, not a protocol mock.
func TestRemoteStorageSetupToken_CreateGetConsume_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForSetupTokens(t)
	ctx := context.Background()
	now := time.Now()

	tok, err := downstream.Storage().CreateSetupToken(ctx,
		buildActiveSetupToken(now, "hash-create-get-consume", core.SetupPurposeAccountSetup, "newuser@example.com"))
	require.NoError(t, err, "creating a setup token must succeed via storage.type: remote")
	require.NotZero(t, tok.ID, "the upstream must assign a real ID")
	assert.Equal(t, core.SetupPurposeAccountSetup, tok.Purpose)
	assert.Equal(t, "newuser@example.com", tok.SubjectEmail)
	assert.Equal(t, core.SetupTokenActive, tok.State)
	assert.WithinDuration(t, now.Add(24*time.Hour), tok.ExpiresAt, time.Second)

	// Confirm it is a REAL row in the upstream's own storage (not just "the call
	// didn't error"), by reading it back directly against upstream.
	direct, err := upstream.Storage().GetSetupTokenByHash(ctx, "hash-create-get-consume")
	require.NoError(t, err)
	assert.Equal(t, tok.ID, direct.ID)

	// GetSetupTokenByHash via the downstream (RemoteStorage) round-trips every field.
	fetched, err := downstream.Storage().GetSetupTokenByHash(ctx, "hash-create-get-consume")
	require.NoError(t, err)
	assert.Equal(t, tok.ID, fetched.ID)
	assert.Equal(t, tok.Purpose, fetched.Purpose)
	assert.Equal(t, tok.SubjectEmail, fetched.SubjectEmail)
	assert.Equal(t, core.SetupTokenActive, fetched.State)

	// Consuming an active token via the downstream must succeed exactly once.
	consumedAt := time.Now()
	ok, err := downstream.Storage().MarkSetupTokenConsumed(ctx, tok.ID, consumedAt)
	require.NoError(t, err)
	assert.True(t, ok, "consuming an active token must succeed")

	// The upstream's own storage must show the real state transition.
	final, err := upstream.Storage().GetSetupTokenByHash(ctx, "hash-create-get-consume")
	require.NoError(t, err)
	assert.Equal(t, core.SetupTokenConsumed, final.State)
	require.NotNil(t, final.ConsumedAt)

	// A second consume attempt against the now-consumed token must cleanly report
	// false (not an error, not a silent double success) — the single-use guarantee.
	ok, err = downstream.Storage().MarkSetupTokenConsumed(ctx, tok.ID, time.Now())
	require.NoError(t, err)
	assert.False(t, ok, "consuming an already-consumed token must not report success")
}

// TestRemoteStorageSetupToken_GetByHashNotFound_RealServer proves a clean not-found
// error (not a panic, not a garbage 500) for an unknown hash.
func TestRemoteStorageSetupToken_GetByHashNotFound_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForSetupTokens(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetSetupTokenByHash(ctx, "nonexistent-hash-does-not-exist")
	require.Error(t, err)
}

// TestRemoteStorageSetupToken_Supersede_RealServer proves SupersedeActiveSetupTokens
// flips every active token for (purpose, email) to superseded — the atomic
// "resend kills the old link" guarantee IssueSetupToken relies on.
func TestRemoteStorageSetupToken_Supersede_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForSetupTokens(t)
	ctx := context.Background()
	now := time.Now()

	_, err := downstream.Storage().CreateSetupToken(ctx,
		buildActiveSetupToken(now, "hash-supersede-1", core.SetupPurposePasswordResetLink, "reset@example.com"))
	require.NoError(t, err)
	_, err = downstream.Storage().CreateSetupToken(ctx,
		buildActiveSetupToken(now, "hash-supersede-2", core.SetupPurposePasswordResetLink, "reset@example.com"))
	require.NoError(t, err)
	// A different email must NOT be affected.
	_, err = downstream.Storage().CreateSetupToken(ctx,
		buildActiveSetupToken(now, "hash-supersede-other", core.SetupPurposePasswordResetLink, "other@example.com"))
	require.NoError(t, err)

	require.NoError(t, downstream.Storage().SupersedeActiveSetupTokens(ctx, core.SetupPurposePasswordResetLink, "reset@example.com"))

	s1, err := upstream.Storage().GetSetupTokenByHash(ctx, "hash-supersede-1")
	require.NoError(t, err)
	assert.Equal(t, core.SetupTokenSuperseded, s1.State)

	s2, err := upstream.Storage().GetSetupTokenByHash(ctx, "hash-supersede-2")
	require.NoError(t, err)
	assert.Equal(t, core.SetupTokenSuperseded, s2.State)

	other, err := upstream.Storage().GetSetupTokenByHash(ctx, "hash-supersede-other")
	require.NoError(t, err)
	assert.Equal(t, core.SetupTokenActive, other.State, "a different subject's active token must be untouched")
}

// TestRemoteStorageSetupToken_Expire_RealServer proves MarkSetupTokenExpired's
// lazy-expiry transition round-trips over storage.type: remote.
func TestRemoteStorageSetupToken_Expire_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForSetupTokens(t)
	ctx := context.Background()
	now := time.Now()

	tok, err := downstream.Storage().CreateSetupToken(ctx,
		buildActiveSetupToken(now, "hash-expire", core.SetupPurposeAccountSetup, "expire@example.com"))
	require.NoError(t, err)

	require.NoError(t, downstream.Storage().MarkSetupTokenExpired(ctx, tok.ID))

	final, err := upstream.Storage().GetSetupTokenByHash(ctx, "hash-expire")
	require.NoError(t, err)
	assert.Equal(t, core.SetupTokenExpired, final.State)
}

// TestRemoteStorageSetupToken_CountSince_RealServer proves CountSetupTokensSince
// backs resend throttling/the daily cap correctly over storage.type: remote.
func TestRemoteStorageSetupToken_CountSince_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForSetupTokens(t)
	ctx := context.Background()
	now := time.Now()
	since := now.Add(-time.Hour)

	_, err := downstream.Storage().CreateSetupToken(ctx,
		buildActiveSetupToken(now, "hash-count-1", core.SetupPurposeAccountSetup, "count@example.com"))
	require.NoError(t, err)
	_, err = downstream.Storage().CreateSetupToken(ctx,
		buildActiveSetupToken(now, "hash-count-2", core.SetupPurposeAccountSetup, "count@example.com"))
	require.NoError(t, err)
	// A different purpose must not be counted.
	_, err = downstream.Storage().CreateSetupToken(ctx,
		buildActiveSetupToken(now, "hash-count-other-purpose", core.SetupPurposePasswordResetLink, "count@example.com"))
	require.NoError(t, err)

	n, err := downstream.Storage().CountSetupTokensSince(ctx, core.SetupPurposeAccountSetup, "count@example.com", since)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)

	// Before any token existed, the count from a future cutoff must be zero.
	n, err = downstream.Storage().CountSetupTokensSince(ctx, core.SetupPurposeAccountSetup, "count@example.com", now.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

// TestRemoteStorageSetupToken_ConcurrentConsumeRace_RealServer is the critical #510
// test: it fires N concurrent "consume" requests at the SAME active setup token
// over real HTTP against the real upstream router, and asserts EXACTLY ONE
// succeeds — proving ConsumeSetupTokenProxy's conditional
// `WHERE id = ? AND state = 'active'` write (local_auth.go, proxied unchanged by
// server/http/handlers/setup_tokens_proxy.go) still closes the double-consume
// TOCTOU race consumeInspectedToken (setup_token.go) depends on, even across a
// network hop — not a client-side "GET, check state, then mark" sequence, which
// would reopen exactly this race. Mirrors #507's
// TestRemoteStorageInvitation_ConcurrentAcceptRace_RealServer exactly.
func TestRemoteStorageSetupToken_ConcurrentConsumeRace_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForSetupTokens(t)
	ctx := context.Background()
	now := time.Now()

	tok, err := downstream.Storage().CreateSetupToken(ctx,
		buildActiveSetupToken(now, "hash-race", core.SetupPurposeAccountSetup, "race@example.com"))
	require.NoError(t, err)

	const n = 20
	var successCount atomic.Int64
	var errCount atomic.Int64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ok, err := downstream.Storage().MarkSetupTokenConsumed(ctx, tok.ID, time.Now())
			if err != nil {
				errCount.Add(1)
				return
			}
			if ok {
				successCount.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(0), errCount.Load(), "every concurrent consume attempt must get a clean result, not a transport/server error")
	assert.Equal(t, int64(1), successCount.Load(), "exactly one concurrent consume must win the race — the rest must cleanly lose, never a double consume")

	final, err := downstream.Storage().GetSetupTokenByHash(ctx, "hash-race")
	require.NoError(t, err)
	assert.Equal(t, core.SetupTokenConsumed, final.State)
}

// TestRemoteStorageSetupToken_CompleteSetupEndToEnd_RealServer is the actual
// user-facing flow #510 fixed: core.KeyorixCore.CompleteSetup, called against a
// DOWNSTREAM core backed entirely by storage.type: remote. Before this fix,
// CompleteSetup's very first step (inspectActiveSetupToken → GetSetupTokenByHash)
// hard-failed with "invalid setup token" for EVERY purpose, unconditionally.
//
// This proves inspectActiveSetupToken (GetSetupTokenByHash) and
// consumeInspectedToken (MarkSetupTokenConsumed) — the two #510 storage
// primitives on this call path — both now genuinely work end-to-end: CompleteSetup
// proceeds past both and only then fails at applyNewPassword's SetPasswordHash — a
// SEPARATE, pre-existing, deliberately-hard-failing gap (#484, documented in
// remote_users.go: password_hash is tagged json:"-" on models.User and can never
// cross RemoteStorage's wire format at all, so it fails loud rather than silently
// no-op). That gap is out of #510's scope, exactly as #507's test file left
// GetRoleByName's separate gap (#512) undisturbed. If #510 were still broken, this
// call would fail immediately at the setup-token lookup instead.
func TestRemoteStorageSetupToken_CompleteSetupEndToEnd_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForSetupTokens(t)
	ctx := context.Background()

	// A password_reset_link token acts on an EXISTING account (unlike account_setup,
	// which is more naturally paired with the admin-facing deliver_setup_link/
	// generate_one_time_password CreateUser flags — flags that RemoteStorage's own
	// CreateUser wire (remote_users.go's userCreateWireRequest) does not carry at
	// all, an orthogonal gap out of #510's scope), so the subject is created with an
	// ordinary initial password here, exactly as a real admin-created account would
	// have one before a self-service reset.
	user, err := downstream.Storage().CreateUser(ctx, &models.User{
		Username:    "newhire",
		Email:       "newhire@example.com",
		DisplayName: "New Hire",
		IsActive:    true,
	}, "Initial#Passw0rd!")
	require.NoError(t, err, "creating the subject account must succeed via storage.type: remote")

	issued, err := downstream.IssueSetupToken(ctx, core.IssueSetupTokenRequest{
		Purpose:       core.SetupPurposePasswordResetLink,
		SubjectEmail:  user.Email,
		SubjectUserID: &user.ID,
	})
	require.NoError(t, err, "issuing a setup token must succeed via storage.type: remote (#510: SupersedeActiveSetupTokens + CreateSetupToken)")
	require.NotEmpty(t, issued.PlainToken)

	_, err = downstream.CompleteSetup(ctx, issued.PlainToken, "Str0ngP@ssw0rd123!", "test-agent", "127.0.0.1")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "invalid setup token",
		"must NOT fail at the #510 setup-token lookup step — that is the bug this fix closes")
	assert.ErrorIs(t, err, corestorage.ErrUnsupportedByBackend,
		"must fail at the SEPARATE, already-documented #484 gap (SetPasswordHash), proving inspectActiveSetupToken + consumeInspectedToken both succeeded first")

	// Fail-closed design (setup_token.go's consumeInspectedToken comment): the token
	// is consumed BEFORE applyNewPassword runs, so even on this later failure it must
	// already show as genuinely, atomically consumed on the upstream — proving
	// MarkSetupTokenConsumed's write landed for real, not just "the call didn't error".
	final, err := upstream.Storage().GetSetupTokenByHash(ctx, issued.Token.TokenHash)
	require.NoError(t, err)
	assert.Equal(t, core.SetupTokenConsumed, final.State, "the token must be spent even though the password step failed afterward (fail-closed)")
}

// TestRemoteStorageSetupToken_CompleteSetupInvalidToken_RealServer proves that an
// unknown token cleanly fails CompleteSetup via storage.type: remote (the ordinary
// "bad link" case, not a transport error).
func TestRemoteStorageSetupToken_CompleteSetupInvalidToken_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForSetupTokens(t)
	ctx := context.Background()

	_, err := downstream.CompleteSetup(ctx, "kx_setup_totally-bogus-token", "Str0ngP@ssw0rd123!", "test-agent", "127.0.0.1")
	require.Error(t, err)
	assert.False(t, errors.Is(err, corestorage.ErrUnsupportedByBackend),
		"an unknown token must fail as 'not found', not be misreported as the unrelated #484 backend gap")
}
