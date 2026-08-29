// remote_storage_setup_tokens_test.go — end-to-end coverage for #510: RemoteStorage's
// SetupToken CRUD (CreateSetupToken/GetSetupTokenByHash/SupersedeActiveSetupTokens/
// MarkSetupTokenExpired/CountSetupTokensSince) was entirely stubbed, so
// CompleteSetup's very first step (inspectActiveSetupToken) hard-failed under
// storage.type: remote for EVERY setup-token purpose (account_setup,
// password_reset_link, invitation_accept) — not just invitations. Mirrors
// remote_storage_invitations_test.go's #507 harness exactly: a real "upstream"
// exercised through the production NewRouter/handlers (including the new
// /api/v1/system/setup-tokens routes, server/http/handlers/setup_tokens_proxy.go),
// and a "downstream" *core.KeyorixCore configured with storage.type: remote pointed
// at "upstream" over real HTTP via store.RemoteStorage.
//
// MarkSetupTokenConsumed/ConsumeSetupTokenProxy and their tests (including the
// CompleteSetup end-to-end flow and the concurrent-consume race, which
// exercised MarkSetupTokenConsumed as part of that flow) were DELETED (#1579
// liveness sweep, docs/adr-090-stale-fork-proxy-deletion.md's "#1579/#1580"
// addendum) — no live caller in either topology. This file's remaining tests
// only cover CreateSetupToken/GetSetupTokenByHash/SupersedeActiveSetupTokens/
// MarkSetupTokenExpired/CountSetupTokensSince, all still real.
package http

import (
	"context"
	"errors"
	"net/http/httptest"
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
// storage-primitive tests below can exercise CreateSetupToken/GetSetupTokenByHash
// directly, independent of the higher-level core API.
//
// Deliberately does NOT set SubjectUserID or InvitationID: CreateSetupTokenProxy
// (#G79, server/http/handlers/setup_tokens_proxy.go) requires exactly one of them,
// depending on purpose, referencing a real row whose email matches SubjectEmail —
// every caller below sets the appropriate one on the returned token before passing
// it to CreateSetupToken. invitation_accept callers already do this (set
// InvitationID); account_setup/password_reset_link callers must set SubjectUserID
// via createSetupTokenSubjectUser.
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

// createSetupTokenSubjectUser creates a real user with the given email on upstream
// and returns its ID, for a buildActiveSetupToken caller to set as SubjectUserID —
// CreateSetupTokenProxy requires it to reference a real user whose email matches
// the token's SubjectEmail exactly (case-insensitive).
func createSetupTokenSubjectUser(t *testing.T, upstream *core.KeyorixCore, email string) uint {
	t.Helper()
	user, err := upstream.Storage().CreateUser(context.Background(), &models.User{
		Username: "setup-subject-" + email, Email: email,
	}, "TestPassword123!")
	require.NoError(t, err)
	return user.ID
}

// TestRemoteStorageSetupToken_CreateGet_RealServer proves the #510 fix for
// CreateSetupToken/GetSetupTokenByHash: a setup token is genuinely persisted
// on the upstream server via the DOWNSTREAM's RemoteStorage, fetchable by
// hash, via storage.type: remote against a real router, not a protocol mock.
func TestRemoteStorageSetupToken_CreateGet_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForSetupTokens(t)
	ctx := context.Background()
	now := time.Now()

	subjectID := createSetupTokenSubjectUser(t, upstream, "newuser@example.com")
	newToken := buildActiveSetupToken(now, "hash-create-get", core.SetupPurposeAccountSetup, "newuser@example.com")
	newToken.SubjectUserID = &subjectID
	tok, err := downstream.Storage().CreateSetupToken(ctx, newToken)
	require.NoError(t, err, "creating a setup token must succeed via storage.type: remote")
	require.NotZero(t, tok.ID, "the upstream must assign a real ID")
	assert.Equal(t, core.SetupPurposeAccountSetup, tok.Purpose)
	assert.Equal(t, "newuser@example.com", tok.SubjectEmail)
	assert.Equal(t, core.SetupTokenActive, tok.State)
	assert.WithinDuration(t, now.Add(24*time.Hour), tok.ExpiresAt, time.Second)

	// Confirm it is a REAL row in the upstream's own storage (not just "the call
	// didn't error"), by reading it back directly against upstream.
	direct, err := upstream.Storage().GetSetupTokenByHash(ctx, "hash-create-get")
	require.NoError(t, err)
	assert.Equal(t, tok.ID, direct.ID)

	// GetSetupTokenByHash via the downstream (RemoteStorage) round-trips every field.
	fetched, err := downstream.Storage().GetSetupTokenByHash(ctx, "hash-create-get")
	require.NoError(t, err)
	assert.Equal(t, tok.ID, fetched.ID)
	assert.Equal(t, tok.Purpose, fetched.Purpose)
	assert.Equal(t, tok.SubjectEmail, fetched.SubjectEmail)
	assert.Equal(t, core.SetupTokenActive, fetched.State)
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

	resetSubjectID := createSetupTokenSubjectUser(t, upstream, "reset@example.com")
	otherSubjectID := createSetupTokenSubjectUser(t, upstream, "other@example.com")

	tok1 := buildActiveSetupToken(now, "hash-supersede-1", core.SetupPurposePasswordResetLink, "reset@example.com")
	tok1.SubjectUserID = &resetSubjectID
	_, err := downstream.Storage().CreateSetupToken(ctx, tok1)
	require.NoError(t, err)
	tok2 := buildActiveSetupToken(now, "hash-supersede-2", core.SetupPurposePasswordResetLink, "reset@example.com")
	tok2.SubjectUserID = &resetSubjectID
	_, err = downstream.Storage().CreateSetupToken(ctx, tok2)
	require.NoError(t, err)
	// A different email must NOT be affected.
	tokOther := buildActiveSetupToken(now, "hash-supersede-other", core.SetupPurposePasswordResetLink, "other@example.com")
	tokOther.SubjectUserID = &otherSubjectID
	_, err = downstream.Storage().CreateSetupToken(ctx, tokOther)
	require.NoError(t, err)

	require.NoError(t, downstream.Storage().SupersedeActiveSetupTokens(ctx, core.SetupPurposePasswordResetLink, "reset@example.com", nil))

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

// TestRemoteStorageSetupToken_SupersedeProjectScoped_RealServer is the
// CORE-INVITATIONS-003 end-to-end regression: over storage.type: remote, a
// project-scoped supersede (as InviteToProjectWithLink/ResendInvitationLink now
// issue) must not cross the HTTP hop as an unscoped one — an unrelated project's
// invite must not invalidate a different project's still-pending invite to the same
// email, while a same-project reissue still supersedes.
func TestRemoteStorageSetupToken_SupersedeProjectScoped_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForSetupTokens(t)
	ctx := context.Background()
	now := time.Now()
	const email = "victim@example.com"

	invA, err := upstream.Storage().CreateProjectInvitation(ctx, &models.ProjectInvitation{
		ProjectID: 101, Email: email, Role: "project_developer", State: core.InvitationPending,
	})
	require.NoError(t, err)
	invB, err := upstream.Storage().CreateProjectInvitation(ctx, &models.ProjectInvitation{
		ProjectID: 202, Email: email, Role: "project_viewer", State: core.InvitationPending,
	})
	require.NoError(t, err)

	tokA := buildActiveSetupToken(now, "hash-proj-a-1", core.SetupPurposeInvitationAccept, email)
	tokA.InvitationID = &invA.ID
	_, err = downstream.Storage().CreateSetupToken(ctx, tokA)
	require.NoError(t, err)

	// Project B's admin invites the same email to project B — the pre-issuance
	// supersede is scoped to project B only.
	projectB := invB.ProjectID
	require.NoError(t, downstream.Storage().SupersedeActiveSetupTokens(ctx, core.SetupPurposeInvitationAccept, email, &projectB))
	tokB := buildActiveSetupToken(now, "hash-proj-b-1", core.SetupPurposeInvitationAccept, email)
	tokB.InvitationID = &invB.ID
	_, err = downstream.Storage().CreateSetupToken(ctx, tokB)
	require.NoError(t, err)

	sA, err := upstream.Storage().GetSetupTokenByHash(ctx, "hash-proj-a-1")
	require.NoError(t, err)
	assert.Equal(t, core.SetupTokenActive, sA.State, "project B's invite must not supersede project A's pending link")

	sB1, err := upstream.Storage().GetSetupTokenByHash(ctx, "hash-proj-b-1")
	require.NoError(t, err)
	assert.Equal(t, core.SetupTokenActive, sB1.State)

	// A same-project (B) reissue must still supersede project B's own prior link.
	require.NoError(t, downstream.Storage().SupersedeActiveSetupTokens(ctx, core.SetupPurposeInvitationAccept, email, &projectB))
	tokB2 := buildActiveSetupToken(now, "hash-proj-b-2", core.SetupPurposeInvitationAccept, email)
	tokB2.InvitationID = &invB.ID
	_, err = downstream.Storage().CreateSetupToken(ctx, tokB2)
	require.NoError(t, err)

	sB1Reloaded, err := upstream.Storage().GetSetupTokenByHash(ctx, "hash-proj-b-1")
	require.NoError(t, err)
	assert.Equal(t, core.SetupTokenSuperseded, sB1Reloaded.State, "a same-project reissue must still supersede the project's own prior link")

	sB2, err := upstream.Storage().GetSetupTokenByHash(ctx, "hash-proj-b-2")
	require.NoError(t, err)
	assert.Equal(t, core.SetupTokenActive, sB2.State)

	sAFinal, err := upstream.Storage().GetSetupTokenByHash(ctx, "hash-proj-a-1")
	require.NoError(t, err)
	assert.Equal(t, core.SetupTokenActive, sAFinal.State, "project A's link must remain untouched throughout")
}

// TestRemoteStorageSetupToken_Expire_RealServer proves MarkSetupTokenExpired's
// lazy-expiry transition round-trips over storage.type: remote.
func TestRemoteStorageSetupToken_Expire_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForSetupTokens(t)
	ctx := context.Background()
	now := time.Now()

	subjectID := createSetupTokenSubjectUser(t, upstream, "expire@example.com")
	expireToken := buildActiveSetupToken(now, "hash-expire", core.SetupPurposeAccountSetup, "expire@example.com")
	expireToken.SubjectUserID = &subjectID
	tok, err := downstream.Storage().CreateSetupToken(ctx, expireToken)
	require.NoError(t, err)

	require.NoError(t, downstream.Storage().MarkSetupTokenExpired(ctx, tok.ID))

	final, err := upstream.Storage().GetSetupTokenByHash(ctx, "hash-expire")
	require.NoError(t, err)
	assert.Equal(t, core.SetupTokenExpired, final.State)
}

// TestRemoteStorageSetupToken_CountSince_RealServer proves CountSetupTokensSince
// backs resend throttling/the daily cap correctly over storage.type: remote.
func TestRemoteStorageSetupToken_CountSince_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForSetupTokens(t)
	ctx := context.Background()
	now := time.Now()
	since := now.Add(-time.Hour)

	subjectID := createSetupTokenSubjectUser(t, upstream, "count@example.com")

	tok1 := buildActiveSetupToken(now, "hash-count-1", core.SetupPurposeAccountSetup, "count@example.com")
	tok1.SubjectUserID = &subjectID
	_, err := downstream.Storage().CreateSetupToken(ctx, tok1)
	require.NoError(t, err)
	tok2 := buildActiveSetupToken(now, "hash-count-2", core.SetupPurposeAccountSetup, "count@example.com")
	tok2.SubjectUserID = &subjectID
	_, err = downstream.Storage().CreateSetupToken(ctx, tok2)
	require.NoError(t, err)
	// A different purpose must not be counted.
	tokOtherPurpose := buildActiveSetupToken(now, "hash-count-other-purpose", core.SetupPurposePasswordResetLink, "count@example.com")
	tokOtherPurpose.SubjectUserID = &subjectID
	_, err = downstream.Storage().CreateSetupToken(ctx, tokOtherPurpose)
	require.NoError(t, err)

	n, err := downstream.Storage().CountSetupTokensSince(ctx, core.SetupPurposeAccountSetup, "count@example.com", since)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)

	// Before any token existed, the count from a future cutoff must be zero.
	n, err = downstream.Storage().CountSetupTokensSince(ctx, core.SetupPurposeAccountSetup, "count@example.com", now.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

// TestRemoteStorageSetupToken_ConcurrentConsumeRace_RealServer and
// TestRemoteStorageSetupToken_CompleteSetupEndToEnd_RealServer (which proved
// MarkSetupTokenConsumed's wire behavior, standalone and as part of
// CompleteSetup respectively) were DELETED (#1579 liveness sweep) — no real
// production caller ever constructs a RemoteStorage-backed core and calls
// CompleteSetup/ConsumeSetupToken (a test harness doing so directly does not
// establish that; see docs/adr-090-stale-fork-proxy-deletion.md's
// "#1579/#1580" addendum). MarkSetupTokenConsumed is now a hard stub
// (internal/storage/store/remote_auth_test.go's
// TestRemoteStorage_MarkSetupTokenConsumed_Unsupported covers it directly).

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
