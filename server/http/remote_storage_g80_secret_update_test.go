// remote_storage_g80_secret_update_test.go — end-to-end coverage for G80 Phase 0's
// default-deny diff (server/http/handlers/secret_update_diff.go), against a REAL
// upstream server (NewRouter, not a mock).
//
// The PRIMARY, exhaustive test for this fix is
// server/http/handlers/secret_update_diff_test.go — it operates at the storage-interface
// contract level (every models.SecretNode field, reflection-driven) and needs no HTTP
// server. This file is a smaller set of true end-to-end checks layered on top, split into
// two kinds:
//
//  1. TestG80Phase0_StorageInterface_* drive store.RemoteStorage.UpdateSecret directly —
//     the actual contract this fix changes — with a hand-mutated *models.SecretNode
//     matching exactly what an internal/core call site would send, bypassing
//     internal/core's own permission-check layer entirely (that layer is a separate
//     concern; several internal/core functions are additionally blocked against
//     RemoteStorage by the pre-existing, separately-tracked
//     https://github.com/keyorixhq/keyorix/issues/1512, which has nothing to do with
//     this fix — testing through those functions would conflate the two).
//
//  2. TestG80Phase0_ClassifySecret_* / TestG80Phase0_SetSecretAutoRotate_* drive the
//     real internal/core call sites for the two operations that have no internal
//     permission check of their own (so they aren't blocked by #1512) — ClassifySecret
//     and SetSecretAutoRotate. These guard the contract for FUTURE callers of these
//     functions against RemoteStorage, not a live bug: grepping the whole tree found no
//     current CLI command that reaches either function through RemoteStorage today (see
//     the PR description's severity correction) — every CLI command for classification,
//     ownership transfer, move, rename, and rotation config uses its own direct
//     common.RemoteClient REST call, a separate code path unaffected by this fix. The
//     only currently-reachable path through the OLD, narrower secretUpdateWireRequest was
//     internal/cli/secret/update.go's embedded+storage.type:remote fallback (Type/
//     MaxReads/Expiration/Metadata, now also Description).
package http

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForSecretUpdate mirrors newUpstreamDownstreamForGroups
// (remote_storage_groups_test.go) for the ordinary (non-/system/) secrets API: an
// "upstream" exercised through the REAL production router, and a "downstream"
// *core.KeyorixCore backed by store.RemoteStorage pointed at it over real HTTP, using
// an ordinary authenticated session token (createTestToken) — PUT /api/v1/secrets/{id}
// is gated on plain secrets.write, not the /system/* node-credential tier.
func newUpstreamDownstreamForSecretUpdate(t *testing.T) (upstream, downstream *core.KeyorixCore, actorID uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createTestToken(t, upstream)

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"}}}
	upstreamRouter, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	t.Cleanup(upstreamSrv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: upstreamSrv.URL, APIKey: upstreamToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)
	downstream = core.NewKeyorixCore(rs)

	admin, err := upstream.Storage().GetUserByUsername(context.Background(), "testadmin")
	require.NoError(t, err)
	return upstream, downstream, admin.ID
}

// seedSecretForUpdateTest creates a project/environment/secret directly against the
// upstream's own storage (bypassing the wire for setup, mirroring the #452/#794/#496
// e2e tests' own convention) and returns it.
func seedSecretForUpdateTest(t *testing.T, upstream *core.KeyorixCore, ownerID uint) *models.SecretNode {
	t.Helper()
	ctx := context.Background()
	project, err := upstream.CreateProject(ctx, "g80-project", "seeded for G80 Phase 0's e2e test")
	require.NoError(t, err)
	envs, err := upstream.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	secret := &models.SecretNode{
		Name: "g80-secret", ProjectID: project.ID, EnvironmentID: envs[0].ID,
		IsSecret: true, Type: "generic", OwnerID: ownerID,
	}
	created, err := upstream.Storage().CreateSecret(ctx, secret, "s3cr3t-v4lu3")
	require.NoError(t, err)
	return created
}

// countAuditEvents returns the number of AuditEvent rows on upstream matching eventType
// — used to prove a rejected update writes NO audit event (the audit-trail divergence
// finding from G80's Step 1 report: before this fix, these events fired unconditionally
// after a silently-dropped write).
func countAuditEvents(t *testing.T, upstream *core.KeyorixCore, eventType string) int64 {
	t.Helper()
	action := eventType
	_, total, err := upstream.Storage().GetAuditLogs(context.Background(), &storage.AuditFilter{
		Action: &action, Page: 1, PageSize: 1000,
	})
	require.NoError(t, err)
	return total
}

// TestG80Phase0_StorageInterface_AllowedFieldRoundTrips drives store.RemoteStorage.
// UpdateSecret directly (the actual contract this fix changes) for an allowed field,
// end-to-end against a real hub — proving the happy path genuinely persists, not just
// that gated fields are rejected.
func TestG80Phase0_StorageInterface_AllowedFieldRoundTrips(t *testing.T) {
	upstream, downstream, actorID := newUpstreamDownstreamForSecretUpdate(t)
	secret := seedSecretForUpdateTest(t, upstream, actorID)
	ctx := context.Background()

	desired, err := downstream.Storage().GetSecret(ctx, secret.ID)
	require.NoError(t, err)
	desired.Description = "a real description"

	updated, err := downstream.Storage().UpdateSecret(ctx, desired)
	require.NoError(t, err)
	require.Equal(t, "a real description", updated.Description)

	reloaded, gerr := upstream.Storage().GetSecret(ctx, secret.ID)
	require.NoError(t, gerr)
	require.Equal(t, "a real description", reloaded.Description,
		"the upstream's authoritative row must genuinely carry the new description")
}

// TestG80Phase0_StorageInterface_RejectedFieldsFailLoudly drives store.RemoteStorage.
// UpdateSecret directly with each of the security-gated fields mutated, one at a time —
// exactly what TransferSecretOwnership/MoveSecret/ClassifySecret/BulkRenameSecrets/
// SetSecretAutoRotate would send onto the wire — and proves each is refused, not
// silently dropped, with the upstream's authoritative row left unchanged.
func TestG80Phase0_StorageInterface_RejectedFieldsFailLoudly(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(s *models.SecretNode)
		unmodified func(s *models.SecretNode) bool
	}{
		{"OwnerID", func(s *models.SecretNode) { s.OwnerID = 999 }, func(s *models.SecretNode) bool { return s.OwnerID != 999 }},
		{"ParentID", func(s *models.SecretNode) { id := uint(1); s.ParentID = &id }, func(s *models.SecretNode) bool { return s.ParentID == nil }},
		{"Name", func(s *models.SecretNode) { s.Name = "renamed" }, func(s *models.SecretNode) bool { return s.Name == "g80-secret" }},
		{"Classification", func(s *models.SecretNode) { s.Classification = "restricted" }, func(s *models.SecretNode) bool { return s.Classification == "" }},
		{"AutoRotate", func(s *models.SecretNode) { s.AutoRotate = true }, func(s *models.SecretNode) bool { return !s.AutoRotate }},
		{"RotationBackend", func(s *models.SecretNode) { s.RotationBackend = "aws-kms"; s.RotationRef = "ref" }, func(s *models.SecretNode) bool { return s.RotationBackend == "" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream, downstream, actorID := newUpstreamDownstreamForSecretUpdate(t)
			secret := seedSecretForUpdateTest(t, upstream, actorID)
			ctx := context.Background()

			desired, err := downstream.Storage().GetSecret(ctx, secret.ID)
			require.NoError(t, err)
			tc.mutate(desired)

			_, err = downstream.Storage().UpdateSecret(ctx, desired)
			require.ErrorContains(t, err, "cannot update field",
				"must fail via the G80 default-deny diff specifically, not some unrelated error")

			reloaded, gerr := upstream.Storage().GetSecret(ctx, secret.ID)
			require.NoError(t, gerr)
			require.True(t, tc.unmodified(reloaded), "the upstream's authoritative row must be unchanged")
		})
	}
}

// TestG80Phase0_ClassifySecret_RejectedInConnectedMode guards the storage.Storage
// contract for a future caller of ClassifySecret against RemoteStorage — not a
// currently-live bug (see this file's doc comment). ClassifySecret has no internal
// permission check of its own, so unlike TransferSecretOwnership/MoveSecret/
// BulkRenameSecrets/SetSecretDescription it isn't blocked by #1512, and can be driven
// through the real call site end-to-end. Also proves the audit-trail divergence fix:
// no event fires for a change that was refused.
func TestG80Phase0_ClassifySecret_RejectedInConnectedMode(t *testing.T) {
	upstream, downstream, actorID := newUpstreamDownstreamForSecretUpdate(t)
	secret := seedSecretForUpdateTest(t, upstream, actorID)
	ctx := context.Background()

	before := countAuditEvents(t, upstream, "secret.updated")

	_, err := downstream.ClassifySecret(ctx, actorID, "testadmin", secret.ID, "confidential")
	require.ErrorContains(t, err, "cannot update field",
		"must fail via the G80 default-deny diff specifically, not some unrelated error")

	reloaded, gerr := upstream.Storage().GetSecret(ctx, secret.ID)
	require.NoError(t, gerr)
	require.Empty(t, reloaded.Classification, "the upstream's authoritative row must be unchanged")

	after := countAuditEvents(t, upstream, "secret.updated")
	require.Equal(t, before, after, "a rejected classification change must write NO audit event — "+
		"see G80's audit-trail-divergence finding")
}

// TestG80Phase0_SetSecretAutoRotate_RejectedInConnectedMode guards the storage.Storage
// contract for a future caller of SetSecretAutoRotate against RemoteStorage — not a
// currently-live bug (see this file's doc comment). Like ClassifySecret, it has no
// internal permission check of its own, so it isn't blocked by #1512.
func TestG80Phase0_SetSecretAutoRotate_RejectedInConnectedMode(t *testing.T) {
	upstream, downstream, actorID := newUpstreamDownstreamForSecretUpdate(t)
	secret := seedSecretForUpdateTest(t, upstream, actorID)
	ctx := context.Background()

	before := countAuditEvents(t, upstream, core.EventSecretAutoRotateConfig)

	err := downstream.SetSecretAutoRotate(ctx, secret.ID, core.AutoRotateSpec{Enabled: true, Length: 32}, actorID)
	require.ErrorContains(t, err, "cannot update field",
		"must fail via the G80 default-deny diff specifically, not some unrelated error")

	reloaded, gerr := upstream.Storage().GetSecret(ctx, secret.ID)
	require.NoError(t, gerr)
	require.False(t, reloaded.AutoRotate, "the upstream's authoritative row must be unchanged")

	after := countAuditEvents(t, upstream, core.EventSecretAutoRotateConfig)
	require.Equal(t, before, after, "a rejected auto-rotate config change must write NO audit event")
}
