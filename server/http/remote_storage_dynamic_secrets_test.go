package http

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForDynamicSecrets builds the standard #452/#507-style
// two-server harness: an "upstream" exercised through the REAL production
// NewRouter/handlers (including the new /api/v1/system/dynamic-secrets routes,
// server/http/handlers/dynamic_secrets_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote (ADR-049), pointed at
// "upstream" over real HTTP via store.RemoteStorage.
func newUpstreamDownstreamForDynamicSecrets(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore, projectID, environmentID uint) {
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

	ctx := context.Background()
	project, err := upstream.CreateProject(ctx, "Dynamic Secrets Test Project", "")
	require.NoError(t, err)
	// CreateProject auto-seeds default environments (e.g. "production"); reuse one
	// rather than creating a new one, which would collide on the (project_id, name)
	// unique index.
	envs, err := upstream.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs, "CreateProject must seed at least one default environment")
	return upstream, downstream, project.ID, envs[0].ID
}

// buildDynamicSecretConfig mirrors what internal/core.CreateDynamicSecretConfig
// computes before calling storage.CreateDynamicSecretConfig — a fully-built config
// row (metadata only, no admin-DSN ciphertext yet, mirroring the #94 two-phase
// create-then-update) — WITHOUT going through CreateDynamicSecretConfig itself
// (which additionally requires an admin-authority RBAC check whose own storage
// primitives — role resolution — are a separate, pre-existing gap independent of
// this finding, exactly the same class of out-of-scope prerequisite
// remote_storage_invitations_test.go's buildPendingInvitation documents for
// GetRoleByName).
func buildDynamicSecretConfig(now time.Time, projectID, environmentID uint, name string) *models.DynamicSecretConfig {
	return &models.DynamicSecretConfig{
		Name:              name,
		ProjectID:         projectID,
		EnvironmentID:     environmentID,
		BackendType:       "postgres",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600,
		MaxTTLSeconds:     86400,
		MaxActiveLeases:   5,
		CreatedBy:         "alice",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

// TestRemoteStorageDynamicSecrets_ConfigCreateGetList_RealServer proves the fix
// for CreateDynamicSecretConfig/GetDynamicSecretConfig/ListDynamicSecretConfigs:
// a config is genuinely persisted on the upstream server via the DOWNSTREAM's
// RemoteStorage, fetchable by ID, and listed — all via storage.type: remote
// against a real router, not a protocol mock. The classification update
// (formerly also exercised here) is applied directly against the upstream's
// real storage (UpdateDynamicSecretConfigProxy was deleted -- G80 liveness
// sweep found no live caller; see docs/g80-remediation-notes.md).
func TestRemoteStorageDynamicSecrets_ConfigCreateGetList_RealServer(t *testing.T) {
	upstream, downstream, projectID, environmentID := newUpstreamDownstreamForDynamicSecrets(t)
	ctx := context.Background()
	now := time.Now()

	cfg, err := downstream.Storage().CreateDynamicSecretConfig(ctx, buildDynamicSecretConfig(now, projectID, environmentID, "app-db"))
	require.NoError(t, err, "creating a dynamic-secret config must succeed via storage.type: remote")
	require.NotZero(t, cfg.ID, "the upstream must assign a real ID")
	assert.Equal(t, "app-db", cfg.Name)
	assert.Equal(t, "postgres", cfg.BackendType)
	assert.Equal(t, projectID, cfg.ProjectID)
	assert.Equal(t, environmentID, cfg.EnvironmentID)

	// Confirm it is a REAL row in the upstream's own storage (not just "the call
	// didn't error"), by reading it back directly against upstream.
	direct, err := upstream.Storage().GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	assert.Equal(t, "app-db", direct.Name)

	// GetDynamicSecretConfig via the downstream (RemoteStorage) round-trips every
	// field correctly.
	fetched, err := downstream.Storage().GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	assert.Equal(t, cfg.ID, fetched.ID)
	assert.Equal(t, cfg.Name, fetched.Name)
	assert.Equal(t, cfg.CreationTemplate, fetched.CreationTemplate)
	assert.Equal(t, cfg.MaxTTLSeconds, fetched.MaxTTLSeconds)
	assert.Equal(t, cfg.MaxActiveLeases, fetched.MaxActiveLeases)

	// A second config, then list both back via the downstream's ListDynamicSecretConfigs.
	_, err = downstream.Storage().CreateDynamicSecretConfig(ctx, buildDynamicSecretConfig(now, projectID, environmentID, "cache-db"))
	require.NoError(t, err)

	rows, err := downstream.Storage().ListDynamicSecretConfigs(ctx, projectID, environmentID)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	names := map[string]bool{}
	for _, r := range rows {
		names[r.Name] = true
	}
	assert.True(t, names["app-db"])
	assert.True(t, names["cache-db"])

	// A classification change applied directly against the upstream's storage
	// is visible via GetDynamicSecretConfig/CountDynamicSecretConfigsByClassification
	// through the downstream.
	fetched.Classification = "confidential"
	require.NoError(t, upstream.Storage().UpdateDynamicSecretConfig(ctx, fetched))
	reFetched, err := upstream.Storage().GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	assert.Equal(t, "confidential", reFetched.Classification, "the update must be visible directly on the upstream's own storage")

	// CountDynamicSecretConfigsByClassification via the downstream.
	counts, err := downstream.Storage().CountDynamicSecretConfigsByClassification(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, counts["confidential"])
}

// TestRemoteStorageDynamicSecrets_GetConfigNotFound_RealServer proves a clean
// not-found error (not a panic, not a garbage 500) for a nonexistent config ID.
func TestRemoteStorageDynamicSecrets_GetConfigNotFound_RealServer(t *testing.T) {
	_, downstream, _, _ := newUpstreamDownstreamForDynamicSecrets(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetDynamicSecretConfig(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageDynamicSecrets_AdminDSNRoundTripsViaGet_RealServer is the
// sensitive-data-boundary test for this finding: it encrypts an admin DSN with
// a LOCAL encryption service (standing in for the downstream server's own
// encryptAuthSecret, exactly as internal/core.CreateDynamicSecretConfig does
// before ever calling storage.CreateDynamicSecretConfig/UpdateDynamicSecretConfig),
// persists ONLY the resulting ciphertext directly against the upstream's real
// storage (UpdateDynamicSecretConfigProxy was deleted -- G80 liveness sweep
// found no live caller; see docs/g80-remediation-notes.md — so this write no
// longer crosses the wire), and proves fetching the config back via the
// DOWNSTREAM's RemoteStorage and decrypting with the SAME encryption service
// reproduces the exact original plaintext: the ciphertext round-trips through
// the GET HTTP hop byte-for-byte (encoding/json base64 for []byte fields),
// unmodified.
func TestRemoteStorageDynamicSecrets_AdminDSNRoundTripsViaGet_RealServer(t *testing.T) {
	upstream, downstream, projectID, environmentID := newUpstreamDownstreamForDynamicSecrets(t)
	ctx := context.Background()
	now := time.Now()

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	const adminDSNPlain = "postgres://admin:s3cr3t@db.internal:5432/app"

	// Phase 1 (mirrors #94): create the row with no DSN ciphertext yet — cfg.ID
	// isn't known until the row exists, and the AAD binds to it.
	cfg, err := downstream.Storage().CreateDynamicSecretConfig(ctx, buildDynamicSecretConfig(now, projectID, environmentID, "sensitive-db"))
	require.NoError(t, err)

	// Phase 2: encrypt LOCALLY (standing in for the downstream server's own
	// encryptAuthSecret) and persist only the ciphertext, directly against the
	// upstream's storage.
	ct, meta, err := enc.EncryptSecretWithAAD([]byte(adminDSNPlain), encryption.DynamicSecretConfigAAD(cfg.ID, projectID, environmentID))
	require.NoError(t, err)
	require.NotEqual(t, adminDSNPlain, string(ct), "the encrypted bytes must not equal the plaintext")
	cfg.AdminDSNEnc = ct
	cfg.AdminDSNMeta = meta
	require.NoError(t, upstream.Storage().UpdateDynamicSecretConfig(ctx, cfg))

	// The upstream's OWN storage never holds the plaintext DSN anywhere in the
	// row — only the ciphertext this test encrypted itself.
	direct, err := upstream.Storage().GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	assert.NotContains(t, string(direct.AdminDSNEnc), "s3cr3t", "the upstream must never hold the plaintext admin DSN")
	assert.Equal(t, ct, direct.AdminDSNEnc, "the upstream stores the exact ciphertext bytes it was given, unmodified")

	// Fetching back through the downstream's RemoteStorage and decrypting with
	// the SAME encryption service reproduces the original plaintext exactly —
	// the ciphertext round-trips through the GET HTTP hop intact.
	fetched, err := downstream.Storage().GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	plain, err := enc.DecryptSecretWithAAD(fetched.AdminDSNEnc, encryption.DynamicSecretConfigAAD(cfg.ID, projectID, environmentID))
	require.NoError(t, err)
	assert.Equal(t, adminDSNPlain, string(plain), "decrypting the round-tripped ciphertext must reproduce the original admin DSN")
}

// buildDynamicSecretLease mirrors what internal/core.IssueLease computes before
// calling storage.CreateDynamicSecretLease — an already-minted, already-encrypted
// lease row (the credential ciphertext here is a placeholder standing in for a
// real engine.Issue result + encryptAuthSecret call, since minting against a real
// target and the full IssueLease business-logic path are out of this finding's
// storage-primitive scope, mirroring buildDynamicSecretConfig's docs above).
func buildDynamicSecretLease(now time.Time, configID, projectID, environmentID uint, leaseID string) *models.DynamicSecretLease {
	return &models.DynamicSecretLease{
		ConfigID:      configID,
		LeaseID:       leaseID,
		ProjectID:     projectID,
		EnvironmentID: environmentID,
		RoleName:      "kx_lease_" + leaseID,
		Status:        "active",
		IssuedAt:      now,
		ExpiresAt:     now.Add(time.Hour),
	}
}

// TestRemoteStorageDynamicSecrets_LeaseGetListCount_RealServer proves the fix
// for GetDynamicSecretLease/ListDynamicSecretLeases/CountActiveLeases: leases
// seeded directly against the upstream's real storage
// (CreateDynamicSecretLeaseProxy/UpdateDynamicSecretLeaseProxy were deleted --
// G80 liveness sweep found no live caller for either; see
// docs/g80-remediation-notes.md) are fetchable by their opaque LeaseID,
// listed/counted, and a status transition (revoke) applied directly against
// the upstream is visible via the same queries — all via storage.type: remote
// against a real router.
func TestRemoteStorageDynamicSecrets_LeaseGetListCount_RealServer(t *testing.T) {
	upstream, downstream, projectID, environmentID := newUpstreamDownstreamForDynamicSecrets(t)
	ctx := context.Background()
	now := time.Now()

	cfg, err := downstream.Storage().CreateDynamicSecretConfig(ctx, buildDynamicSecretConfig(now, projectID, environmentID, "lease-test-db"))
	require.NoError(t, err)

	lease, err := upstream.Storage().CreateDynamicSecretLease(ctx, buildDynamicSecretLease(now, cfg.ID, projectID, environmentID, "lease-abc-123"))
	require.NoError(t, err)
	require.NotZero(t, lease.ID)

	// GetDynamicSecretLease/ListDynamicSecretLeases/CountActiveLeases via the downstream.
	fetched, err := downstream.Storage().GetDynamicSecretLease(ctx, "lease-abc-123")
	require.NoError(t, err)
	assert.Equal(t, lease.RoleName, fetched.RoleName)
	assert.Equal(t, "active", fetched.Status)

	_, err = upstream.Storage().CreateDynamicSecretLease(ctx, buildDynamicSecretLease(now, cfg.ID, projectID, environmentID, "lease-def-456"))
	require.NoError(t, err)

	leases, err := downstream.Storage().ListDynamicSecretLeases(ctx, cfg.ID)
	require.NoError(t, err)
	require.Len(t, leases, 2)

	active, err := downstream.Storage().CountActiveLeases(ctx, cfg.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), active)

	// Revoke one lease directly against the upstream's storage. Re-verify
	// directly against the upstream, not through the SAME downstream client
	// used above: the client caches successful GET responses for 5 minutes,
	// invalidated only by a MUTATION that goes through that SAME client
	// (internal/storage/remote/client.go) — since the revoke below is applied
	// directly against the upstream (bypassing the downstream client
	// entirely), the shared "downstream" client's already-cached
	// GetDynamicSecretLease/CountActiveLeases responses would otherwise be
	// served stale here. The downstream wire path for these two reads was
	// already proven above (the pre-revoke fetched/active calls).
	fetched.Status = "revoked"
	revokedAt := time.Now()
	fetched.RevokedAt = &revokedAt
	fetched.RevokeReason = "manual"
	require.NoError(t, upstream.Storage().UpdateDynamicSecretLease(ctx, fetched))

	reFetched, err := upstream.Storage().GetDynamicSecretLease(ctx, "lease-abc-123")
	require.NoError(t, err)
	assert.Equal(t, "revoked", reFetched.Status)
	assert.Equal(t, "manual", reFetched.RevokeReason)
	require.NotNil(t, reFetched.RevokedAt)

	// The active count now reflects only the still-active second lease.
	activeAfter, err := upstream.Storage().CountActiveLeases(ctx, cfg.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), activeAfter)
}

// TestRemoteStorageDynamicSecrets_ListExpiredActiveLeases_RealServer proves the
// fix for ListExpiredActiveLeases, which backs the calling server's own
// auto-revoke sweep (internal/core.RevokeExpiredLeases) against a real upstream.
func TestRemoteStorageDynamicSecrets_ListExpiredActiveLeases_RealServer(t *testing.T) {
	upstream, downstream, projectID, environmentID := newUpstreamDownstreamForDynamicSecrets(t)
	ctx := context.Background()
	now := time.Now()

	cfg, err := upstream.Storage().CreateDynamicSecretConfig(ctx, buildDynamicSecretConfig(now, projectID, environmentID, "expiry-test-db"))
	require.NoError(t, err)

	// One lease already expired an hour ago, one still valid for another hour —
	// created directly against the upstream (any caller, local or remote, would
	// produce identical rows).
	expired := buildDynamicSecretLease(now, cfg.ID, projectID, environmentID, "lease-expired")
	expired.ExpiresAt = now.Add(-time.Hour)
	_, err = upstream.Storage().CreateDynamicSecretLease(ctx, expired)
	require.NoError(t, err)

	stillValid := buildDynamicSecretLease(now, cfg.ID, projectID, environmentID, "lease-valid")
	stillValid.ExpiresAt = now.Add(time.Hour)
	_, err = upstream.Storage().CreateDynamicSecretLease(ctx, stillValid)
	require.NoError(t, err)

	rows, err := downstream.Storage().ListExpiredActiveLeases(ctx, now)
	require.NoError(t, err, "listing expired leases must succeed via storage.type: remote")
	require.Len(t, rows, 1)
	assert.Equal(t, "lease-expired", rows[0].LeaseID)
}
