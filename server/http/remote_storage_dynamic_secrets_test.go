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

// TestRemoteStorageDynamicSecrets_ConfigCreateGetListUpdate_RealServer proves the
// fix for CreateDynamicSecretConfig/GetDynamicSecretConfig/ListDynamicSecretConfigs/
// UpdateDynamicSecretConfig: a config is genuinely persisted on the upstream server
// via the DOWNSTREAM's RemoteStorage, fetchable by ID, listed, and updatable — all
// via storage.type: remote against a real router, not a protocol mock.
func TestRemoteStorageDynamicSecrets_ConfigCreateGetListUpdate_RealServer(t *testing.T) {
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

	// UpdateDynamicSecretConfig persists a change (classification) via the downstream.
	fetched.Classification = "confidential"
	require.NoError(t, downstream.Storage().UpdateDynamicSecretConfig(ctx, fetched))
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

// TestRemoteStorageDynamicSecrets_AdminDSNNeverPlaintextOnUpstream_RealServer is
// the critical sensitive-data-boundary test for this finding: it encrypts an
// admin DSN with a LOCAL encryption service (standing in for the downstream
// server's own encryptAuthSecret, exactly as internal/core.CreateDynamicSecretConfig
// does before ever calling storage.CreateDynamicSecretConfig/
// UpdateDynamicSecretConfig), persists ONLY the resulting ciphertext through the
// downstream's RemoteStorage, and proves:
//  1. the RAW bytes visible directly in the upstream's own storage are NOT the
//     plaintext admin DSN (the upstream never sees it — it only ever receives
//     opaque ciphertext over the wire);
//  2. fetching the config back via the downstream's RemoteStorage and decrypting
//     with the SAME encryption service reproduces the exact original plaintext,
//     proving the ciphertext round-trips through this HTTP hop byte-for-byte
//     (encoding/json base64 for []byte fields), unmodified.
func TestRemoteStorageDynamicSecrets_AdminDSNNeverPlaintextOnUpstream_RealServer(t *testing.T) {
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
	// encryptAuthSecret) and persist only the ciphertext.
	ct, meta, err := enc.EncryptSecretWithAAD([]byte(adminDSNPlain), encryption.DynamicSecretConfigAAD(cfg.ID, projectID, environmentID))
	require.NoError(t, err)
	require.NotEqual(t, adminDSNPlain, string(ct), "the encrypted bytes must not equal the plaintext")
	cfg.AdminDSNEnc = ct
	cfg.AdminDSNMeta = meta
	require.NoError(t, downstream.Storage().UpdateDynamicSecretConfig(ctx, cfg))

	// Property 1: the upstream's OWN storage never holds the plaintext DSN anywhere
	// in the row — only the ciphertext this test encrypted itself.
	direct, err := upstream.Storage().GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	assert.NotContains(t, string(direct.AdminDSNEnc), "s3cr3t", "the upstream must never receive/store the plaintext admin DSN")
	assert.Equal(t, ct, direct.AdminDSNEnc, "the upstream stores the exact ciphertext bytes it was given, unmodified")

	// Property 2: fetching back through the downstream's RemoteStorage and
	// decrypting with the SAME encryption service reproduces the original
	// plaintext exactly — the ciphertext round-trips through the HTTP hop intact.
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

// TestRemoteStorageDynamicSecrets_LeaseCreateGetListCountUpdate_RealServer proves
// the fix for CreateDynamicSecretLease/GetDynamicSecretLease/
// ListDynamicSecretLeases/CountActiveLeases/UpdateDynamicSecretLease: a lease is
// genuinely persisted, fetchable by its opaque LeaseID, listed/counted, and its
// status transition (revoke) is visible directly on the upstream — all via
// storage.type: remote against a real router.
func TestRemoteStorageDynamicSecrets_LeaseCreateGetListCountUpdate_RealServer(t *testing.T) {
	upstream, downstream, projectID, environmentID := newUpstreamDownstreamForDynamicSecrets(t)
	ctx := context.Background()
	now := time.Now()

	cfg, err := downstream.Storage().CreateDynamicSecretConfig(ctx, buildDynamicSecretConfig(now, projectID, environmentID, "lease-test-db"))
	require.NoError(t, err)

	lease, err := downstream.Storage().CreateDynamicSecretLease(ctx, buildDynamicSecretLease(now, cfg.ID, projectID, environmentID, "lease-abc-123"))
	require.NoError(t, err, "creating a dynamic-secret lease must succeed via storage.type: remote")
	require.NotZero(t, lease.ID)
	assert.Equal(t, "lease-abc-123", lease.LeaseID)
	assert.Equal(t, "active", lease.Status)

	// A REAL row on the upstream's own storage.
	direct, err := upstream.Storage().GetDynamicSecretLease(ctx, "lease-abc-123")
	require.NoError(t, err)
	assert.Equal(t, cfg.ID, direct.ConfigID)

	// GetDynamicSecretLease/ListDynamicSecretLeases/CountActiveLeases via the downstream.
	fetched, err := downstream.Storage().GetDynamicSecretLease(ctx, "lease-abc-123")
	require.NoError(t, err)
	assert.Equal(t, lease.RoleName, fetched.RoleName)

	_, err = downstream.Storage().CreateDynamicSecretLease(ctx, buildDynamicSecretLease(now, cfg.ID, projectID, environmentID, "lease-def-456"))
	require.NoError(t, err)

	leases, err := downstream.Storage().ListDynamicSecretLeases(ctx, cfg.ID)
	require.NoError(t, err)
	require.Len(t, leases, 2)

	active, err := downstream.Storage().CountActiveLeases(ctx, cfg.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), active)

	// UpdateDynamicSecretLease: revoke one lease via the downstream, confirm the
	// transition is visible directly on the upstream.
	fetched.Status = "revoked"
	revokedAt := time.Now()
	fetched.RevokedAt = &revokedAt
	fetched.RevokeReason = "manual"
	require.NoError(t, downstream.Storage().UpdateDynamicSecretLease(ctx, fetched))

	reFetched, err := upstream.Storage().GetDynamicSecretLease(ctx, "lease-abc-123")
	require.NoError(t, err)
	assert.Equal(t, "revoked", reFetched.Status)
	assert.Equal(t, "manual", reFetched.RevokeReason)
	require.NotNil(t, reFetched.RevokedAt)

	// The active count now reflects only the still-active second lease.
	activeAfter, err := downstream.Storage().CountActiveLeases(ctx, cfg.ID)
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
