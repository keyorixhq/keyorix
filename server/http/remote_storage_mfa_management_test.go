// remote_storage_mfa_management_test.go — end-to-end coverage for #524:
// RemoteStorage's UpsertMFASecret/GetMFASecret/CountUnusedMFARecoveryCodes
// were unconditional stubs, so MFA enrolment and management
// (internal/core/mfa.go's BeginMFAEnrollment/ActivateMFA/DisableMFA/
// RegenerateMFARecoveryCodes/MFARecoveryCodesRemaining — every /auth/mfa/*
// route except already-active MFA LOGIN, separately proxied by
// #509/remote_storage_mfa_login_test.go) was 100% broken under
// storage.type: remote. Mirrors remote_storage_sso_state_test.go's (#521) and
// remote_storage_login_lockout_write_test.go's (#529) harness exactly: a real
// "upstream" exercised through the production NewRouter/handlers (including
// the /api/v1/system/mfa routes, server/http/handlers/mfa_management_proxy.go),
// and a "downstream" *core.KeyorixCore configured with storage.type: remote
// pointed at "upstream" over real HTTP via store.RemoteStorage.
//
// ActivateMFASecret/DeleteMFAForUser/SetUserMFAEnabled/
// CreateMFARecoveryCodes/DeleteMFARecoveryCodes and their coverage here were
// DELETED (#1593, docs/adr-089-mfa-purge-relay-deletion.md) — no live
// caller. GetMFASecret/CountUnusedMFARecoveryCodes remain real and are still
// covered below.
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

// newUpstreamDownstreamForMFAManagement builds the standard two-server harness
// used across this campaign, PLUS a real encryption.Service wired into BOTH
// cores — needed because BeginMFAEnrollment refuses outright when at-rest
// encryption is unavailable, and because the downstream core must be able to
// decrypt what it itself just encrypted (see remote_mfa.go's package doc for
// why that "same calling server does both halves" property is what makes
// proxying SecretEnc/SecretMeta as opaque ciphertext safe here).
func newUpstreamDownstreamForMFAManagement(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createTestToken(t, upstream)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))
	upstream.SetAuthEncryptor(enc)

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
	// The downstream is the server that actually terminates /auth/mfa/*
	// requests under storage.type: remote, so it needs its OWN encryption
	// service wired up too — exactly like a real spoke deployment configured
	// with its own at-rest encryption.
	downstream.SetAuthEncryptor(enc)
	return upstream, downstream
}

// TestRemoteStorageMFAManagement_StoragePrimitives_RealServer proves the
// surviving #524 storage primitives (GetMFASecret,
// CountUnusedMFARecoveryCodes) genuinely round-trip through a real upstream
// server, exercised directly (not via internal/core), mirroring
// TestRemoteStorageSSOState_CreateConsume_RealServer's storage-primitive-level
// coverage. Both the secret and the recovery codes are seeded directly
// against the upstream's real storage (UpsertMFASecretProxy was deleted --
// G80 liveness sweep found no live caller; see docs/g80-remediation-notes.md
// -- and CreateMFARecoveryCodes was deleted, #1593,
// docs/adr-089-mfa-purge-relay-deletion.md).
func TestRemoteStorageMFAManagement_StoragePrimitives_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForMFAManagement(t)
	ctx := context.Background()

	seeded, err := upstream.CreateUser(ctx, &core.CreateUserRequest{
		Username: "mfa-mgmt-primitives", Email: "mfa-mgmt-primitives@example.com",
		Password: "Qr7#Kp2$Lm5@Vn9!", DisplayName: "MFA Management Primitives Test User",
	})
	require.NoError(t, err)

	// --- GetMFASecret ---
	secret := &models.MFASecret{
		UserID:     seeded.ID,
		SecretEnc:  []byte("ciphertext-bytes-not-a-real-secret"),
		SecretMeta: []byte("meta-v1"),
		Activated:  false,
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, upstream.Storage().UpsertMFASecret(ctx, secret))
	require.NotZero(t, secret.ID, "the upstream must assign a real ID")

	fetched, err := downstream.Storage().GetMFASecret(ctx, seeded.ID)
	require.NoError(t, err)
	assert.Equal(t, []byte("ciphertext-bytes-not-a-real-secret"), fetched.SecretEnc)
	assert.Equal(t, []byte("meta-v1"), fetched.SecretMeta)
	assert.False(t, fetched.Activated)

	// Confirm it is a REAL row in the upstream's own storage.
	directFetch, err := upstream.Storage().GetMFASecret(ctx, seeded.ID)
	require.NoError(t, err)
	assert.Equal(t, secret.ID, directFetch.ID)

	// --- CountUnusedMFARecoveryCodes ---
	require.NoError(t, upstream.Storage().CreateMFARecoveryCodes(ctx, seeded.ID, []string{"hash1", "hash2", "hash3"}))
	count, err := downstream.Storage().CountUnusedMFARecoveryCodes(ctx, seeded.ID)
	require.NoError(t, err)
	assert.Equal(t, 3, count, "the recovery codes must be REAL rows in the upstream's own storage")
}

// TestRemoteStorageMFAManagement_FullLifecycle_RealServer used to drive
// BeginMFAEnrollment/ActivateMFA/MFARecoveryCodesRemaining/
// RegenerateMFARecoveryCodes/DisableMFA (internal/core/mfa.go) entirely
// through the DOWNSTREAM core, proving the enrolment/management lifecycle
// against a real upstream server. It was deleted here, not weakened: its
// entry point, BeginMFAEnrollment, internally calls storage.UpsertMFASecret,
// and UpsertMFASecretProxy was deleted (G80 liveness sweep found no live
// caller; see docs/g80-remediation-notes.md), so the enrolment leg of this
// end-to-end path no longer has a wire route to exercise. The remaining test
// in this file (TestRemoteStorageMFAManagement_StoragePrimitives_RealServer)
// still covers every surviving storage primitive.
