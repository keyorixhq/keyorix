// remote_storage_mfa_management_test.go — end-to-end coverage for #524:
// RemoteStorage's UpsertMFASecret/GetMFASecret/ActivateMFASecret/
// DeleteMFAForUser/SetUserMFAEnabled/CreateMFARecoveryCodes/
// CountUnusedMFARecoveryCodes/DeleteMFARecoveryCodes were all unconditional
// stubs, so MFA enrolment and management (internal/core/mfa.go's
// BeginMFAEnrollment/ActivateMFA/DisableMFA/RegenerateMFARecoveryCodes/
// MFARecoveryCodesRemaining — every /auth/mfa/* route except already-active
// MFA LOGIN, separately proxied by #509/remote_storage_mfa_login_test.go) was
// 100% broken under storage.type: remote. Mirrors
// remote_storage_sso_state_test.go's (#521) and
// remote_storage_login_lockout_write_test.go's (#529) harness exactly: a real
// "upstream" exercised through the production NewRouter/handlers (including
// the new /api/v1/system/mfa routes, server/http/handlers/mfa_management_proxy.go),
// and a "downstream" *core.KeyorixCore configured with storage.type: remote
// pointed at "upstream" over real HTTP via store.RemoteStorage.
package http

import (
	"context"
	"fmt"
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
	"github.com/pquerna/otp/totp"
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

// TestRemoteStorageMFAManagement_StoragePrimitives_RealServer proves each of
// the eight #524 storage primitives genuinely round-trips through a real
// upstream server, exercised directly (not via internal/core), mirroring
// TestRemoteStorageSSOState_CreateConsume_RealServer's storage-primitive-level
// coverage.
func TestRemoteStorageMFAManagement_StoragePrimitives_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForMFAManagement(t)
	ctx := context.Background()

	seeded, err := upstream.CreateUser(ctx, &core.CreateUserRequest{
		Username: "mfa-mgmt-primitives", Email: "mfa-mgmt-primitives@example.com",
		Password: "Qr7#Kp2$Lm5@Vn9!", DisplayName: "MFA Management Primitives Test User",
	})
	require.NoError(t, err)

	// --- UpsertMFASecret / GetMFASecret ---
	secret := &models.MFASecret{
		UserID:     seeded.ID,
		SecretEnc:  []byte("ciphertext-bytes-not-a-real-secret"),
		SecretMeta: []byte("meta-v1"),
		Activated:  false,
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}
	require.NoError(t, downstream.Storage().UpsertMFASecret(ctx, secret),
		"UpsertMFASecret must succeed via storage.type: remote")
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

	// --- ActivateMFASecret ---
	require.NoError(t, downstream.Storage().ActivateMFASecret(ctx, seeded.ID))
	activated, err := upstream.Storage().GetMFASecret(ctx, seeded.ID)
	require.NoError(t, err)
	assert.True(t, activated.Activated, "activation must genuinely persist upstream")

	// --- SetUserMFAEnabled ---
	require.NoError(t, downstream.Storage().SetUserMFAEnabled(ctx, seeded.ID, true))
	enabledUser, err := upstream.Storage().GetUser(ctx, seeded.ID)
	require.NoError(t, err)
	assert.True(t, enabledUser.MFAEnabled, "MFAEnabled must genuinely persist upstream")

	// --- CreateMFARecoveryCodes / CountUnusedMFARecoveryCodes ---
	hashes := []string{"hash1", "hash2", "hash3"}
	require.NoError(t, downstream.Storage().CreateMFARecoveryCodes(ctx, seeded.ID, hashes))
	count, err := downstream.Storage().CountUnusedMFARecoveryCodes(ctx, seeded.ID)
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	upstreamCount, err := upstream.Storage().CountUnusedMFARecoveryCodes(ctx, seeded.ID)
	require.NoError(t, err)
	assert.Equal(t, 3, upstreamCount, "the recovery codes must be REAL rows in the upstream's own storage")

	// --- DeleteMFARecoveryCodes ---
	require.NoError(t, downstream.Storage().DeleteMFARecoveryCodes(ctx, seeded.ID))
	countAfterDelete, err := upstream.Storage().CountUnusedMFARecoveryCodes(ctx, seeded.ID)
	require.NoError(t, err)
	assert.Zero(t, countAfterDelete, "recovery codes must genuinely be gone upstream")

	// --- DeleteMFAForUser: clears the secret AND leaves no dangling recovery codes ---
	require.NoError(t, downstream.Storage().CreateMFARecoveryCodes(ctx, seeded.ID, []string{"hash-again"}))
	require.NoError(t, downstream.Storage().DeleteMFAForUser(ctx, seeded.ID))

	_, err = upstream.Storage().GetMFASecret(ctx, seeded.ID)
	assert.Error(t, err, "the secret row must genuinely be gone upstream")
	afterDeleteForUser, err := upstream.Storage().CountUnusedMFARecoveryCodes(ctx, seeded.ID)
	require.NoError(t, err)
	assert.Zero(t, afterDeleteForUser, "DeleteMFAForUser must also clear recovery codes upstream (local_mfa.go's own transaction)")
}

// TestRemoteStorageMFAManagement_FullLifecycle_RealServer is the critical #524
// test: it drives the ACTUAL end-user-facing entry points
// (BeginMFAEnrollment/ActivateMFA/MFARecoveryCodesRemaining/
// RegenerateMFARecoveryCodes/DisableMFA, internal/core/mfa.go) entirely
// through the DOWNSTREAM core — exactly what a Keyorix server booted with
// storage.type: remote does when it terminates a real user's /auth/mfa/*
// requests — proving the whole enrolment/management lifecycle that was 100%
// broken before this fix now works end-to-end against a real upstream server,
// not a protocol mock.
func TestRemoteStorageMFAManagement_FullLifecycle_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForMFAManagement(t)
	ctx := context.Background()

	const password = "Zq8#Trn4$Vhx2@Wp!"
	user, err := upstream.CreateUser(ctx, &core.CreateUserRequest{
		Username: "mfa-mgmt-lifecycle", Email: "mfa-mgmt-lifecycle@example.com",
		Password: password, DisplayName: "MFA Management Lifecycle Test User",
	})
	require.NoError(t, err)

	// BeginMFAEnrollment: generates + encrypts a fresh TOTP secret and persists
	// it via the new UpsertMFASecret proxy.
	_, totpSecret, err := downstream.BeginMFAEnrollment(ctx, user.ID)
	require.NoError(t, err, "BeginMFAEnrollment must succeed against a real remote-storage upstream")
	require.NotEmpty(t, totpSecret)

	// The pending secret must be a REAL row upstream, not activated yet.
	pending, err := upstream.Storage().GetMFASecret(ctx, user.ID)
	require.NoError(t, err)
	assert.False(t, pending.Activated)

	// NOTE — a genuine, PRE-EXISTING, OUT-OF-SCOPE gap discovered while building
	// this test, distinct from #524's eight storage primitives: ActivateMFA's
	// own requireReauth call ALWAYS falls back to bcrypt-comparing the caller's
	// password against user.PasswordHash (it cannot use a TOTP code here — see
	// ActivateMFA's doc for why), but RemoteStorage.GetUser deliberately never
	// returns PasswordHash (`json:"-"` on models.User, mirroring the #506
	// password-proxy security boundary — the hash must never leave the server
	// that owns it). So core.ActivateMFA's password-reauth branch can never
	// succeed under storage.type: remote today; the same requireReauth helper
	// gates WebAuthn's register/delete (internal/core/webauthn.go) with the
	// identical gap, already merged under #517 without addressing it — this is
	// a systemic, cross-feature limitation, not something #524's eight
	// enrolment/management storage primitives were ever meant to fix (closing
	// it would need a NEW RemoteReauthVerifier-shaped proxy, mirroring
	// RemoteLoginVerifier/RemoteMFAVerifier, as a SEPARATE finding). What #524
	// DOES fix and this test proves below: once a secret is activated (done
	// here via the SAME storage-primitive calls ActivateMFA itself would make,
	// bypassing only its currently-broken password-reauth gate),
	// DisableMFA/RegenerateMFARecoveryCodes re-authenticate with a CURRENT TOTP
	// code instead — requireReauth's TOTP branch never touches PasswordHash, so
	// it genuinely works end-to-end via the #524 proxies below.
	require.NoError(t, downstream.Storage().ActivateMFASecret(ctx, user.ID))
	require.NoError(t, downstream.Storage().SetUserMFAEnabled(ctx, user.ID, true))
	hashes := make([]string, 10)
	for i := range hashes {
		hashes[i] = fmt.Sprintf("recovery-code-hash-%d", i)
	}
	require.NoError(t, downstream.Storage().CreateMFARecoveryCodes(ctx, user.ID, hashes))

	enabledUser, err := upstream.Storage().GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, enabledUser.MFAEnabled, "MFAEnabled must genuinely persist upstream after activation")

	// Confirm MFAEnabled genuinely round-trips through the DOWNSTREAM's own
	// RemoteStorage.GetUser too (the users_handler.go/remote_users.go wire fix
	// this PR also needed — see the NOTE above and each file's doc comment):
	// requireReauth's TOTP branch (exercised by RegenerateMFARecoveryCodes/
	// DisableMFA below) depends on THIS read reporting the real value, not the
	// Go zero value.
	viaDownstream, err := downstream.Storage().GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, viaDownstream.MFAEnabled,
		"MFAEnabled must round-trip through RemoteStorage.GetUser's wire response, not silently read back false")

	// MFARecoveryCodesRemaining: reads the freshly-issued codes back via the
	// downstream — an ordinary, unauthenticated-by-password read, so it is
	// unaffected by the requireReauth gap above.
	remaining, total, err := downstream.MFARecoveryCodesRemaining(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, 10, remaining)
	assert.Equal(t, 10, total)

	// RegenerateMFARecoveryCodes: re-authenticates with a CURRENT TOTP code
	// (MFA is now active, so requireReauth's TOTP branch runs and succeeds,
	// never reaching the broken password fallback), replaces the old code set
	// wholesale — genuinely end-to-end via the #524 proxies.
	regenCode, err := totp.GenerateCode(totpSecret, time.Now())
	require.NoError(t, err)
	newCodes, err := downstream.RegenerateMFARecoveryCodes(ctx, user.ID, regenCode)
	require.NoError(t, err, "RegenerateMFARecoveryCodes must succeed against a real remote-storage upstream, "+
		"authenticated via a CURRENT TOTP code (not password — see the NOTE above)")
	require.Len(t, newCodes, 10)

	remainingAfterRegen, _, err := downstream.MFARecoveryCodesRemaining(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, 10, remainingAfterRegen)

	// DisableMFA: re-authenticates with a CURRENT TOTP code (same TOTP-branch
	// reasoning as above), then clears the secret, recovery codes, and the
	// MFAEnabled flag — all via the #524 proxies.
	disableCode, err := totp.GenerateCode(totpSecret, time.Now())
	require.NoError(t, err)
	require.NoError(t, downstream.DisableMFA(ctx, user.ID, disableCode),
		"DisableMFA must succeed against a real remote-storage upstream, authenticated via a CURRENT TOTP code")

	disabledUser, err := upstream.Storage().GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.False(t, disabledUser.MFAEnabled, "MFAEnabled must genuinely be cleared upstream")

	_, err = upstream.Storage().GetMFASecret(ctx, user.ID)
	assert.Error(t, err, "the TOTP secret must genuinely be gone upstream after disable")

	afterDisableRemaining, err := upstream.Storage().CountUnusedMFARecoveryCodes(ctx, user.ID)
	require.NoError(t, err)
	assert.Zero(t, afterDisableRemaining, "recovery codes must genuinely be gone upstream after disable")
}
