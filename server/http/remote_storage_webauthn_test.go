// remote_storage_webauthn_test.go — end-to-end coverage for #517: RemoteStorage's
// WebAuthn storage primitives (CreateWebAuthnCredential/ListWebAuthnCredentials/
// GetWebAuthnCredentialByCredID/LockWebAuthnCredentialForUpdate/
// UpdateWebAuthnCredential/AdvanceWebAuthnCredentialCounter/
// DeleteWebAuthnCredential/CountWebAuthnCredentials/SetUserWebAuthnEnabled/
// CreateWebAuthnSession/ConsumeWebAuthnSession) were entirely stubbed
// (remoteUnsupported), so every passkey registration/login flow was completely
// non-functional under storage.type: remote. Mirrors
// remote_storage_dynamic_secrets_test.go/remote_storage_setup_tokens_test.go's
// #452/#507/#510 harness exactly: a real "upstream" exercised through the
// production NewRouter/handlers (including the new /api/v1/system/webauthn
// routes, server/http/handlers/webauthn_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote (ADR-049), pointed at
// "upstream" over real HTTP via store.RemoteStorage.
package http

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForWebAuthn builds the standard two-server harness.
func newUpstreamDownstreamForWebAuthn(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore) {
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

// webAuthnCredentialBlob builds the same JSON shape internal/core/webauthn.go's
// persistUpdatedCredential marshals (json.Marshal of a *webauthn.Credential) —
// AdvanceWebAuthnCredentialCounter/local_webauthn.go's webauthnStoredCounter reads
// back exactly the "authenticator.signCount" field this produces.
func webAuthnCredentialBlob(t *testing.T, credID []byte, signCount uint32) []byte {
	t.Helper()
	blob, err := json.Marshal(webauthn.Credential{ID: credID, Authenticator: webauthn.Authenticator{SignCount: signCount}})
	require.NoError(t, err)
	return blob
}

// TestRemoteStorageWebAuthn_CredentialCRUD_RealServer proves the fix for
// CreateWebAuthnCredential/ListWebAuthnCredentials/GetWebAuthnCredentialByCredID/
// LockWebAuthnCredentialForUpdate/UpdateWebAuthnCredential/
// CountWebAuthnCredentials/DeleteWebAuthnCredential/SetUserWebAuthnEnabled: a
// credential is genuinely persisted on the upstream server via the downstream's
// RemoteStorage, fetchable both by ID (lock) and cred ID, listed, counted,
// updatable, and deletable — all via storage.type: remote against a real router.
func TestRemoteStorageWebAuthn_CredentialCRUD_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForWebAuthn(t)
	ctx := context.Background()
	now := time.Now()

	user, err := upstream.CreateUser(ctx, &core.CreateUserRequest{
		Username: "passkeyuser",
		Email:    "passkeyuser@example.com",
		Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	credID := []byte("credential-id-1")
	row := &models.WebAuthnCredential{
		UserID:         user.ID,
		CredentialID:   credID,
		Name:           "YubiKey 5C",
		CredentialBlob: webAuthnCredentialBlob(t, credID, 0),
		CreatedAt:      now,
	}
	require.NoError(t, downstream.Storage().CreateWebAuthnCredential(ctx, row))
	require.NotZero(t, row.ID, "the upstream must assign a real ID")

	// A REAL row on the upstream's own storage.
	direct, err := upstream.Storage().GetWebAuthnCredentialByCredID(ctx, credID, user.ID)
	require.NoError(t, err)
	assert.Equal(t, "YubiKey 5C", direct.Name)

	// GetWebAuthnCredentialByCredID / LockWebAuthnCredentialForUpdate via the
	// downstream both round-trip correctly.
	fetched, err := downstream.Storage().GetWebAuthnCredentialByCredID(ctx, credID, user.ID)
	require.NoError(t, err)
	assert.Equal(t, row.ID, fetched.ID)
	assert.Equal(t, "YubiKey 5C", fetched.Name)

	locked, err := downstream.Storage().LockWebAuthnCredentialForUpdate(ctx, credID, user.ID)
	require.NoError(t, err)
	assert.Equal(t, row.ID, locked.ID)

	// A second credential, then list + count both via the downstream.
	credID2 := []byte("credential-id-2")
	row2 := &models.WebAuthnCredential{
		UserID:         user.ID,
		CredentialID:   credID2,
		Name:           "Touch ID",
		CredentialBlob: webAuthnCredentialBlob(t, credID2, 0),
		CreatedAt:      now,
	}
	require.NoError(t, downstream.Storage().CreateWebAuthnCredential(ctx, row2))

	rows, err := downstream.Storage().ListWebAuthnCredentials(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	names := map[string]bool{}
	for _, r := range rows {
		names[r.Name] = true
	}
	assert.True(t, names["YubiKey 5C"])
	assert.True(t, names["Touch ID"])

	count, err := downstream.Storage().CountWebAuthnCredentials(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	// UpdateWebAuthnCredential (rejectIfCloned's own write path): mark the first
	// credential disabled via the downstream, confirm it's visible directly on the
	// upstream.
	fetched.Disabled = true
	require.NoError(t, downstream.Storage().UpdateWebAuthnCredential(ctx, fetched))
	reFetched, err := upstream.Storage().GetWebAuthnCredentialByCredID(ctx, credID, user.ID)
	require.NoError(t, err)
	assert.True(t, reFetched.Disabled, "the disable must be visible directly on the upstream's own storage")

	// SetUserWebAuthnEnabled via the downstream.
	require.NoError(t, downstream.Storage().SetUserWebAuthnEnabled(ctx, user.ID, true))
	directUser, err := upstream.Storage().GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, directUser.WebAuthnEnabled)

	// DeleteWebAuthnCredential via the downstream; count drops to 1.
	require.NoError(t, downstream.Storage().DeleteWebAuthnCredential(ctx, user.ID, row2.ID))
	countAfter, err := downstream.Storage().CountWebAuthnCredentials(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), countAfter)
}

// TestRemoteStorageWebAuthn_GetCredentialNotFound_RealServer proves a clean
// not-found error (not a panic, not a garbage 500) for a nonexistent credential.
func TestRemoteStorageWebAuthn_GetCredentialNotFound_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForWebAuthn(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetWebAuthnCredentialByCredID(ctx, []byte("nope"), 999999)
	require.Error(t, err)
}

// TestRemoteStorageWebAuthn_SessionCreateConsume_RealServer proves the fix for
// CreateWebAuthnSession/ConsumeWebAuthnSession: a ceremony session is genuinely
// persisted, consumable exactly once, and a second consume of the same token
// cleanly fails — all via storage.type: remote.
func TestRemoteStorageWebAuthn_SessionCreateConsume_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForWebAuthn(t)
	ctx := context.Background()
	now := time.Now()

	user, err := upstream.CreateUser(ctx, &core.CreateUserRequest{
		Username: "sessionuser",
		Email:    "sessionuser@example.com",
		Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	sess := &models.WebAuthnSession{
		UserID:    user.ID,
		TokenHash: "session-hash-1",
		Purpose:   "register",
		Data:      []byte(`{"challenge":"abc"}`),
		ExpiresAt: now.Add(5 * time.Minute),
		CreatedAt: now,
	}
	require.NoError(t, downstream.Storage().CreateWebAuthnSession(ctx, sess))
	require.NotZero(t, sess.ID, "the upstream must assign a real ID")

	// ConsumeWebAuthnSession via the downstream succeeds exactly once.
	consumed, err := downstream.Storage().ConsumeWebAuthnSession(ctx, "session-hash-1", time.Now())
	require.NoError(t, err, "consuming a valid session must succeed via storage.type: remote")
	assert.Equal(t, "register", consumed.Purpose)
	assert.Equal(t, user.ID, consumed.UserID)

	// A second consume of the same token must cleanly fail (single-use).
	_, err = downstream.Storage().ConsumeWebAuthnSession(ctx, "session-hash-1", time.Now())
	require.Error(t, err, "a second consume of the same session token must fail")
}

// TestRemoteStorageWebAuthn_ConcurrentCounterAdvanceRace_RealServer is the
// critical #306/#517 test: it fires N concurrent AdvanceWebAuthnCredentialCounter
// calls at the SAME credential, over real HTTP against the real upstream router,
// each proposing a different candidate signature counter. It asserts the FINAL
// persisted counter is exactly the maximum of every candidate — i.e. no
// concurrent write, regardless of goroutine scheduling or network interleaving,
// is ever allowed to regress the persisted counter below a value some other
// concurrent (or already-completed) call already established. This proves
// AdvanceWebAuthnCredentialCounterProxy's single-request locked compare-and-swap
// (server/http/handlers/webauthn_proxy.go) closes the exact TOCTOU race a naive
// client-side Lock-then-Update pair over two separate remote calls would reopen
// (RemoteStorage.WithTransaction is a no-op passthrough, remote_transaction.go).
func TestRemoteStorageWebAuthn_ConcurrentCounterAdvanceRace_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForWebAuthn(t)
	ctx := context.Background()
	now := time.Now()

	user, err := upstream.CreateUser(ctx, &core.CreateUserRequest{
		Username: "raceuser",
		Email:    "raceuser@example.com",
		Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	credID := []byte("race-credential")
	row := &models.WebAuthnCredential{
		UserID:         user.ID,
		CredentialID:   credID,
		Name:           "Race Key",
		CredentialBlob: webAuthnCredentialBlob(t, credID, 0),
		CreatedAt:      now,
	}
	require.NoError(t, upstream.Storage().CreateWebAuthnCredential(ctx, row))

	// A mix of candidate counters, deliberately unordered and including values both
	// above and below one another, so no goroutine start order could accidentally
	// produce a monotonic sequence on its own.
	candidates := []uint32{15, 3, 42, 8, 100, 1, 77, 29, 64, 5, 91, 12, 55, 2, 88, 33, 60, 9, 47, 21}
	maxCandidate := uint32(0)
	for _, c := range candidates {
		if c > maxCandidate {
			maxCandidate = c
		}
	}

	var wg sync.WaitGroup
	var errCount atomic.Int64
	wg.Add(len(candidates))
	start := make(chan struct{})
	for _, c := range candidates {
		c := c
		go func() {
			defer wg.Done()
			<-start
			blob := webAuthnCredentialBlob(t, credID, c)
			_, err := downstream.Storage().AdvanceWebAuthnCredentialCounter(ctx, credID, user.ID, blob, c, time.Now())
			if err != nil {
				errCount.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	require.Equal(t, int64(0), errCount.Load(), "every concurrent advance-counter call must get a clean result, not a transport/server error")

	final, err := upstream.Storage().GetWebAuthnCredentialByCredID(ctx, credID, user.ID)
	require.NoError(t, err)
	var stored webauthn.Credential
	require.NoError(t, json.Unmarshal(final.CredentialBlob, &stored))
	assert.Equal(t, maxCandidate, stored.Authenticator.SignCount,
		"the persisted counter must end at the maximum candidate regardless of goroutine scheduling — any lower final value means a stale write clobbered a genuinely higher one")
}

// TestRemoteStorageWebAuthn_StaleCounterAdvanceRejectedAfterWinner_RealServer pins
// the exact sequential case the concurrent test above proves statistically: a
// stale (lower) counter arriving AFTER a higher one has already committed must be
// rejected (advanced=false), and must never overwrite the already-persisted higher
// value — all via storage.type: remote.
func TestRemoteStorageWebAuthn_StaleCounterAdvanceRejectedAfterWinner_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForWebAuthn(t)
	ctx := context.Background()
	now := time.Now()

	user, err := upstream.CreateUser(ctx, &core.CreateUserRequest{
		Username: "staleuser",
		Email:    "staleuser@example.com",
		Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	credID := []byte("stale-credential")
	row := &models.WebAuthnCredential{
		UserID:         user.ID,
		CredentialID:   credID,
		Name:           "Stale Test Key",
		CredentialBlob: webAuthnCredentialBlob(t, credID, 0),
		CreatedAt:      now,
	}
	require.NoError(t, upstream.Storage().CreateWebAuthnCredential(ctx, row))

	// Winner commits first: counter advances 0 -> 100.
	advanced, err := downstream.Storage().AdvanceWebAuthnCredentialCounter(ctx, credID, user.ID, webAuthnCredentialBlob(t, credID, 100), 100, time.Now())
	require.NoError(t, err)
	assert.True(t, advanced)

	// A stale (lower) counter arrives after: must be rejected, not persisted.
	advanced, err = downstream.Storage().AdvanceWebAuthnCredentialCounter(ctx, credID, user.ID, webAuthnCredentialBlob(t, credID, 50), 50, time.Now())
	require.NoError(t, err, "a stale advance-counter call is a benign rejected write, not a storage error")
	assert.False(t, advanced, "a stale (lower) counter must never be reported as advanced")

	final, err := upstream.Storage().GetWebAuthnCredentialByCredID(ctx, credID, user.ID)
	require.NoError(t, err)
	var stored webauthn.Credential
	require.NoError(t, json.Unmarshal(final.CredentialBlob, &stored))
	assert.Equal(t, uint32(100), stored.Authenticator.SignCount, "the stale write must not have clobbered the winner's persisted counter")

	// The (0, 0) "authenticator doesn't implement a counter" carve-out: an
	// authenticator that always reports 0 must still get its blob/LastUsedAt
	// updated (e.g. for a DIFFERENT credential starting fresh at 0), not be
	// treated as permanently stale.
	credID2 := []byte("zero-counter-credential")
	row2 := &models.WebAuthnCredential{
		UserID:         user.ID,
		CredentialID:   credID2,
		Name:           "Touch ID (no counter)",
		CredentialBlob: webAuthnCredentialBlob(t, credID2, 0),
		CreatedAt:      now,
	}
	require.NoError(t, upstream.Storage().CreateWebAuthnCredential(ctx, row2))

	lastUsed := time.Now()
	advanced, err = downstream.Storage().AdvanceWebAuthnCredentialCounter(ctx, credID2, user.ID, webAuthnCredentialBlob(t, credID2, 0), 0, lastUsed)
	require.NoError(t, err)
	assert.True(t, advanced, "a (0, 0) counter comparison must not be treated as stale")

	final2, err := upstream.Storage().GetWebAuthnCredentialByCredID(ctx, credID2, user.ID)
	require.NoError(t, err)
	require.NotNil(t, final2.LastUsedAt)
}
