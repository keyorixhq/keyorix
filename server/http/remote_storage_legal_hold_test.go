package http

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForLegalHold builds the standard #452/#507/#510/#511
// two-server harness: an "upstream" exercised through the REAL production
// NewRouter/handlers (including the new /api/v1/system/legal-hold routes,
// server/http/handlers/legal_hold_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote (ADR-049), pointed at
// "upstream" over real HTTP via store.RemoteStorage. Mirrors
// newUpstreamDownstreamForMemberships exactly.
func newUpstreamDownstreamForLegalHold(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore) {
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

// TestRemoteStorageLegalHold_CreateGetUpdate_RealServer proves finding #519's
// fix: a legal hold is genuinely persisted on the upstream server via the
// DOWNSTREAM's RemoteStorage, fetchable as the active hold, and its lift
// (release) round-trips too — all via storage.type: remote against a real
// router, not a protocol mock.
func TestRemoteStorageLegalHold_CreateGetUpdate_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForLegalHold(t)
	ctx := context.Background()

	// No hold active yet.
	active, err := downstream.Storage().GetActiveLegalHold(ctx)
	require.NoError(t, err)
	assert.Nil(t, active, "no hold should be active initially")

	placedAt := time.Now()
	hold, err := downstream.Storage().CreateLegalHold(ctx, &models.LegalHold{
		Reason: "litigation hold: Doe v. Acme", PlacedBy: 1, PlacedAt: placedAt, Released: false,
	})
	require.NoError(t, err, "creating a legal hold must succeed via storage.type: remote")
	require.NotZero(t, hold.ID, "the upstream must assign a real ID")
	assert.Equal(t, "litigation hold: Doe v. Acme", hold.Reason)
	assert.Equal(t, uint(1), hold.PlacedBy)
	assert.False(t, hold.Released)

	// Confirm it is a REAL row in the upstream's own storage (not just "the call
	// didn't error"), by reading it back directly against upstream.
	direct, err := upstream.Storage().GetActiveLegalHold(ctx)
	require.NoError(t, err)
	require.NotNil(t, direct)
	assert.Equal(t, hold.ID, direct.ID)

	// GetActiveLegalHold via the downstream (RemoteStorage) round-trips every
	// field correctly.
	fetched, err := downstream.Storage().GetActiveLegalHold(ctx)
	require.NoError(t, err)
	require.NotNil(t, fetched)
	assert.Equal(t, hold.ID, fetched.ID)
	assert.Equal(t, hold.Reason, fetched.Reason)
	assert.Equal(t, hold.PlacedBy, fetched.PlacedBy)
	assert.WithinDuration(t, placedAt, fetched.PlacedAt, time.Second)
	assert.False(t, fetched.Released)

	// Lift it: UpdateLegalHold is a plain full-row Save (see the package doc),
	// so this round-trips Released/ReleasedBy/ReleasedAt/ReleaseReason.
	releasedAt := time.Now()
	fetched.Released = true
	fetched.ReleasedBy = 2
	fetched.ReleasedAt = &releasedAt
	fetched.ReleaseReason = "case settled"
	require.NoError(t, downstream.Storage().UpdateLegalHold(ctx, fetched))

	// No hold should be reported as active anymore.
	afterLift, err := downstream.Storage().GetActiveLegalHold(ctx)
	require.NoError(t, err)
	assert.Nil(t, afterLift, "a released hold must not be reported as active")

	// Directly against the upstream's own storage too, proving this isn't an
	// artifact of RemoteStorage's response cache.
	directAfterLift, err := upstream.Storage().GetActiveLegalHold(ctx)
	require.NoError(t, err)
	assert.Nil(t, directAfterLift)
}

// TestRemoteStorageLegalHold_AlreadyActive_RealServer proves the real DB-level
// partial unique index (uniq_legal_holds_active, `released` WHERE
// released = false) is still enforced across the HTTP hop, AND that
// CreateLegalHoldProxy translates the resulting unique-constraint violation
// into the SAME storage.ErrLegalHoldAlreadyActive sentinel core.PlaceLegalHold's
// errors.Is check depends on — not an opaque, unclassifiable storage error.
func TestRemoteStorageLegalHold_AlreadyActive_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForLegalHold(t)
	ctx := context.Background()

	_, err := downstream.Storage().CreateLegalHold(ctx, &models.LegalHold{
		Reason: "first hold", PlacedBy: 1, PlacedAt: time.Now(), Released: false,
	})
	require.NoError(t, err)

	// A second, concurrent-in-spirit placement attempt must be rejected by the
	// upstream's real DB-level unique index, and the rejection must reconstruct
	// as storage.ErrLegalHoldAlreadyActive on this side of the HTTP hop.
	_, err = downstream.Storage().CreateLegalHold(ctx, &models.LegalHold{
		Reason: "second hold", PlacedBy: 2, PlacedAt: time.Now(), Released: false,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, coreStorage.ErrLegalHoldAlreadyActive),
		"a duplicate active legal hold must surface as storage.ErrLegalHoldAlreadyActive, not an opaque error: %v", err)
}

// TestRemoteStorageLegalHold_ConcurrentCreate_OnlyOneWins_RealServer is the
// concurrency proof for the TOCTOU race core.PlaceLegalHold's own doc comment
// describes (#305): many concurrent CreateLegalHold calls through the SAME
// downstream RemoteStorage client race to place a hold; the real upstream
// database's partial unique index must let exactly one commit, with every
// other caller observing storage.ErrLegalHoldAlreadyActive — never two active
// holds, and never a caller silently swallowing an error and believing its own
// placement won when it didn't.
func TestRemoteStorageLegalHold_ConcurrentCreate_OnlyOneWins_RealServer(t *testing.T) {
	upstream, downstream := newUpstreamDownstreamForLegalHold(t)
	ctx := context.Background()

	const n = 10
	var wg sync.WaitGroup
	successes := make([]bool, n)
	alreadyActive := make([]bool, n)
	otherErrs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := downstream.Storage().CreateLegalHold(ctx, &models.LegalHold{
				Reason: "race", PlacedBy: uint(i + 1), PlacedAt: time.Now(), Released: false,
			})
			switch {
			case err == nil:
				successes[i] = true
			case errors.Is(err, coreStorage.ErrLegalHoldAlreadyActive):
				alreadyActive[i] = true
			default:
				otherErrs[i] = err
			}
		}(i)
	}
	wg.Wait()

	successCount := 0
	for i := 0; i < n; i++ {
		require.NoError(t, otherErrs[i], "every non-winning call must fail specifically with ErrLegalHoldAlreadyActive, not an opaque error")
		if successes[i] {
			successCount++
		}
	}
	assert.Equal(t, 1, successCount, "exactly one concurrent placement must win")
	for i := 0; i < n; i++ {
		assert.True(t, successes[i] || alreadyActive[i], "every call must either win or observe ErrLegalHoldAlreadyActive")
	}

	// The upstream's own storage must show exactly one active hold, not zero
	// (silently lost) and not more than one (the race actually won).
	active, err := upstream.Storage().GetActiveLegalHold(ctx)
	require.NoError(t, err)
	require.NotNil(t, active)
}
