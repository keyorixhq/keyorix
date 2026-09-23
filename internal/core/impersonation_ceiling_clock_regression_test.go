// impersonation_ceiling_clock_regression_test.go — #1983 investigation
// follow-up finding: cachedImpersonationCeiling (authz.go) compared a bare
// c.now() directly against its cache entry's expiresAt, with none of the
// monotonic-watermark protection every sibling credential-expiry/permission
// cache in this file already has (authEffectiveNow, shareEffectiveNow,
// consumeClockLooksRegressed). A host clock stepped backward makes an
// already-cached verdict look further from its ceilingCacheTTL (60s) than it
// really is, so a stale verdict -- including a stale ALLOW -- is trusted past
// its intended window, extending the exact MT-007 exposure
// ReauthorizeImpersonation exists to bound (a demoted admin, or a promoted
// target, mid-session). Mirrors oidc_clock_regression_test.go's shape.
package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// TestCachedImpersonationCeiling_ClockSteppedBackward_StaleAllowIsRechecked is
// the exploit-shaped test. Sequence:
//
//  1. Seed the cache as if an earlier call at `baseline` cached an ALLOWED
//     verdict (expiresAt = baseline+60s), and warm the watermark directly to
//     a LATER reading this process has already legitimately observed
//     (baseline+90s) -- exactly what a second, real call at that later
//     instant would have done.
//  2. Step c.now() BACKWARD to baseline+30s: naively "only 30s since caching,
//     still inside the 60s TTL" -- but EARLIER than the baseline+90s reading
//     already observed. Before the fix, this stale ALLOW would be served
//     without ever re-checking real authority. After the fix,
//     impersonationCeilingEffectiveNow clamps to the baseline+90s watermark,
//     correctly finds the cached entry expired (90s > 60s TTL), and forces a
//     fresh check -- which now (authority was revoked in the meantime) must
//     return denied.
func TestCachedImpersonationCeiling_ClockSteppedBackward_StaleAllowIsRechecked(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()

	baseline := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	const adminID, targetID = uint(1), uint(2)

	c.impersonationCeilingCache.Store("1:2", ceilingCacheEntry{err: nil, expiresAt: baseline.Add(ceilingCacheTTL)})
	c.impersonationCeilingClockWatermark = baseline.Add(90 * time.Second)
	c.now = func() time.Time { return baseline.Add(30 * time.Second) }

	// If the stale cache entry is (wrongly) trusted, none of this ever gets
	// consulted -- registering it is itself part of the assertion: a fresh
	// check must actually run.
	store.On("GetUser", ctx, adminID).Return(&models.User{ID: adminID, Username: "admin", IsActive: true, AccountState: AccountActive}, nil)
	store.On("GetUserRoleIDsAt", ctx, adminID, Scope{}).Return([]uint{5}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, adminID, Scope{}).Return([]uint{}, nil)
	store.On("RoleSetBypassesPermissionChecks", ctx, []uint{5}).Return(false, nil)
	store.On("RoleSetHasPermission", ctx, []uint{5}, "users.impersonate").Return(false, nil) // revoked since caching

	err := c.ReauthorizeImpersonation(ctx, adminID, targetID)
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a cached ALLOW predating this process's own later-observed watermark must be rechecked, not trusted: got %v", err)
	}
	store.AssertCalled(t, "GetUserRoleIDsAt", ctx, adminID, Scope{})
}

// TestImpersonationCeilingEffectiveNow_ClampsBackwardReadingToWatermark is a
// direct unit test of the clamp itself, mirroring
// TestOIDCEffectiveNow_ClampsBackwardReadingToWatermark (oidc_clock_regression_test.go).
func TestImpersonationCeilingEffectiveNow_ClampsBackwardReadingToWatermark(t *testing.T) {
	t.Parallel()
	c := &KeyorixCore{}
	watermark := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	c.impersonationCeilingClockWatermark = watermark

	backward := watermark.Add(-time.Hour)
	c.now = func() time.Time { return backward }
	require.Equal(t, watermark, c.impersonationCeilingEffectiveNow(), "a backward-looking reading must clamp up to the watermark")

	forward := watermark.Add(time.Hour)
	c.now = func() time.Time { return forward }
	require.Equal(t, forward, c.impersonationCeilingEffectiveNow(), "a forward reading must pass through unchanged and advance the watermark")
	require.Equal(t, forward, c.impersonationCeilingClockWatermark)
}
