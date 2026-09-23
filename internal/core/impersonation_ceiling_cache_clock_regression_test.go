// impersonation_ceiling_cache_clock_regression_test.go — 2026-09-23 finding
// (docs/findings/2026-09-23-FINDING-impersonation-ceiling-cache-clock-regression.md):
// exploit-shaped test for cachedImpersonationCeiling (authz.go). Both the
// cache write and the cache read compared against raw c.now(); a server clock
// stepped BACKWARD after a verdict is cached (NTP correction, manual time
// change) made the read-side comparison keep landing before expiresAt,
// extending a stale cached ALLOW past its intended 60s ceiling for as long as
// the clock stayed behind — even after the underlying permission was revoked.
// Fixed by switching both sides to authEffectiveNow() (auth.go), the same
// watermark-clamped clock ValidateSessionToken already uses for the session
// expiry checks that run immediately before this one in the same request.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// TestReauthorizeImpersonation_CeilingCacheClockSteppedBackward_RevokedStaysDenied
// is the exploit-shaped test. Sequence:
//
//  1. At T0, ReauthorizeImpersonation(admin, target) succeeds (admin holds
//     users.impersonate and outranks target) — cachedImpersonationCeiling
//     caches the ALLOW with expiresAt = T0+60s, and this first authEffectiveNow()
//     call warms the shared watermark to T0.
//  2. Simulate genuine forward progress elsewhere in the process (e.g. another
//     request's session-expiry check) by calling c.authEffectiveNow() directly
//     with the clock at T0+120s — past the cache's 60s TTL — advancing the
//     watermark to T0+120s. The impersonation cache entry itself is untouched.
//  3. The admin's users.impersonate grant is revoked (the mock's
//     RoleSetHasPermission stub for the second consumed call now returns
//     false).
//  4. Step c.now() BACKWARD to T0+30s — inside the cache's nominal 60s window,
//     and before the T0+120s already observed — and call
//     ReauthorizeImpersonation again for the SAME (admin, target) pair.
//
// Before the fix (raw c.now()), step 4's read compares the backward-stepped
// T0+30s against expiresAt=T0+60s: still before it, so the stale cached ALLOW
// is returned, bypassing the revocation entirely (CONSTRAINT BYPASS). After
// the fix, authEffectiveNow() at step 4 is clamped to the watermark
// (T0+120s, since raw T0+30s is behind it), which is past expiresAt: the
// cache is correctly treated as expired, a fresh (now-revoked) check runs,
// and ReauthorizeImpersonation returns the revocation error.
func TestReauthorizeImpersonation_CeilingCacheClockSteppedBackward_RevokedStaysDenied(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()

	const adminID, targetID = uint(1), uint(2)
	t0 := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

	store.On("GetUser", ctx, adminID).Return(&models.User{ID: adminID, Username: "admin", IsActive: true, AccountState: AccountActive}, nil)
	store.On("GetUserRoleIDsAt", ctx, adminID, Scope{}).Return([]uint{5}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, adminID, Scope{}).Return([]uint{}, nil)
	store.On("RoleSetBypassesPermissionChecks", ctx, []uint{5}).Return(false, nil)
	store.On("GetUserRoleScopes", ctx, targetID).Return([]Scope{}, nil)

	// Step 1: T0, admin still holds users.impersonate -- ALLOW, cached with
	// expiresAt = T0+60s. Consumed once: the second (post-revocation) call
	// below must NOT be able to reuse this stub.
	store.On("RoleSetHasPermission", ctx, []uint{5}, "users.impersonate").Return(true, nil).Once()
	c.now = func() time.Time { return t0 }
	err := c.ReauthorizeImpersonation(ctx, adminID, targetID)
	require.NoError(t, err, "sanity: the admin must still be authorized at T0, before anything is revoked or the clock moves")

	// Step 2: genuine forward progress elsewhere in the process, past the
	// cache's 60s TTL -- warms the shared watermark to T0+120s directly,
	// without touching the impersonation cache entry itself.
	c.now = func() time.Time { return t0.Add(120 * time.Second) }
	c.authEffectiveNow()

	// Step 3: the revocation. Next (and only next) matching call returns false.
	store.On("RoleSetHasPermission", ctx, []uint{5}, "users.impersonate").Return(false, nil).Once()

	// Step 4: the exploit attempt. Clock stepped BACKWARD to T0+30s -- still
	// nominally inside the cache's 60s window if read naively, and behind the
	// T0+120s already observed.
	c.now = func() time.Time { return t0.Add(30 * time.Second) }
	err = c.ReauthorizeImpersonation(ctx, adminID, targetID)
	require.Error(t, err, "a backward clock step must not let a cached ALLOW outlive a since-revoked impersonation permission")
	require.Contains(t, err.Error(), "impersonation authority has been revoked")
}
