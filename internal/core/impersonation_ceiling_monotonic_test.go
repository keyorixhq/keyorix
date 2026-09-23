// impersonation_ceiling_monotonic_test.go — #1983 investigation follow-up,
// closed as NO BUG: cachedImpersonationCeiling (authz.go) is an in-process
// TTL cache -- both the write (entry.expiresAt = c.now().Add(ceilingCacheTTL))
// and the read (c.now().Before(entry.expiresAt)) happen in the SAME process,
// using bare c.now(). In production c.now defaults to time.Now, and Go's
// time.Time retains a monotonic clock reading through Add()/Before()/After()
// as long as neither operand has had it stripped (by .UTC(), .Round(), a
// round-trip through persistence, etc.) -- so this comparison was ALREADY
// immune to a host wall-clock step (an operator's `date -s`, an NTP
// correction) before any of this investigation's changes, via Go's own
// language guarantee, not anything this code does explicitly.
//
// Two proposed fixes (#1994, #1995 -- both closed, neither merged) would
// have introduced a REAL regression here: both routed this comparison
// through a new "effectiveNow" wrapper modeled on authEffectiveNow/
// shareEffectiveNow (auth.go, permissions.go), which calls .UTC() before
// clamping to a watermark. .UTC() unconditionally strips the monotonic
// reading. Once stripped, the SAME backward wall-clock step this cache
// already tolerated instead causes the watermark to freeze "now" at the
// pre-step reading -- extending trust in a cached verdict well past its
// intended 60s TTL, which is the OPPOSITE of what both PRs set out to fix.
//
// The authEffectiveNow/shareEffectiveNow pattern is correct where it's
// actually used: comparing against a PERSISTED instant (a DB ExpiresAt
// column, a JWT exp/iat claim) that was serialized and deserialized and so
// never had a monotonic reading to begin with -- there, wall-clock-only
// comparison is the only option, and the watermark is the right defense
// against a backward step. cachedImpersonationCeiling compares two
// in-process readings that both still carry monotonic, so the same defense
// mechanism, applied here, discards a stronger guarantee already in place
// and replaces it with a weaker one.
//
// This file pins the invariant the fix (staying as bare c.now()) depends on,
// so a future edit can't silently reintroduce the #1994/#1995 regression.
package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// TestCachedImpersonationCeiling_RealClockRetainsMonotonicReading is the
// direct, deterministic mechanism check: with the real clock wired in,
// cachedImpersonationCeiling's cache write must retain a monotonic reading.
// time.Time.String() appends "m=+<seconds>" when a monotonic reading is
// present (documented behavior, time package). A no-op today; this is the
// test that catches the #1994/#1995 shape directly and immediately -- routing
// this call through anything that calls .UTC() (authEffectiveNow,
// shareEffectiveNow, or a new equivalent) strips the monotonic reading
// unconditionally, and this assertion goes red on the very first line of
// output, with no timing or scheduling involved.
func TestCachedImpersonationCeiling_RealClockRetainsMonotonicReading(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newImpersonationCore(store)
	c.now = time.Now // override the fixture's fixed (non-monotonic) date
	ctx := context.Background()
	const adminID, targetID = uint(1), uint(2)

	store.On("GetUser", ctx, adminID).Return(&models.User{ID: adminID, Username: "admin", IsActive: true, AccountState: AccountActive}, nil)
	store.On("GetUserRoleIDsAt", ctx, adminID, Scope{}).Return([]uint{5}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, adminID, Scope{}).Return([]uint{}, nil)
	store.On("RoleSetBypassesPermissionChecks", ctx, []uint{5}).Return(false, nil)
	store.On("RoleSetHasPermission", ctx, []uint{5}, "users.impersonate").Return(true, nil)
	store.On("GetUserRoleScopes", ctx, targetID).Return([]Scope{}, nil)

	require.NoError(t, c.ReauthorizeImpersonation(ctx, adminID, targetID))

	v, ok := c.impersonationCeilingCache.Load("1:2")
	require.True(t, ok, "sanity: the cache must have been populated")
	entry := v.(ceilingCacheEntry)
	require.Contains(t, entry.expiresAt.String(), "m=+",
		"entry.expiresAt lost its monotonic reading -- cachedImpersonationCeiling must compute it "+
			"from a bare c.now().Add(...), never through anything that calls .UTC() first")
}

// TestCachedImpersonationCeiling_TTLExpiryUsesGenuineElapsedTime is the
// behavioral companion: an entry cached 61s ago (in monotonic terms) must be
// treated as expired and rechecked, using REAL time.Now()-derived values
// throughout (not a synthetic fixed clock) -- Go's monotonic reading is a
// property of genuine runtime clock readings; a fixed time.Time literal (as
// this package's other impersonation tests use, deliberately, for
// determinism) never carries one, so it cannot exercise this property at
// all. That gap is exactly why the exploit-shaped tests #1994 and #1995 each
// shipped alongside their own regression -- neither the tests nor the fixes
// touched a genuinely monotonic value.
//
// The 61s of elapsed time is real: it comes from Add() on an actual
// time.Now() reading, which Go's own documentation guarantees preserves the
// monotonic component exactly as continued execution would -- there is no
// public API to fabricate a time.Time whose wall and monotonic components
// diverge (by design: a forgeable monotonic reading would defeat its own
// purpose), so this is the closest faithful reproduction of "genuine elapsed
// process time" achievable without an actual 61-second sleep in the suite.
func TestCachedImpersonationCeiling_TTLExpiryUsesGenuineElapsedTime(t *testing.T) {
	t.Parallel()
	store := new(MockStorage)
	c := newImpersonationCore(store)
	c.now = time.Now
	ctx := context.Background()
	const adminID, targetID = uint(1), uint(2)

	store.On("GetUser", ctx, adminID).Return(&models.User{ID: adminID, Username: "admin", IsActive: true, AccountState: AccountActive}, nil)
	store.On("GetUserRoleIDsAt", ctx, adminID, Scope{}).Return([]uint{5}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, adminID, Scope{}).Return([]uint{}, nil)
	store.On("RoleSetBypassesPermissionChecks", ctx, []uint{5}).Return(false, nil)
	store.On("GetUserRoleScopes", ctx, targetID).Return([]Scope{}, nil)
	store.On("RoleSetHasPermission", ctx, []uint{5}, "users.impersonate").Return(true, nil).Once()

	// Populate the cache with an ALLOW verdict.
	require.NoError(t, c.ReauthorizeImpersonation(ctx, adminID, targetID))

	// Advance 61s of genuinely monotonic-linked time -- past the 60s TTL.
	base := c.now()
	later := base.Add(61 * time.Second)
	c.now = func() time.Time { return later }

	// Authority was revoked in the meantime.
	store.On("RoleSetHasPermission", ctx, []uint{5}, "users.impersonate").Return(false, nil).Once()

	err := c.ReauthorizeImpersonation(ctx, adminID, targetID)
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a cache entry past its 60s TTL must be rechecked, not trusted: got %v", err)
	}
	store.AssertNumberOfCalls(t, "RoleSetHasPermission", 2)
}
