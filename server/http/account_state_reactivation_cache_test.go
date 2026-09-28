// account_state_reactivation_cache_test.go — regression coverage for a real
// auth-cache/DB divergence found by FuzzAuthCacheDifferential (FUZZ-GAPS G5)
// within seconds of its first fuzzing run.
//
// ROOT CAUSE: setAccountState (internal/core/account_state.go), the shared
// implementation behind SuspendUser/ReactivateUser/RequirePasswordReset/etc,
// collected every one of the target user's session AND personal-access-token
// hashes and evicted them from the HTTP auth cache via
// customMiddleware.InvalidateTokenCacheByHash for EVERY account-state
// transition — including a transition INTO plain "active" (ReactivateUser).
// InvalidateTokenCacheByHash does not do a plain delete; per its own doc
// comment it writes a short-lived NEGATIVE tombstone (so an in-flight
// positive validation racing a real revoke can't resurrect a stale entry).
// Writing that tombstone unconditionally means: a personal access token
// created WHILE an account is suspended, then hit by that SAME account's
// later reactivation sweep, gets spuriously rejected (401 "Invalid or
// expired token") for up to invalidTokenTTL — even though the credential was
// NEVER cached before, the account is already active again, and nothing
// about the token itself is invalid. The fix scopes the sweep to only run
// when the TARGET state is more restrictive than plain active
// (AccountLoginBlocked || AccountRestricted) — moving toward active never
// needed a proactive evict for correctness in the first place: an
// over-restrictive stale cache entry is safe (fail-closed), and any EXISTING
// positive entry already gets AccountState/Restricted refreshed on every hit
// by serveAuthCacheHit's own re-check, independent of this sweep.
package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// TestReactivateUser_DoesNotTombstoneNeverCachedPAT is the deterministic
// regression test. RED on unfixed code: a PAT created while the account is
// suspended is immediately, spuriously denied the first time it is ever
// used, right after the SAME account is reactivated — even though the
// account is active and the PAT was never revoked, expired, or previously
// cached at all.
func TestReactivateUser_DoesNotTombstoneNeverCachedPAT(t *testing.T) {
	w := srrSetupWorld(t, "asrt-reactivate.db")
	ctx := context.Background()

	c := core.NewKeyorixCore(w.ls)
	c.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)

	victim, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "asrt-victim", Email: "asrt-victim@x.io", Password: "Xk7#Qp2$Rn5@Wv9!",
	})
	if err != nil || victim == nil {
		t.Fatalf("create victim: %v", err)
	}
	var role models.Role
	if err := w.db.Where("name = ?", "srr-reader").First(&role).Error; err != nil {
		t.Fatalf("lookup role: %v", err)
	}
	var proj models.Project
	if err := w.db.Where("name = ?", "srr").First(&proj).Error; err != nil {
		t.Fatalf("lookup project: %v", err)
	}
	if err := c.AssignUserRole(ctx, 0, victim.ID, role.ID, core.Scope{ProjectID: proj.ID}, false); err != nil {
		t.Fatalf("grant victim read role: %v", err)
	}

	// Suspend the account, THEN create the PAT while it's still suspended —
	// this PAT has never been validated, never been cached, positive or
	// negative, at any point before this test's own assertion below.
	if err := c.SuspendUser(ctx, w.admin.ID, victim.ID); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	res, err := c.CreateOwnPAT(ctx, victim.ID, "asrt-pat", nil, nil, 0, 0, nil)
	if err != nil || res == nil {
		t.Fatalf("create PAT while suspended: %v", err)
	}

	// Reactivate. This is the sweep call under test: on unfixed code it
	// unconditionally tombstones every hash it collects, including this PAT's,
	// even though moving TO active needs no proactive eviction.
	if err := c.ReactivateUser(ctx, w.admin.ID, victim.ID); err != nil {
		t.Fatalf("reactivate: %v", err)
	}

	r, err := NewRouter(&config.Config{}, c)
	if err != nil {
		t.Fatalf("router: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/value?ref="+w.ref, nil)
	req.Header.Set("Authorization", "Bearer "+res.PlainToken)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("a PAT created during suspension, first used right after the SAME account's reactivation, must authenticate (the account is active and the PAT was never touched before) -- got %d, want 200", rec.Code)
	}
}
