// users_active_transition_proxy_lastadmin_test.go — G80 overnight campaign,
// Tier 1 Group A fix #3. UpdateUserIfActiveStateMatchesProxy never called the
// last-global-admin lockout guard core.UpdateUser's deactivating branch applies
// (internal/core/users.go:384) — a caller could deactivate the install's only
// admin through this raw proxy with no protection at all. Fixed by calling
// core.GuardLastAdminDeactivation (a target-state check, no actor needed) before
// the conditional write whenever the transition is a deactivation
// (FromActive:true, Active:false).
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateUserIfActiveStateMatchesProxy_RefusesLastAdminDeactivation_RealServer
// attempts to deactivate the seeded install admin (UserID=1, the only global
// admin freshCoreS12WithAdmin creates) via the raw proxy and asserts it's
// refused rather than silently applied.
func TestUpdateUserIfActiveStateMatchesProxy_RefusesLastAdminDeactivation_RealServer(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	admin, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)
	require.True(t, admin.IsActive)

	body, err := json.Marshal(map[string]interface{}{
		"username":    admin.Username,
		"email":       admin.Email,
		"active":      false,
		"updated_at":  time.Now(),
		"from_active": true,
	})
	require.NoError(t, err)
	req := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(body)), map[string]string{"id": machineUintToStr(admin.ID)})
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	assert.Equal(t, 403, w.Code, "deactivating the install's last admin must be refused: %s", w.Body.String())

	reloaded, err := cs.Storage().GetUser(ctx, admin.ID)
	require.NoError(t, err)
	assert.True(t, reloaded.IsActive, "the last admin must still be active -- the deactivation must not have persisted")
}

// TestUpdateUserIfActiveStateMatchesProxy_AllowsNonAdminDeactivation_RealServer
// is the control case: deactivating an ordinary, non-admin user must still
// succeed through the same proxy -- the guard must not become an unconditional
// refusal.
func TestUpdateUserIfActiveStateMatchesProxy_AllowsNonAdminDeactivation_RealServer(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := t.Context()

	regular, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "g80lastadminregular", Email: "g80-lastadmin-regular@example.com",
		DisplayName: "G80 Regular", Password: "NotArealpassword123!",
	})
	require.NoError(t, err)

	body, err := json.Marshal(map[string]interface{}{
		"username":    regular.Username,
		"email":       regular.Email,
		"active":      false,
		"updated_at":  time.Now(),
		"from_active": true,
	})
	require.NoError(t, err)
	req := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(body)), map[string]string{"id": machineUintToStr(regular.ID)})
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	require.Equal(t, 200, w.Code, "deactivating a non-admin user must still succeed: %s", w.Body.String())

	reloaded, err := cs.Storage().GetUser(ctx, regular.ID)
	require.NoError(t, err)
	assert.False(t, reloaded.IsActive)
}
