// active_transition_admin_rank_ceiling_test.go — F5 (system-proxy-target-authority
// audit): PUT /api/v1/system/users/{id}/active-transition
// (UpdateUserIfActiveStateMatchesProxy) required users.write
// (active-transition-proxy-users-write-001, already closed) but that alone
// is not sufficient reason to trust a caller against every possible target:
// a users.write holder with otherwise minimal privilege could still rewrite
// a much higher-authority account's identity (email, in particular) and
// pivot into taking it over via a password-reset flow. This file covers the
// admin-rank ceiling (core.RequireEqualOrGreaterAdminAuthority, already
// established for impersonation) closing that narrower, second gap.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	stdhttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestActiveTransitionProxy_UsersWriteHolder_CanUpdateNonAdminUser_RealServer
// is the control: the legitimate caller this route exists to serve — a
// principal holding users.write (the SAME ceiling the human-facing
// PUT /api/v1/users/{id} route requires) — can still successfully update an
// ORDINARY, unprivileged user through this proxy. Proves the admin-rank
// ceiling is an added restriction, not an accidental blanket refusal.
//
// The target is created via a direct storage insert, NOT core.CreateUser --
// core.CreateUser auto-assigns the system_viewer baseline role (system.read),
// which would make this test also exercise the admin-rank ceiling rather
// than isolating what THIS test is actually about: an unprivileged target
// has nothing for that ceiling to protect, so it must never fire here.
func TestActiveTransitionProxy_UsersWriteHolder_CanUpdateNonAdminUser_RealServer(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	testCore := newTestCore(t)
	router, err := NewRouter(&config.Config{}, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	ctx := context.Background()
	createTestToken(t, testCore)

	target, err := testCore.Storage().CreateUser(ctx, &models.User{
		Username: "f5-control-target", UsernameFolded: "f5-control-target",
		Email: "f5-control-target@example.com", EmailFolded: "f5-control-target@example.com",
		DisplayName: "F5 Control Target", IsActive: true, AccountState: "active",
	})
	require.NoError(t, err)

	callerToken := createSystemWriteAndUsersWriteToken(t, testCore)

	body, err := json.Marshal(map[string]any{
		"username":     target.Username,
		"email":        target.Email,
		"display_name": "Legitimately Renamed",
		"active":       target.IsActive,
		"updated_at":   target.UpdatedAt,
		"from_active":  target.IsActive,
	})
	require.NoError(t, err)
	req, err := stdhttp.NewRequest(stdhttp.MethodPut,
		fmt.Sprintf("%s/api/v1/system/users/%d/active-transition", server.URL, target.ID), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+callerToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := stdhttp.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var respBuf bytes.Buffer
	_, err = respBuf.ReadFrom(resp.Body)
	require.NoError(t, err)
	t.Logf("system.write+users.write caller PUT active-transition on non-admin target: status=%d body=%s", resp.StatusCode, respBuf.String())

	require.Equal(t, stdhttp.StatusOK, resp.StatusCode, "a legitimate users.write holder must still be able to use this route")

	after, err := testCore.Storage().GetUser(ctx, target.ID)
	require.NoError(t, err)
	assert.Equal(t, "Legitimately Renamed", after.DisplayName, "the legitimate write must actually apply")
}

// TestActiveTransitionProxy_UsersWriteHolderWithoutAdminRank_CannotRewriteAdmin_RealServer
// is the admin-rank ceiling's own regression: users.write alone is not
// enough to rewrite a target who holds MORE authority than the caller. The
// caller here holds system.write + users.write (real, legitimate authority
// to use this route for an ordinary user — see the control test above) but
// is not admin-tier and holds none of the seeded admin's other permissions.
// Asserts the effect: refused, and the admin's row is unchanged.
func TestActiveTransitionProxy_UsersWriteHolderWithoutAdminRank_CannotRewriteAdmin_RealServer(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	testCore := newTestCore(t)
	router, err := NewRouter(&config.Config{}, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	ctx := context.Background()
	createTestToken(t, testCore)
	admin, err := testCore.Storage().GetUserByUsername(ctx, "testadmin")
	require.NoError(t, err)
	beforeEmail := admin.Email

	callerToken := createSystemWriteAndUsersWriteToken(t, testCore)

	body, err := json.Marshal(map[string]any{
		"username":     admin.Username,
		"email":        "lesser-privilege-caller@example.invalid",
		"display_name": admin.DisplayName,
		"active":       admin.IsActive,
		"updated_at":   admin.UpdatedAt,
		"from_active":  admin.IsActive,
	})
	require.NoError(t, err)
	req, err := stdhttp.NewRequest(stdhttp.MethodPut,
		fmt.Sprintf("%s/api/v1/system/users/%d/active-transition", server.URL, admin.ID), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+callerToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := stdhttp.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var respBuf bytes.Buffer
	_, err = respBuf.ReadFrom(resp.Body)
	require.NoError(t, err)
	t.Logf("users.write holder (non-admin-tier) PUT active-transition on admin: status=%d body=%s", resp.StatusCode, respBuf.String())

	assert.Equal(t, stdhttp.StatusForbidden, resp.StatusCode,
		"a caller with less effective authority than the target must be refused, even holding users.write")
	assert.Contains(t, respBuf.String(), "PERMISSION_DENIED")

	after, err := testCore.Storage().GetUser(ctx, admin.ID)
	require.NoError(t, err)
	assert.Equal(t, beforeEmail, after.Email, "CEILING VIOLATED if this differs: admin email must be unchanged")
}

// TestActiveTransitionProxy_Admin_CanRewriteAdmin_RealServer is the
// admin-rank ceiling's control: an ACTUAL admin-tier caller (holding at
// least the target's own authority) can still use this route against a
// privileged target — the ceiling is an added restriction on lesser-privilege
// callers, not an unconditional block on modifying any privileged user.
func TestActiveTransitionProxy_Admin_CanRewriteAdmin_RealServer(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	testCore := newTestCore(t)
	router, err := NewRouter(&config.Config{}, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	ctx := context.Background()
	adminToken := createTestToken(t, testCore)
	admin, err := testCore.Storage().GetUserByUsername(ctx, "testadmin")
	require.NoError(t, err)

	body, err := json.Marshal(map[string]any{
		"username":     admin.Username,
		"email":        admin.Email,
		"display_name": "Admin Self-Renamed",
		"active":       admin.IsActive,
		"updated_at":   admin.UpdatedAt,
		"from_active":  admin.IsActive,
	})
	require.NoError(t, err)
	req, err := stdhttp.NewRequest(stdhttp.MethodPut,
		fmt.Sprintf("%s/api/v1/system/users/%d/active-transition", server.URL, admin.ID), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := stdhttp.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var respBuf bytes.Buffer
	_, err = respBuf.ReadFrom(resp.Body)
	require.NoError(t, err)
	t.Logf("admin PUT active-transition on self: status=%d body=%s", resp.StatusCode, respBuf.String())

	require.Equal(t, stdhttp.StatusOK, resp.StatusCode, "an actual admin-tier caller must still be able to use this route")

	after, err := testCore.Storage().GetUser(ctx, admin.ID)
	require.NoError(t, err)
	assert.Equal(t, "Admin Self-Renamed", after.DisplayName, "the legitimate write must actually apply")
}
