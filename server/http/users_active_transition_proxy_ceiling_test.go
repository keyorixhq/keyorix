// users_active_transition_proxy_ceiling_test.go — F5 regression: the /system
// active-transition proxy (server/http/handlers/users_active_transition_proxy.go)
// used to accept any caller holding only the /system route group's own
// blanket system.write gate, with no per-target authority check at all,
// letting a system.write-only principal rewrite ANY user's username/email/
// display_name/active state -- including a global admin's.
//
// Originally zz_research_active_transition_probe_test.go (2026-09-20 scratch
// research), confirmed live against origin/main bb93b549: HTTP 200, the
// target's email actually changed. Promoted here as the permanent regression
// test, RED on bb93b549 and GREEN after core.RequireUsersWriteAuthority
// closes it (internal/core/users.go).
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/require"
)

// TestUpdateUserIfActiveStateMatchesProxy_SystemWriteOnly_CannotRewriteAdminEmail
// asserts the EFFECT (the row's real email, re-read from storage after the
// request), not just the status code -- a 403 that still wrote something
// would still fail this test.
func TestUpdateUserIfActiveStateMatchesProxy_SystemWriteOnly_CannotRewriteAdminEmail(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	c := newTestCore(t)
	ctx := context.Background()
	createTestToken(t, c)
	admin, err := c.Storage().GetUserByUsername(ctx, "testadmin")
	require.NoError(t, err)
	isAdmin, err := c.IsGlobalAdmin(ctx, admin.ID)
	require.NoError(t, err)
	require.True(t, isAdmin, "need a global admin target")
	before := admin.Email

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	token := createSystemWriteOnlyToken(t, c)
	body, err := json.Marshal(map[string]any{
		"username": admin.Username, "email": "ceiling-probe-changed@example.invalid",
		"display_name": admin.DisplayName, "active": admin.IsActive, "updated_at": admin.UpdatedAt, "from_active": admin.IsActive,
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/api/v1/system/users/%d/active-transition", srv.URL, admin.ID), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	after, err := c.Storage().GetUser(ctx, admin.ID)
	require.NoError(t, err)
	t.Logf("status=%d admin email before=%q after=%q", resp.StatusCode, before, after.Email)
	require.Equal(t, http.StatusForbidden, resp.StatusCode,
		"a system.write-only caller with no users.write must be refused rewriting another user's profile")
	require.Equal(t, before, after.Email,
		"CEILING VIOLATED: a system.write-only principal changed a global admin's email via the active-transition proxy")
}

// TestUpdateUserIfActiveStateMatchesProxy_UsersWriteHolder_CanRewriteOtherUserEmail
// is F5's control case: a caller who genuinely holds users.write (the SAME
// authority the human-facing PUT /api/v1/users/{id} route already requires)
// must still be able to use this route -- the fix must not turn into a
// blanket denial.
func TestUpdateUserIfActiveStateMatchesProxy_UsersWriteHolder_CanRewriteOtherUserEmail(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()
	c := newTestCore(t)
	ctx := context.Background()
	createTestToken(t, c)
	admin, err := c.Storage().GetUserByUsername(ctx, "testadmin")
	require.NoError(t, err)

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	token := createSystemWriteAndUsersWriteToken(t, c)
	const newEmail = "ceiling-probe-authorized@example.invalid"
	body, err := json.Marshal(map[string]any{
		"username": admin.Username, "email": newEmail,
		"display_name": admin.DisplayName, "active": admin.IsActive, "updated_at": admin.UpdatedAt, "from_active": admin.IsActive,
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/api/v1/system/users/%d/active-transition", srv.URL, admin.ID), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	after, err := c.Storage().GetUser(ctx, admin.ID)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, newEmail, after.Email,
		"a caller who genuinely holds users.write must still be able to edit another user's profile via this route")
}
