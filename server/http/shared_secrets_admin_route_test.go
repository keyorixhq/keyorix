// shared_secrets_admin_route_test.go — router-wiring coverage for
// GET /api/v1/users/{id}/shared-secrets. The handler-level tests in
// server/http/handlers cover the core authorization logic (S1 ceiling,
// existence-collapse, audit); this file confirms the ROUTE ITSELF is gated
// by the router's RequirePermission middleware -- an ordinary authenticated
// user holding only the default baseline role (no secrets.read/users.read)
// must be refused before ever reaching the handler.
package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// TestSharedSecretsForUser_NonAdminRefusedByRouterPermissionGate: a user
// created via the normal CreateUser path (which grants only the baseline
// system_viewer role -- system.read, not secrets.read/users.read) must be
// refused with 403 when hitting the admin-scoped route for ANOTHER user,
// entirely at the router's permission-middleware layer, before the handler's
// own S1 ceiling logic ever runs.
func TestSharedSecretsForUser_NonAdminRefusedByRouterPermissionGate(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	testCore := newTestCore(t)
	_ = createTestToken(t, testCore) // bootstraps the admin user/roles/project

	ctx := t.Context()
	admin, err := testCore.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)

	// An ordinary user created through the normal path: baseline role only.
	nonAdmin, err := testCore.CreateUser(ctx, &core.CreateUserRequest{
		Username:    "s6routercaller",
		Email:       "s6routercaller@example.com",
		DisplayName: "S6 Router Caller",
		Password:    "CorrectHorse9Battery!",
	})
	require.NoError(t, err)

	session, _, err := testCore.Login(ctx, &core.LoginRequest{
		Username: "s6routercaller",
		Password: "CorrectHorse9Battery!",
	})
	require.NoError(t, err)

	cfg := &config.Config{
		Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"}},
	}
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/users/%d/shared-secrets", srv.URL, admin.ID), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+session.SessionToken)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"a caller holding only the baseline role (no secrets.read/users.read) must be refused by the router's own permission gate")
	assert.NotZero(t, nonAdmin.ID)
}
