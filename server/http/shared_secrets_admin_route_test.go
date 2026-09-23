// shared_secrets_admin_route_test.go — router-wiring coverage for
// GET /api/v1/users/{id}/shared-secrets. The handler-level tests in
// server/http/handlers cover the core authorization logic (S1 ceiling,
// existence-collapse, audit); this file confirms two things end to end,
// through the REAL router + permission middleware, that the handler-level
// tests can't: (1) the route is gated by the router's RequirePermission
// middleware at all (a caller with no secrets.read/users.read never reaches
// the handler), and (2) that gate alone is NOT an admin check -- a caller
// holding exactly the project_viewer permission bundle (secrets.read +
// users.read, nothing else) clears the router but must still be refused by
// core.ListSharedSecretsForUser's own roles.read check for a same-rank peer.
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

// TestSharedSecretsForUser_ProjectViewerLikeActorRefusedAgainstSameRankPeer:
// secrets.read (this route's own permission gate) is routinely bundled with
// users.read into ordinary, non-admin roles -- project_viewer holds exactly
// this pair (auth_bootstrap.go's defaultRoles) -- so an actor holding just
// that pair clears the ROUTER's permission middleware. It must still be
// refused by core.ListSharedSecretsForUser's own roles.read check when
// targeting a same-rank peer, since the S1 ceiling alone never refuses a
// target holding no MORE than the actor.
func TestSharedSecretsForUser_ProjectViewerLikeActorRefusedAgainstSameRankPeer(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	testCore := newTestCore(t)
	_ = createTestToken(t, testCore) // bootstraps admin/roles/permissions/project
	ctx := t.Context()

	perms, err := testCore.ListPermissions(ctx)
	require.NoError(t, err)
	var permIDs []uint
	for _, p := range perms {
		if p.Name == "secrets.read" || p.Name == "users.read" {
			permIDs = append(permIDs, p.ID)
		}
	}
	require.Len(t, permIDs, 2, "secrets.read and users.read must both exist after bootstrap")

	admin, err := testCore.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	_, _, err = testCore.CreateRole(ctx, admin.ID, "s6_viewer_like",
		"secrets.read+users.read only, mirrors project_viewer's exact permission bundle", permIDs)
	require.NoError(t, err)

	_, err = testCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "s6vieweractor", Email: "s6vieweractor@example.com",
		DisplayName: "S6 Viewer Actor", Password: "CorrectHorse9Battery!",
	})
	require.NoError(t, err)
	require.NoError(t, testCore.AssignRoleToUser(ctx, "s6vieweractor@example.com", "s6_viewer_like"))

	peer, err := testCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "s6viewerpeer", Email: "s6viewerpeer@example.com",
		DisplayName: "S6 Viewer Peer", Password: "CorrectHorse9Battery!",
	})
	require.NoError(t, err)

	session, _, err := testCore.Login(ctx, &core.LoginRequest{
		Username: "s6vieweractor", Password: "CorrectHorse9Battery!",
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
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/users/%d/shared-secrets", srv.URL, peer.ID), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+session.SessionToken)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"secrets.read+users.read (the project_viewer permission pair) clears the router's own gate but must not be enough, alone, to view a same-rank peer's shares")
}
