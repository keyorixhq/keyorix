package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// Follow-up to #2595: DELETE .../machine-identities/{machineId}/roles/{roleId}
// had no way to name an environment, so an environment-scoped grant could not be
// removed through the API. These tests assert the EFFECT (AuthorizePrincipal),
// not just the status code. Fixture: project 1 has dev=10, prod=11; project 2 has
// b-prod=20; machine 10 (project 1); role 2 grants secrets.read.

func deleteMachineRole(t *testing.T, serverURL, query string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, serverURL+"/api/v1/projects/1/machine-identities/10/roles/2"+query, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer admin-tok")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func machineCan(t *testing.T, c *core.KeyorixCore, sc core.Scope) bool {
	t.Helper()
	ok, err := c.AuthorizePrincipal(t.Context(), core.ActorTypeMachine, 10, "secrets.read", sc)
	require.NoError(t, err)
	return ok
}

func setupRemoveScopeServer(t *testing.T) (*core.KeyorixCore, string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	c := setupMachineRoleGrantScopeCore(t)
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return c, srv.URL
}

func TestRemoveMachineRole_EnvironmentScopedGrantRemovedByEnvironmentID(t *testing.T) {
	c, url := setupRemoveScopeServer(t)
	require.NoError(t, c.AssignMachineRole(t.Context(), 10, 2, core.Scope{ProjectID: 1, EnvironmentID: 10}, 1, false))
	require.True(t, machineCan(t, c, core.Scope{ProjectID: 1, EnvironmentID: 10}), "precondition: grant at env 10 is effective")

	// Without environment_id only the project-wide grant is addressed: the
	// env-scoped grant is not found (409 "not assigned") and must survive.
	require.Equal(t, http.StatusConflict, deleteMachineRole(t, url, ""))
	require.True(t, machineCan(t, c, core.Scope{ProjectID: 1, EnvironmentID: 10}), "project-wide removal must not touch an env-scoped grant")

	// Naming the wrong environment of the same project removes nothing.
	require.Equal(t, http.StatusConflict, deleteMachineRole(t, url, "?environment_id=11"))
	require.True(t, machineCan(t, c, core.Scope{ProjectID: 1, EnvironmentID: 10}))

	require.Equal(t, http.StatusOK, deleteMachineRole(t, url, "?environment_id=10"))
	require.False(t, machineCan(t, c, core.Scope{ProjectID: 1, EnvironmentID: 10}), "grant at env 10 must be gone")
}

func TestRemoveMachineRole_CrossProjectEnvironmentRejectedAndNothingRemoved(t *testing.T) {
	c, url := setupRemoveScopeServer(t)
	require.NoError(t, c.AssignMachineRole(t.Context(), 10, 2, core.Scope{ProjectID: 1, EnvironmentID: 10}, 1, false))

	// Env 20 belongs to project 2, not project 1.
	require.Equal(t, http.StatusBadRequest, deleteMachineRole(t, url, "?environment_id=20"))
	// Non-existent environment: 404 (same mapping as the grant path), fail closed.
	require.Equal(t, http.StatusNotFound, deleteMachineRole(t, url, "?environment_id=9999"))
	// Malformed value must not fall back to the project-wide grant.
	require.Equal(t, http.StatusBadRequest, deleteMachineRole(t, url, "?environment_id=abc"))

	require.True(t, machineCan(t, c, core.Scope{ProjectID: 1, EnvironmentID: 10}), "rejected removals must leave the grant in place")
}
