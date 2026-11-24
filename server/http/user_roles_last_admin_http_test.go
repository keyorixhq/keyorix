package http

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUpdateUserRolesHTTP_RemovingLastInstallAdmin_Conflict409 is the nightly strict
// OpenAPI fuzz finding #4672: PUT /api/v1/users/{id}/roles that replaces the sole
// install administrator's global roles with nothing is refused by the last-admin guard
// (storage.ErrWouldStrandLastAdmin). The handler's legacy switch did not know the
// sentinel and answered an undeclared 500 InternalError "Failed to update user roles".
// It is a refusal of the target's state, a 409 ConflictError declared in openapi.yaml,
// and nothing changes.
func TestUpdateUserRolesHTTP_RemovingLastInstallAdmin_Conflict409(t *testing.T) {
	w := newRoleScopeHTTPWorld(t) // user 2 is the only global administrator

	before := w.userGrants(t, 2)
	status, body := w.put(t, "/api/v1/users/2/roles", `{"role_ids":[],"project_id":0}`)
	require.Equal(t, http.StatusConflict, status, body)
	require.Contains(t, body, "ConflictError")
	require.Contains(t, body, "last install administrator", "the 409 carries core's refusal text")
	require.NotContains(t, body, "InternalError")
	require.Equal(t, before, w.userGrants(t, 2), "the refused replacement changed the administrator's roles")
}
