// secrets_crud_resolved_secret_id_check_test.go — coordinator review item 5
// on #2420: GetSecret's machine branch must not trust a context-resolved
// secret that doesn't match the path's own id.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// TestGetSecret_MachineBranch_IgnoresMismatchedResolvedSecret proves the
// fix for coordinator review item 5 on #2420: GetSecret's machine branch
// used to trust middleware.GetResolvedSecretFromContext unconditionally —
// correct ONLY because every real route wires the middleware to resolve
// the SAME secret the path id names. This test simulates what a future
// middleware or route-wiring bug would produce: a resolved secret in the
// context that does NOT match the path id. Before the fix, the handler
// would have served the WRONG secret's metadata and value under this
// request's authorization. After the fix, a mismatch is treated the same
// as "nothing resolved" and the handler fetches the path's own id fresh.
func TestGetSecret_MachineBranch_IgnoresMismatchedResolvedSecret(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	h, svc := newIsolatedSecretHandlerS10(t)
	ctx := context.Background()

	proj, err := svc.CreateProject(ctx, "s2420-item5-proj", "coordinator review item 5")
	require.NoError(t, err)
	envs, err := svc.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	secretA, err := svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "secret-a", Value: []byte("value-a"), Type: "generic",
		ProjectID: proj.ID, EnvironmentID: envs[0].ID, CreatedBy: "testuser",
	})
	require.NoError(t, err)
	secretB, err := svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "secret-b", Value: []byte("value-b"), Type: "generic",
		ProjectID: proj.ID, EnvironmentID: envs[0].ID, CreatedBy: "testuser",
	})
	require.NoError(t, err)
	require.NotEqual(t, secretA.ID, secretB.ID)

	// Path id names secretB, but the context carries secretA as the
	// "already-resolved" secret -- the mismatch this fix must catch.
	url := fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secretB.ID)
	r := httptest.NewRequest(http.MethodGet, url, nil)
	r = withMachineCtxS10(r)
	r = r.WithContext(customMiddleware.WithResolvedSecret(r.Context(), secretA))
	r = withChiParam(r, "id", fmt.Sprintf("%d", secretB.ID))
	w := httptest.NewRecorder()

	h.GetSecret(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var body map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	data, _ := body["data"].(map[string]any)
	require.NotNil(t, data)
	secretWire, _ := data["secret"].(map[string]any)
	require.NotNil(t, secretWire)

	assert.Equal(t, float64(secretB.ID), secretWire["id"], "must serve the path id's own secret, not the mismatched resolved one")
	assert.Equal(t, "secret-b", secretWire["name"])
	assert.Equal(t, "value-b", data["value"], "must serve the path id's own value, not secret A's")
}
