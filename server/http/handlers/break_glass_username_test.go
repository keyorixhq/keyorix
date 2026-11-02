// break_glass_username_test.go — the break-glass list carries an additive
// `username` per activation (#3741, LIFECYCLE-WORDING-1) so the UI and CLI can
// show who activated; user_id stays, and a deleted user simply has no username.
package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestListBreakGlassActivations_CarriesUsername(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)

	dana := &models.User{Username: "dana", UsernameFolded: "dana", Email: "dana@example.com",
		EmailFolded: "dana@example.com", AccountState: "active"}
	require.NoError(t, db.Create(dana).Error)
	gone := &models.User{Username: "gone", UsernameFolded: "gone", Email: "gone@example.com",
		EmailFolded: "gone@example.com", AccountState: "active"}
	require.NoError(t, db.Create(gone).Error)
	danaAct := seedBreakGlassActivationS13(t, db, dana.ID, "active")
	goneAct := seedBreakGlassActivationS13(t, db, gone.ID, "active")
	require.NoError(t, db.Delete(&models.User{}, gone.ID).Error, "soft-delete the user")

	req := withUserCtxS7(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.ListBreakGlassActivations(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var env struct {
		Data struct {
			Activations []map[string]any `json:"activations"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
	byID := map[uint]map[string]any{}
	for _, a := range env.Data.Activations {
		byID[uint(a["id"].(float64))] = a
	}
	require.Contains(t, byID, danaAct)
	require.Contains(t, byID, goneAct)

	assert.Equal(t, "dana", byID[danaAct]["username"])
	assert.EqualValues(t, dana.ID, byID[danaAct]["user_id"], "existing field unchanged")
	assert.Equal(t, "project_developer", byID[danaAct]["role_name"], "existing fields still flattened")
	assert.NotContains(t, w.Body.String(), "dana@example.com", "username only, never an email")

	assert.NotContains(t, byID[goneAct], "username", "a deleted user has no username")
	assert.EqualValues(t, gone.ID, byID[goneAct]["user_id"])
}
