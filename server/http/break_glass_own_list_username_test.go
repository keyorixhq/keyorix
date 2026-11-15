package http

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
)

// #3147 / #3741 regression, through the real router: the user who activated
// break-glass lists their own grant (200, not 403) and the row names them; a user
// with no role in the project gets the documented refusal (403) and sees nothing.
func TestBreakGlassOwnList_ActivatorSeesOwnGrantWithUsername_UnrelatedUserRefused(t *testing.T) {
	f := newBGOwnFixture(t)

	path := "/api/v1/projects/" + uid(f.d.projectID) + "/break-glass"
	code, raw := doMachineRequest(t, f.d.srv, f.aliceTok, http.MethodGet, path, nil)
	require.Equal(t, http.StatusOK, code, raw)
	var out struct {
		Data struct {
			Activations []struct {
				ID       uint   `json:"id"`
				UserID   uint   `json:"user_id"`
				Username string `json:"username"`
			} `json:"activations"`
			Scope string `json:"scope"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
	assert.Equal(t, core.BreakGlassListScopeOwn, out.Data.Scope, raw)
	found := false
	for _, a := range out.Data.Activations {
		assert.Equal(t, f.d.aliceID, a.UserID, raw)
		assert.Equal(t, "alice", a.Username, "the row names the user next to user_id: %s", raw)
		found = found || a.ID == f.aliceP
	}
	assert.True(t, found, "the activator's live grant %d must be listed: %s", f.aliceP, raw)

	code, raw = doMachineRequest(t, f.d.srv, f.oscarTok, http.MethodGet, path, nil)
	assert.Equal(t, http.StatusForbidden, code, raw)
	assert.NotContains(t, raw, "alice", raw)
	assert.NotContains(t, raw, bgOwnJustificationPrefix, raw)
}
