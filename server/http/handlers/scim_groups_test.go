package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// provisionUser creates a SCIM user and returns its SCIM id.
func provisionUser(t *testing.T, h *SCIMHandler, userName string) string {
	t.Helper()
	body := `{"userName":"` + userName + `"}`
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	id, _ := decodeSCIM(t, w)["id"].(string)
	require.NotEmpty(t, id)
	return id
}

func groupMemberValues(g map[string]interface{}) []string {
	var out []string
	members, _ := g["members"].([]interface{})
	for _, m := range members {
		if mm, ok := m.(map[string]interface{}); ok {
			if v, ok := mm["value"].(string); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

func TestSCIM_GroupsCreateReplacePatchDelete(t *testing.T) {
	h, _ := setupSCIMTest(t)
	u1 := provisionUser(t, h, "alice@corp.com")
	u2 := provisionUser(t, h, "bob@corp.com")

	// Create a group with alice as the initial member.
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineers","members":[{"value":"` + u1 + `"}]}`
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	created := decodeSCIM(t, w)
	assert.Equal(t, "Engineers", created["displayName"])
	assert.ElementsMatch(t, []string{u1}, groupMemberValues(created))
	gid, _ := created["id"].(string)
	require.NotEmpty(t, gid)

	// PUT replaces the full member set: alice → bob.
	put := `{"displayName":"Engineers","members":[{"value":"` + u2 + `"}]}`
	w = httptest.NewRecorder()
	h.ReplaceGroup(w, withID(httptest.NewRequest(http.MethodPut, "/scim/v2/Groups/"+gid, bytes.NewReader([]byte(put))), gid))
	require.Equal(t, http.StatusOK, w.Code)
	assert.ElementsMatch(t, []string{u2}, groupMemberValues(decodeSCIM(t, w)))

	// PATCH add alice back → both members.
	addPatch := `{"Operations":[{"op":"add","path":"members","value":[{"value":"` + u1 + `"}]}]}`
	w = httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+gid, bytes.NewReader([]byte(addPatch))), gid))
	require.Equal(t, http.StatusOK, w.Code)
	assert.ElementsMatch(t, []string{u1, u2}, groupMemberValues(decodeSCIM(t, w)))

	// PATCH remove bob via the filtered path syntax → alice only.
	rmPatch := `{"Operations":[{"op":"remove","path":"members[value eq \"` + u2 + `\"]"}]}`
	w = httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+gid, bytes.NewReader([]byte(rmPatch))), gid))
	require.Equal(t, http.StatusOK, w.Code)
	assert.ElementsMatch(t, []string{u1}, groupMemberValues(decodeSCIM(t, w)))

	// PATCH rename.
	renamePatch := `{"Operations":[{"op":"replace","path":"displayName","value":"Platform"}]}`
	w = httptest.NewRecorder()
	h.PatchGroup(w, withID(httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+gid, bytes.NewReader([]byte(renamePatch))), gid))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "Platform", decodeSCIM(t, w)["displayName"])

	// List returns the one group.
	w = httptest.NewRecorder()
	h.ListGroups(w, httptest.NewRequest(http.MethodGet, "/scim/v2/Groups", nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, float64(1), decodeSCIM(t, w)["totalResults"])

	// DELETE → 204.
	w = httptest.NewRecorder()
	h.DeleteGroup(w, withID(httptest.NewRequest(http.MethodDelete, "/scim/v2/Groups/"+gid, nil), gid))
	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestSCIM_CreateGroupRequiresDisplayName(t *testing.T) {
	h, _ := setupSCIMTest(t)
	w := httptest.NewRecorder()
	h.CreateGroup(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(`{"members":[]}`))))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
