// group_project_flag_test.go — tests for the --project flag on add-member and
// remove-member.  Covers both the local (core) path and the remote HTTP path.
package group

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeGroupMemberServer returns a minimal httptest.Server that:
//   - POST /api/v1/groups/{id}/members — captures the request body and
//     responds with the server's {"data":…} envelope so the remote client
//     succeeds without erroring on the decode step.
//   - DELETE /api/v1/groups/{id}/members/{userId} — captures the query params
//     and responds with HTTP 204 (no content, no body decode expected).
type groupMemberCapture struct {
	addBody   map[string]interface{}
	removeURL string
}

func fakeGroupMemberServer(t *testing.T) (*httptest.Server, *groupMemberCapture) {
	t.Helper()
	cap := &groupMemberCapture{}
	mux := http.NewServeMux()

	// POST /api/v1/groups/ — matches all paths under groups
	mux.HandleFunc("/api/v1/groups/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(body, &cap.addBody))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"group_id":10,"user_id":5,"project_id":3}}`))
		case http.MethodDelete:
			cap.removeURL = r.URL.RequestURI()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, cap
}

// TestAddMemberCmd_ProjectFlag_Registered verifies the --project flag is
// registered on the add-member command with the correct default.
func TestAddMemberCmd_ProjectFlag_Registered(t *testing.T) {
	f := addMemberCmd.Flags().Lookup("project")
	require.NotNil(t, f, "--project flag must be registered on add-member")
	assert.Equal(t, "0", f.DefValue)
}

// TestRemoveMemberCmd_ProjectFlag_Registered verifies the --project flag is
// registered on the remove-member command with the correct default.
func TestRemoveMemberCmd_ProjectFlag_Registered(t *testing.T) {
	f := removeMemberCmd.Flags().Lookup("project")
	require.NotNil(t, f, "--project flag must be registered on remove-member")
	assert.Equal(t, "0", f.DefValue)
}

// TestRunAddMember_Remote_SendsProjectID exercises the remote HTTP path of
// runAddMember and verifies that project_id is included in the POST body.
func TestRunAddMember_Remote_SendsProjectID(t *testing.T) {
	srv, cap := fakeGroupMemberServer(t)

	// Point the CLI resolver at the fake server.
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origG, origU, origP := addMemberGroupID, addMemberUserID, addMemberProjectID
	defer func() {
		addMemberGroupID = origG
		addMemberUserID = origU
		addMemberProjectID = origP
	}()
	addMemberGroupID = 10
	addMemberUserID = 5
	addMemberProjectID = 3

	err := runAddMember(nil, nil)
	require.NoError(t, err)

	require.NotNil(t, cap.addBody, "request body must have been captured")
	assert.Equal(t, float64(5), cap.addBody["user_id"], "user_id mismatch in POST body")
	assert.Equal(t, float64(3), cap.addBody["project_id"], "project_id mismatch in POST body")
}

// TestRunAddMember_Remote_GlobalMembership verifies that when --project=0 the
// body still includes project_id=0, letting the server apply global semantics.
func TestRunAddMember_Remote_GlobalMembership(t *testing.T) {
	srv, cap := fakeGroupMemberServer(t)

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origG, origU, origP := addMemberGroupID, addMemberUserID, addMemberProjectID
	defer func() {
		addMemberGroupID = origG
		addMemberUserID = origU
		addMemberProjectID = origP
	}()
	addMemberGroupID = 10
	addMemberUserID = 5
	addMemberProjectID = 0 // global membership

	err := runAddMember(nil, nil)
	require.NoError(t, err)

	require.NotNil(t, cap.addBody)
	assert.Equal(t, float64(0), cap.addBody["project_id"], "project_id should be 0 for global membership")
}

// TestRunRemoveMember_Remote_SendsProjectID verifies that when --project is
// non-zero the DELETE URL includes the ?project_id= query param.
func TestRunRemoveMember_Remote_SendsProjectID(t *testing.T) {
	srv, cap := fakeGroupMemberServer(t)

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origG, origU, origP := removeMemberGroupID, removeMemberUserID, removeMemberProjectID
	defer func() {
		removeMemberGroupID = origG
		removeMemberUserID = origU
		removeMemberProjectID = origP
	}()
	removeMemberGroupID = 10
	removeMemberUserID = 5
	removeMemberProjectID = 3

	err := runRemoveMember(nil, nil)
	require.NoError(t, err)

	assert.Contains(t, cap.removeURL, "project_id=3", "DELETE URL must carry project_id query param")
}

// TestRunRemoveMember_Remote_GlobalMembership verifies that when --project=0
// the DELETE URL does NOT include a project_id query param (avoiding a
// spurious ?project_id=0 that could confuse strict servers).
func TestRunRemoveMember_Remote_GlobalMembership(t *testing.T) {
	srv, cap := fakeGroupMemberServer(t)

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origG, origU, origP := removeMemberGroupID, removeMemberUserID, removeMemberProjectID
	defer func() {
		removeMemberGroupID = origG
		removeMemberUserID = origU
		removeMemberProjectID = origP
	}()
	removeMemberGroupID = 10
	removeMemberUserID = 5
	removeMemberProjectID = 0 // global membership

	err := runRemoveMember(nil, nil)
	require.NoError(t, err)

	assert.NotContains(t, cap.removeURL, "project_id", "DELETE URL must NOT include project_id for global membership")
}

// TestRunAddMember_Local_WithProject exercises the local (non-remote) path of
// runAddMember with a non-zero --project flag value. The DB will be created in
// a temp dir; the insert may succeed or fail (no panic is the invariant).
func TestRunAddMember_Local_WithProject(t *testing.T) {
	setupLocalDB(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origG, origU, origP := addMemberGroupID, addMemberUserID, addMemberProjectID
	defer func() {
		addMemberGroupID = origG
		addMemberUserID = origU
		addMemberProjectID = origP
	}()
	addMemberGroupID = 1
	addMemberUserID = 1
	addMemberProjectID = 7

	// No panic is the invariant; the service may return an error for nonexistent IDs.
	_ = runAddMember(nil, nil)
}

// TestRunRemoveMember_Local_WithProject exercises the local (non-remote) path
// of runRemoveMember with a non-zero --project flag value.
func TestRunRemoveMember_Local_WithProject(t *testing.T) {
	setupLocalDB(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	origG, origU, origP := removeMemberGroupID, removeMemberUserID, removeMemberProjectID
	defer func() {
		removeMemberGroupID = origG
		removeMemberUserID = origU
		removeMemberProjectID = origP
	}()
	removeMemberGroupID = 1
	removeMemberUserID = 1
	removeMemberProjectID = 7

	// No panic is the invariant; a missing membership is a no-op in the store.
	_ = runRemoveMember(nil, nil)
}
