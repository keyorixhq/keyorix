// accessreview_gap_test.go — closes remaining coverage gaps identified by
// reading accessreview.go/campaign.go against the existing test suite:
//   - a "role" source entry with EnvironmentID==0 (the "project"-scope label,
//     as opposed to the "env=N" label already covered elsewhere)
//   - a "user" principal with no email (the plain-name branch, as opposed to
//     the "name <email>" branch already covered elsewhere)
//   - runDecision's own server-error path (c.Post returning an error), which
//     is exercised for the campaign subcommands but not for revoke/attest
//   - revokeCmd.RunE and attestCmd.RunE themselves: every existing test calls
//     runDecision(...) directly, so the one-line closures that wire the two
//     cobra commands to it (`return runDecision("revoke")` /
//     `return runDecision("attest")`) were never actually executed
package accessreview

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAccessReview_RoleEntry_ProjectScope covers the EnvironmentID==0 branch
// of the "role" detail formatting (scope stays "project" rather than
// "env=N"), which TestAccessReview_WithRoleEntry does not exercise since it
// always sets a nonzero environment_id.
func TestAccessReview_RoleEntry_ProjectScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"entries":[
			{"principal_type":"user","principal_name":"carol","email":"carol@x.io","source":"role","role_name":"admin","access_level":"admin","environment_id":0}
		],"count":1}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject := flagProject
	defer func() { flagProject = origProject }()
	flagProject = 9

	out, err := captureStdout(t, func() error { return AccessReviewCmd.RunE(AccessReviewCmd, nil) })
	require.NoError(t, err)
	assert.Contains(t, out, "role=admin (project)")
	assert.NotContains(t, out, "env=")
}

// TestAccessReview_UserWithoutEmail covers the branch where a "user"
// principal has no email — the principal column must stay the plain name,
// not "name <>". Every existing user-principal fixture in this package sets
// a nonempty email, so this line was previously uncovered.
func TestAccessReview_UserWithoutEmail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"entries":[
			{"principal_type":"user","principal_name":"dave","email":"","source":"owner","secret_name":"db-pass","access_level":"read"}
		],"count":1}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject := flagProject
	defer func() { flagProject = origProject }()
	flagProject = 9

	out, err := captureStdout(t, func() error { return AccessReviewCmd.RunE(AccessReviewCmd, nil) })
	require.NoError(t, err)
	assert.Contains(t, out, "dave")
	assert.NotContains(t, out, "dave <")
}

// TestRunDecision_ServerError covers runDecision's own c.Post error path
// (revoke/attest hitting a failing server) — the analogous "ServerError"
// case already exists for every campaign subcommand but not for
// revoke/attest themselves.
func TestRunDecision_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origProject, origSource, origPrincipalID, origRoleID :=
		dProject, dSource, dPrincipalID, dRoleID
	defer func() {
		dProject = origProject
		dSource = origSource
		dPrincipalID = origPrincipalID
		dRoleID = origRoleID
	}()
	dProject = 4
	dSource = "role"
	dPrincipalID = 1
	dRoleID = 2

	err := runDecision("revoke")
	require.Error(t, err)
}

// TestRevokeCmd_RunE covers revokeCmd's own RunE closure — every other
// revoke-related test calls runDecision("revoke") directly, bypassing the
// closure that cobra actually invokes when a user runs `access-review
// revoke`.
func TestRevokeCmd_RunE(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject, origSource, origPrincipalID, origRoleID :=
		dProject, dSource, dPrincipalID, dRoleID
	defer func() {
		dProject = origProject
		dSource = origSource
		dPrincipalID = origPrincipalID
		dRoleID = origRoleID
	}()
	dProject = 6
	dSource = "role"
	dPrincipalID = 2
	dRoleID = 9

	require.NoError(t, revokeCmd.RunE(revokeCmd, nil))
	assert.Equal(t, "/api/v1/projects/6/access-review/revoke", gotPath)
}

// TestAttestCmd_RunE covers attestCmd's own RunE closure, the attest
// counterpart of TestRevokeCmd_RunE above.
func TestAttestCmd_RunE(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject, origSource, origPrincipalID, origRoleID :=
		dProject, dSource, dPrincipalID, dRoleID
	defer func() {
		dProject = origProject
		dSource = origSource
		dPrincipalID = origPrincipalID
		dRoleID = origRoleID
	}()
	dProject = 6
	dSource = "role"
	dPrincipalID = 2
	dRoleID = 9

	require.NoError(t, attestCmd.RunE(attestCmd, nil))
	assert.Equal(t, "/api/v1/projects/6/access-review/attest", gotPath)
}
