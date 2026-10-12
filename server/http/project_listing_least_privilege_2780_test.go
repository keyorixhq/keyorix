// project_listing_least_privilege_2780_test.go — #2780 through the REAL router,
// as the real persona, over HTTP.
//
// The handler-level tests (server/http/handlers/catalog_list_scoped_2780_test.go)
// call ListProjects/ListEnvironments directly, so they prove the FILTERING but say
// nothing about the route's middleware chain — and the middleware is where #2780
// actually lived: `RequirePermission(permSecretsRead)` answered 403 before the
// handler ever ran. A handler-only test would stay green if someone put that
// middleware back, which is precisely the regression to guard. So this one drives
// the whole stack: real NewRouter, real session token, real HTTP.
//
// The persona is WEB-SWEEP-1's, built through the product's own API:
// `system_viewer` at global scope plus `project_viewer` on ONE project. The
// assertions are the ones the UI depends on, in the order the UI hits them:
//
//	GET /api/v1/projects      -> 200, exactly their project (was 403)
//	GET /api/v1/environments  -> 200, only their project's environments (was 403)
//	GET /api/v1/projects/{id} -> 200 for theirs, 403 for the other (unchanged)
//	GET /api/v1/projects?include_deleted=true -> 403 (unchanged, admin-only)
//
// and the no-loss half: the bootstrap admin's list still contains every project.
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

const p2780Password = "Qr7#Kp2$Lm5@Vn9!"

// p2780ProjectIDs decodes `{data:{projects:[{id}]}}`.
func p2780ProjectIDs(t *testing.T, body []byte) []uint {
	t.Helper()
	var env struct {
		Data struct {
			Projects []struct {
				ID uint `json:"id"`
			} `json:"projects"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &env), "body: %s", body)
	ids := make([]uint, 0, len(env.Data.Projects))
	for _, p := range env.Data.Projects {
		ids = append(ids, p.ID)
	}
	return ids
}

// p2780EnvProjectIDs decodes `{data:{environments:[{project_id}]}}`.
func p2780EnvProjectIDs(t *testing.T, body []byte) []uint {
	t.Helper()
	var env struct {
		Data struct {
			Environments []struct {
				ProjectID uint `json:"project_id"`
			} `json:"environments"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &env), "body: %s", body)
	ids := make([]uint, 0, len(env.Data.Environments))
	for _, e := range env.Data.Environments {
		ids = append(ids, e.ProjectID)
	}
	return ids
}

// TestProjectListing2780_LeastPrivilegePersonaThroughRouter is the end-to-end
// regression for #2780 on the HTTP transport.
func TestProjectListing2780_LeastPrivilegePersonaThroughRouter(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	testCore := newFullSchemaTestCore(t)
	router, err := NewRouter(&config.Config{}, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	adminToken := createTestToken(t, testCore) // bootstraps roles/permissions/projects
	ctx := context.Background()

	// Two projects, created through the product's own API as an admin would.
	mine, err := testCore.CreateProject(ctx, "p2780-payments-api", "the one they can read")
	require.NoError(t, err)
	theirs, err := testCore.CreateProject(ctx, "p2780-billing", "the one they cannot")
	require.NoError(t, err)
	// An environment in each, so the environment listing has something to filter.
	_, err = testCore.CreateEnvironment(ctx, mine.ID, "p2780-prod")
	require.NoError(t, err)
	_, err = testCore.CreateEnvironment(ctx, theirs.ID, "p2780-prod")
	require.NoError(t, err)

	// The persona: system_viewer globally (system.read only — NOT secrets.read)
	// plus project_viewer on exactly one project. This is the ordinary shape for a
	// developer handed access to one service.
	_, err = testCore.CreateUserWithAssignments(ctx, &core.CreateUserRequest{
		Username: "p2780lowpriv", Email: "p2780lowpriv@example.com", Password: p2780Password,
	}, "system_viewer", []core.ProjectAssignment{{ProjectID: mine.ID, Role: "project_viewer"}}, 0, false)
	require.NoError(t, err)
	sess, _, err := testCore.Login(ctx, &core.LoginRequest{Username: "p2780lowpriv", Password: p2780Password})
	require.NoError(t, err)
	lowToken := sess.SessionToken

	client := &http.Client{Timeout: 10 * time.Second}
	get := func(token, path string) (int, []byte) {
		req, rerr := http.NewRequest(http.MethodGet, server.URL+path, nil)
		require.NoError(t, rerr)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, derr := client.Do(req)
		require.NoError(t, derr)
		defer func() { _ = resp.Body.Close() }()
		body, berr := io.ReadAll(resp.Body)
		require.NoError(t, berr)
		return resp.StatusCode, body
	}

	// Precondition, and the whole argument for why this is a consistency fix rather
	// than a widening: this persona can ALREADY read their project by id, and is
	// already refused the other one. Nothing below changes either answer.
	t.Run("precondition_per_project_read_unchanged", func(t *testing.T) {
		code, _ := get(lowToken, fmt.Sprintf("/api/v1/projects/%d", mine.ID))
		assert.Equal(t, http.StatusOK, code, "they could already read their own project by id")
		other, _ := get(lowToken, fmt.Sprintf("/api/v1/projects/%d", theirs.ID))
		assert.Equal(t, http.StatusForbidden, other, "and were already refused the other one")
	})

	// The regression. 403 here is what emptied the project switcher, the /projects
	// page and the New Secret dialog's Project select — on every route in the app,
	// because the switcher fires from the layout.
	t.Run("project_listing_serves_their_project", func(t *testing.T) {
		code, body := get(lowToken, "/api/v1/projects")
		require.Equal(t, http.StatusOK, code,
			"GET /api/v1/projects must not 403 a project-scoped member (#2780); body: %s", body)
		ids := p2780ProjectIDs(t, body)
		assert.Equal(t, []uint{mine.ID}, ids, "exactly the project they can read")
		assert.NotContains(t, ids, theirs.ID, "and never the one they cannot")
	})

	// The sibling. The web New Secret dialog's required Environment select reads
	// this endpoint, not the per-project one, so without this the dialog stays
	// unsatisfiable for this persona even once the project list works.
	t.Run("environment_listing_serves_their_environments", func(t *testing.T) {
		code, body := get(lowToken, "/api/v1/environments")
		require.Equal(t, http.StatusOK, code,
			"GET /api/v1/environments must not 403 a project-scoped member; body: %s", body)
		projectIDs := p2780EnvProjectIDs(t, body)
		require.NotEmpty(t, projectIDs, "their project's environments must be listed")
		for _, pid := range projectIDs {
			assert.Equal(t, mine.ID, pid, "no environment from a project they cannot read")
		}
	})

	// Must hold before and after: the restore view stays admin-only, because a
	// project-scoped reader cannot read a soft-deleted project through any path.
	t.Run("include_deleted_still_admin_only", func(t *testing.T) {
		code, _ := get(lowToken, "/api/v1/projects?include_deleted=true")
		assert.Equal(t, http.StatusForbidden, code,
			"the soft-deleted project view must stay global-only")
	})

	// The no-loss half: the admin's list is not narrowed by this change.
	t.Run("admin_list_unchanged", func(t *testing.T) {
		code, body := get(adminToken, "/api/v1/projects")
		require.Equal(t, http.StatusOK, code)
		ids := p2780ProjectIDs(t, body)
		assert.Contains(t, ids, mine.ID)
		assert.Contains(t, ids, theirs.ID, "an admin must still see every project")

		dcode, _ := get(adminToken, "/api/v1/projects?include_deleted=true")
		assert.Equal(t, http.StatusOK, dcode, "and still get the restore view")
	})

	// Must hold before and after: a user with no project grant at all sees nothing,
	// and gets 200-with-empty rather than a 403 that the UI renders as "you have
	// nothing to show, create your first secret".
	t.Run("no_project_grant_sees_nothing", func(t *testing.T) {
		_, cerr := testCore.CreateUserWithAssignments(ctx, &core.CreateUserRequest{
			Username: "p2780nobody", Email: "p2780nobody@example.com", Password: p2780Password,
		}, "system_viewer", nil, 0, false)
		require.NoError(t, cerr)
		s, _, lerr := testCore.Login(ctx, &core.LoginRequest{Username: "p2780nobody", Password: p2780Password})
		require.NoError(t, lerr)

		code, body := get(s.SessionToken, "/api/v1/projects")
		require.Equal(t, http.StatusOK, code, "body: %s", body)
		assert.Empty(t, p2780ProjectIDs(t, body), "a user with no project grant must see no project")

		ecode, ebody := get(s.SessionToken, "/api/v1/environments")
		require.Equal(t, http.StatusOK, ecode, "body: %s", ebody)
		assert.Empty(t, p2780EnvProjectIDs(t, ebody), "...and no environment")
	})
}
