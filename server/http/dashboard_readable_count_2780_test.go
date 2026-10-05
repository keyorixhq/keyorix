// dashboard_readable_count_2780_test.go — #2780's second half, through the real
// router over HTTP.
//
// WEB-SWEEP-1's finding was "the dashboard says TOTAL SECRETS 0 while the user can
// read 5", and issue #2780 attributes that to the GET /api/v1/projects 403. That
// attribution is wrong, which is worth stating because it changes what has to be
// fixed: GET /api/v1/dashboard/stats is gated on system.read, which the
// least-privilege persona HOLDS, so it answered 200 all along — with a 0 that came
// from core/dashboard.go counting secrets the caller had AUTHORED
// (SecretFilter{CreatedBy: &username}), not secrets they could read. Fixing the
// project listing alone leaves this number at 0.
//
// The oracle here is deliberately not a hard-coded 5. It is the EQUALITY between
// what the dashboard reports and what GET /api/v1/secrets actually returns, for the
// same caller in the same session:
//
//	dashboard.totalSecrets == (GET /api/v1/secrets).total
//
// A hard-coded number would pass if both sides drifted together, and would have to
// be re-tuned whenever the fixture changes. The equality is the property the tile
// claims, it is checked for THREE different personas (least-privilege, admin, and a
// user with no access at all), and it is what the two call sites now share one
// function to guarantee.
package http

import (
	"context"
	"encoding/json"
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

// dash2780Totals is the pair the test compares.
type dash2780Totals struct {
	dashboard int64
	list      int64
	degraded  bool
}

func TestDashboard2780_TotalSecretsEqualsWhatTheListReturns(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	testCore := newFullSchemaTestCore(t)
	router, err := NewRouter(&config.Config{}, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	adminToken := createTestToken(t, testCore)
	ctx := context.Background()

	// Two projects. The persona gets read access to the first only, so a correct
	// count has to be a real number rather than "all of them" or "none of them".
	mine, err := testCore.CreateProject(ctx, "d2780-payments-api", "readable")
	require.NoError(t, err)
	theirs, err := testCore.CreateProject(ctx, "d2780-billing", "not readable")
	require.NoError(t, err)
	mineEnv, err := testCore.CreateEnvironment(ctx, mine.ID, "d2780-prod")
	require.NoError(t, err)
	theirsEnv, err := testCore.CreateEnvironment(ctx, theirs.ID, "d2780-prod")
	require.NoError(t, err)

	// Five secrets in the readable project, three in the other. Created by the
	// ADMIN, deliberately: the persona authors nothing, which is the exact shape
	// that made the old authorship-based count report 0.
	for _, name := range []string{"d2780-a", "d2780-b", "d2780-c", "d2780-d", "d2780-e"} {
		_, cerr := testCore.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: name, Value: []byte("v"), Type: "text", CreatedBy: "testadmin",
			ProjectID: mine.ID, EnvironmentID: mineEnv.ID, OwnerID: 1,
		})
		require.NoError(t, cerr, "seeding %s", name)
	}
	for _, name := range []string{"d2780-x", "d2780-y", "d2780-z"} {
		_, cerr := testCore.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: name, Value: []byte("v"), Type: "text", CreatedBy: "testadmin",
			ProjectID: theirs.ID, EnvironmentID: theirsEnv.ID, OwnerID: 1,
		})
		require.NoError(t, cerr, "seeding %s", name)
	}

	const pw = "Qr7#Kp2$Lm5@Vn9!"
	newPersona := func(t *testing.T, username string, assignments []core.ProjectAssignment) string {
		t.Helper()
		_, cerr := testCore.CreateUserWithAssignments(ctx, &core.CreateUserRequest{
			Username: username, Email: username + "@example.com", Password: pw,
		}, "system_viewer", assignments, 0, false)
		require.NoError(t, cerr)
		sess, _, lerr := testCore.Login(ctx, &core.LoginRequest{Username: username, Password: pw})
		require.NoError(t, lerr)
		return sess.SessionToken
	}

	lowToken := newPersona(t, "d2780lowpriv", []core.ProjectAssignment{{ProjectID: mine.ID, Role: "project_viewer"}})
	nobodyToken := newPersona(t, "d2780nobody", nil)

	client := &http.Client{Timeout: 10 * time.Second}
	get := func(t *testing.T, token, path string) []byte {
		t.Helper()
		req, rerr := http.NewRequest(http.MethodGet, server.URL+path, nil)
		require.NoError(t, rerr)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, derr := client.Do(req)
		require.NoError(t, derr)
		defer func() { _ = resp.Body.Close() }()
		body, berr := io.ReadAll(resp.Body)
		require.NoError(t, berr)
		require.Equal(t, http.StatusOK, resp.StatusCode, "GET %s: %s", path, body)
		return body
	}

	totalsFor := func(t *testing.T, token string) dash2780Totals {
		t.Helper()
		var dash struct {
			Data struct {
				TotalSecrets int64 `json:"totalSecrets"`
				Degraded     bool  `json:"degraded"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(get(t, token, "/api/v1/dashboard/stats"), &dash))
		var list struct {
			Data struct {
				Total int64 `json:"total"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(get(t, token, "/api/v1/secrets?page_size=100"), &list))
		return dash2780Totals{dashboard: dash.Data.TotalSecrets, list: list.Data.Total, degraded: dash.Data.Degraded}
	}

	// The regression. Red before the fix: dashboard 0, list 5.
	t.Run("least_privilege_persona", func(t *testing.T) {
		got := totalsFor(t, lowToken)
		require.False(t, got.degraded,
			"a degraded snapshot would make a 0 mean \"unknown\" rather than \"counted\" — the comparison below needs a real count")
		assert.Equal(t, int64(5), got.list,
			"fixture sanity: this persona can read the five secrets in their project (and not the other three)")
		assert.Equal(t, got.list, got.dashboard,
			"TOTAL SECRETS must be the count of what GET /api/v1/secrets returns this caller. "+
				"Reporting 0 to someone reading five is #2780: it is confidently wrong, and the UI turns it "+
				"into \"Create your first secret to get started\"")
	})

	// Must hold before and after: an admin (audit.read) keeps the deployment-wide
	// total, which this fix deliberately does not touch.
	t.Run("admin_sees_deployment_total", func(t *testing.T) {
		got := totalsFor(t, adminToken)
		assert.Equal(t, int64(8), got.dashboard,
			"an audit.read holder still gets the deployment-wide secret count (5 + 3), not a per-caller one")
		assert.Equal(t, got.list, got.dashboard,
			"for a global reader the two are the same number anyway, so the equality holds here too")
	})

	// Must hold before and after: a caller with no access is told zero, truthfully.
	// This is the case the old behaviour got RIGHT by accident, and it must not
	// become generous.
	t.Run("no_access_persona_sees_zero", func(t *testing.T) {
		got := totalsFor(t, nobodyToken)
		assert.Equal(t, int64(0), got.list, "this persona can read nothing")
		assert.Equal(t, int64(0), got.dashboard, "...and is told so, which was always correct")
	})
}
