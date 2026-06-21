package rbac

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRBACServer mimics the subset of the Keyorix HTTP API the remote rbac
// commands call, wrapping every payload in the server's {"data":…} envelope.
func fakeRBACServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[
			{"id":1,"name":"admin","description":"Administrator"},
			{"id":2,"name":"viewer","description":"Read-only access"}
		]}}`))
	})
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/users/5/roles", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"viewer","description":"Read-only access"}]}}`))
	})
	mux.HandleFunc("/api/v1/roles/2/permissions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"permissions":[{"name":"secrets.read"},{"name":"users.read"}]}}`))
	})
	mux.HandleFunc("/api/v1/audit/rbac-logs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"logs":[
			{"id":2,"action":"role.assigned","actor_user_id":1,"target_user_id":5,"role_id":1,"project_id":0,"details":"","created_at":"2026-06-07T10:00:00Z"},
			{"id":1,"action":"role.removed","actor_user_id":1,"target_user_id":5,"role_id":2,"created_at":"2026-06-07T09:00:00Z"}
		],"total":2,"page":1,"page_size":50,"total_pages":1}}`))
	})
	mux.HandleFunc("/api/v1/user-roles", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"user_id":5,"role_id":1}}`))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// remoteClientFor points the CLI's remote-config resolver at the fake server via
// env vars (highest priority in ResolveRemote), so NewRemoteClient picks it up.
func remoteClientFor(t *testing.T, srv *httptest.Server) *common.RemoteClient {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok, "remote client should resolve from env")
	return rc
}

func TestResolveUserIDByEmail(t *testing.T) {
	rc := remoteClientFor(t, fakeRBACServer(t))
	id, err := resolveUserIDByEmail(context.Background(), rc, "ALICE@test.com") // case-insensitive
	require.NoError(t, err)
	assert.Equal(t, uint(5), id)

	_, err = resolveUserIDByEmail(context.Background(), rc, "nobody@test.com")
	require.Error(t, err)
}

func TestResolveRoleIDByName(t *testing.T) {
	rc := remoteClientFor(t, fakeRBACServer(t))
	id, err := resolveRoleIDByName(context.Background(), rc, "admin")
	require.NoError(t, err)
	assert.Equal(t, uint(1), id)

	_, err = resolveRoleIDByName(context.Background(), rc, "ghost")
	require.Error(t, err)
}

func TestUserEffectivePermissions(t *testing.T) {
	rc := remoteClientFor(t, fakeRBACServer(t))
	perms, err := userEffectivePermissions(context.Background(), rc, 5)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"secrets.read", "users.read"}, perms)
}

// The remote command wrappers exercise the full request path against the fake
// server and must not error (output is printed; correctness of the decision is
// covered by TestUserEffectivePermissions).
func TestRemoteCommandWrappers(t *testing.T) {
	srv := fakeRBACServer(t)
	rc := remoteClientFor(t, srv)
	ctx := context.Background()

	require.NoError(t, runListRolesRemote(ctx, rc))
	require.NoError(t, runListUserRolesRemote(ctx, rc, "alice@test.com"))
	require.NoError(t, runListPermissionsRemote(ctx, rc, "alice@test.com"))
	require.NoError(t, runCheckPermissionRemote(ctx, rc, "alice@test.com", "secrets.read"))
	require.NoError(t, runCheckPermissionRemote(ctx, rc, "alice@test.com", "secrets.write")) // not held → ❌, still nil err
	require.NoError(t, runAssignRoleRemote(ctx, rc, "alice@test.com", "admin", 0))
	require.NoError(t, runRemoveRoleRemote(ctx, rc, "alice@test.com", "admin"))

	// A malformed permission name is rejected before any request.
	require.Error(t, runCheckPermissionRemote(ctx, rc, "alice@test.com", "notvalid"))
}

// A time-bound grant (--ttl) sends an expires_at in the future; a permanent grant
// omits it entirely.
func TestRunAssignRoleRemote_TimeBound(t *testing.T) {
	var lastBody map[string]interface{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/user-roles", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&lastBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"user_id":5,"role_id":1}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)
	ctx := context.Background()

	require.NoError(t, runAssignRoleRemote(ctx, rc, "alice@test.com", "admin", 4*time.Hour))
	require.Contains(t, lastBody, "expires_at")
	exp, err := time.Parse(time.RFC3339, lastBody["expires_at"].(string))
	require.NoError(t, err)
	assert.True(t, exp.After(time.Now()), "expiry must be in the future")

	lastBody = nil
	require.NoError(t, runAssignRoleRemote(ctx, rc, "alice@test.com", "admin", 0))
	assert.NotContains(t, lastBody, "expires_at", "a permanent grant omits expires_at")
}

func TestRunAuditLogsRemote(t *testing.T) {
	rc := remoteClientFor(t, fakeRBACServer(t))
	// Exercises the full request + decode path against the fake /audit/rbac-logs.
	require.NoError(t, runAuditLogsRemote(context.Background(), rc, 1, 50))
}
