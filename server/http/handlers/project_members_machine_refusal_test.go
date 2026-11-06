package handlers

// project_members_machine_refusal_test.go — REST mapping of the refusals of the
// direct project-member routes (PR #3990). A machine credential holding
// roles.assign at the project used to fail inside the privilege ceiling and
// POST /projects/{id}/members answered it 500; both direct routes now answer 403
// with the refusal text, and nothing is granted.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/middleware"
)

func TestProjectMemberRoutes_RefusalsAnswer403(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()
	db := sqlitetest.Open(t, "kxmembermachine_")
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	local := store.NewLocalStorage(db)
	cs := core.NewKeyorixCore(local)

	mkUser := func(name string) uint {
		u, err := local.CreateUser(ctx, &models.User{
			Username: name, UsernameFolded: name, Email: name + "@example.com", EmailFolded: name + "@example.com",
			IsActive: true, AccountState: "active",
		})
		require.NoError(t, err)
		return u.ID
	}
	actor := mkUser("member-actor")
	require.EqualValues(t, 1, actor, "withUserCtx authenticates as user 1")
	target := mkUser("member-target")

	proj := &models.Project{Name: "member-machine-proj"}
	require.NoError(t, db.Create(proj).Error)
	assign := &models.Permission{Name: "roles.assign", Resource: "roles", Action: "assign"}
	read := &models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
	require.NoError(t, db.Create(assign).Error)
	require.NoError(t, db.Create(read).Error)
	mgr := &models.Role{Name: "member-manager"}
	viewer := &models.Role{Name: "member-viewer"}
	require.NoError(t, db.Create(mgr).Error)
	require.NoError(t, db.Create(viewer).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: mgr.ID, PermissionID: assign.ID}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: viewer.ID, PermissionID: read.ID}).Error)
	// The human actor holds roles.assign only: it passes the route gate but fails
	// the ceiling for member-viewer (secrets.read).
	require.NoError(t, local.AssignRole(ctx, actor, mgr.ID, corestorage.Scope{ProjectID: proj.ID}))

	cat := NewCatalogHandler(cs)
	pid := suID(proj.ID)
	params := map[string]string{"id": pid, "userId": suID(target)}
	addBody := `{"user_id":` + suID(target) + `,"role":"member-viewer"}`
	setBody := `{"role":"member-viewer"}`

	machineID := uint(41)
	asMachine := func(r *http.Request) *http.Request {
		uc := &middleware.UserContext{ActorType: core.ActorTypeMachine, MachineIdentityID: &machineID, Username: "ci-runner-41"}
		return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
	}
	machineReq := func(method, body string) *http.Request {
		return asMachine(withChiParams(httptest.NewRequest(method, "/", strings.NewReader(body)), params))
	}

	t.Run("machine POST add member", func(t *testing.T) {
		w := httptest.NewRecorder()
		cat.AddProjectMember(w, machineReq(http.MethodPost, addBody))
		assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), core.ErrMachineProjectMembershipDenied.Error())
	})
	t.Run("machine PUT change role", func(t *testing.T) {
		w := httptest.NewRecorder()
		cat.UpdateProjectMember(w, machineReq(http.MethodPut, setBody))
		assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), core.ErrMachineProjectMembershipDenied.Error())
	})
	t.Run("human failing the ceiling POST add member", func(t *testing.T) {
		w := httptest.NewRecorder()
		cat.AddProjectMember(w, suReq(http.MethodPost, addBody, params))
		assert.Equal(t, http.StatusForbidden, w.Code, "a ceiling refusal is a 403, not a 500: %s", w.Body.String())
	})

	members, err := local.ListProjectMembers(ctx, proj.ID)
	require.NoError(t, err)
	for _, m := range members {
		assert.NotEqual(t, target, m.UserID, "no refused call may leave a membership row for the target")
	}
}
