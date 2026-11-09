package handlers

// member_grant_target_oracle_test.go — OWNERSHIP-ORACLE-1 item 2 over REST.
//
// The actor holds roles.assign (the route gate of every handler here) but may not
// grant the role asked for. With the membership domain allowlist on, the handlers
// used to answer by target: 404 / 403 "email domain is not on the allowlist" / the
// ceiling refusal, so the refusal said which user IDs exist and whose email is off
// the allowlist. Every target now gets the same body and status 403 (FU-OWNERSHIP-1:
// POST /projects/{id}/memberships answered the ceiling refusal 500).

import (
	"context"
	"net/http"
	"net/http/httptest"
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
)

func TestMemberGrantHandlers_UnauthorizedActorIdenticalAnswer(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()
	db := sqlitetest.Open(t, "kxmemberoracle_")
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	local := store.NewLocalStorage(db)
	cs := core.NewKeyorixCore(local)
	cs.SetMembershipDomainAllowlist([]string{"allowed.com"})

	mkUser := func(name, email string) uint {
		u, err := local.CreateUser(ctx, &models.User{
			Username: name, UsernameFolded: name, Email: email, EmailFolded: email,
			IsActive: true, AccountState: "active",
		})
		require.NoError(t, err)
		return u.ID
	}
	actor := mkUser("oracle-actor", "oracle-actor@allowed.com")
	require.EqualValues(t, 1, actor, "withUserCtx authenticates as user 1")
	targets := map[string]uint{
		"existing user":      mkUser("oracle-allowed", "oracle-allowed@allowed.com"),
		"missing user":       999999,
		"off-allowlist user": mkUser("oracle-offlist", "oracle-offlist@evil.com"),
	}

	proj := &models.Project{Name: "oracle-proj"}
	require.NoError(t, db.Create(proj).Error)
	assign := &models.Permission{Name: "roles.assign", Resource: "roles", Action: "assign"}
	read := &models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
	require.NoError(t, db.Create(assign).Error)
	require.NoError(t, db.Create(read).Error)
	mgr := &models.Role{Name: "oracle-member-manager"}
	viewer := &models.Role{Name: "oracle-viewer"}
	require.NoError(t, db.Create(mgr).Error)
	require.NoError(t, db.Create(viewer).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: mgr.ID, PermissionID: assign.ID}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: viewer.ID, PermissionID: read.ID}).Error)
	require.NoError(t, local.AssignRole(ctx, actor, mgr.ID, corestorage.Scope{ProjectID: proj.ID}))
	require.NoError(t, local.AssignRole(ctx, actor, mgr.ID, corestorage.Scope{}))
	g, err := local.CreateGroup(ctx, &models.Group{Name: "oracle-group", NameFolded: "oracle-group"})
	require.NoError(t, err)
	require.NoError(t, local.AssignRoleToGroup(ctx, g.ID, viewer.ID, corestorage.Scope{ProjectID: proj.ID}))

	cat := NewCatalogHandler(cs)
	grp, err := NewGroupHandler(cs)
	require.NoError(t, err)
	pid := suID(proj.ID)

	ops := map[string]func(target uint) *httptest.ResponseRecorder{
		"POST /projects/{id}/members": func(target uint) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			cat.AddProjectMember(w, suReq(http.MethodPost, `{"user_id":`+suID(target)+`,"role":"oracle-viewer"}`, map[string]string{"id": pid}))
			return w
		},
		"PUT /projects/{id}/members/{userId}": func(target uint) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			cat.UpdateProjectMember(w, suReq(http.MethodPut, `{"role":"oracle-viewer"}`, map[string]string{"id": pid, "userId": suID(target)}))
			return w
		},
		"POST /projects/{id}/memberships": func(target uint) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			cat.InviteMember(w, suReq(http.MethodPost, `{"user_id":`+suID(target)+`,"role":"oracle-viewer"}`, map[string]string{"id": pid}))
			return w
		},
		"POST /groups/{id}/members": func(target uint) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			grp.AddGroupMember(w, suReq(http.MethodPost, `{"user_id":`+suID(target)+`,"project_id":`+pid+`}`, map[string]string{"id": suID(g.ID)}))
			return w
		},
	}
	type answer struct {
		code int
		body string
	}
	for name, op := range ops {
		got := map[string]answer{}
		for label, target := range targets {
			w := op(target)
			assert.Equal(t, http.StatusForbidden, w.Code, "%s %s: a refused grant answers 403: %s", name, label, w.Body.String())
			got[label] = answer{w.Code, w.Body.String()}
		}
		want := got["existing user"]
		for label, a := range got {
			assert.Equal(t, want, a, "%s: %s answers differently from an existing user", name, label)
		}
	}
}
