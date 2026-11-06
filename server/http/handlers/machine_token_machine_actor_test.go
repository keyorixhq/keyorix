package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/require"
)

func issueTokenAsMachine(t *testing.T, roleName string) *httptest.ResponseRecorder {
	t.Helper()
	cs := freshCoreS11(t)
	h := NewCatalogHandler(cs)
	bootstrapS11(t, cs, "tokmach")
	projID := uint(1)
	ctx := context.Background()
	st := cs.Storage()

	caller, err := st.CreateMachineIdentity(ctx, &models.MachineIdentity{ProjectID: projID, Name: "token-caller", State: "active"})
	require.NoError(t, err)
	target, err := st.CreateMachineIdentity(ctx, &models.MachineIdentity{ProjectID: projID, Name: "token-target", State: "active"})
	require.NoError(t, err)
	role, err := st.GetRoleByName(ctx, roleName)
	require.NoError(t, err)
	require.NoError(t, st.AssignMachineRole(ctx, caller.ID, role.ID, storage.Scope{ProjectID: projID}))

	uc := &middleware.UserContext{UserID: 0, ActorType: core.ActorTypeMachine, MachineIdentityID: &caller.ID}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"by-machine"}`))
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	req = withChiParams(req, map[string]string{"id": machineUintToStr(projID), "machineId": machineUintToStr(target.ID)})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	return w
}

// A machine holding roles.assign at the project can issue a token for another
// machine in that project.
func TestIssueMachineToken_MachineActorWithRolesAssign(t *testing.T) {
	w := issueTokenAsMachine(t, "project_admin")
	require.Equal(t, http.StatusCreated, w.Code, "response body: %s", w.Body.String())
}

// A machine without roles.assign is refused with 403, not a server error.
func TestIssueMachineToken_MachineActorWithoutRolesAssignForbidden(t *testing.T) {
	w := issueTokenAsMachine(t, "project_viewer")
	require.Equal(t, http.StatusForbidden, w.Code, "response body: %s", w.Body.String())
}
