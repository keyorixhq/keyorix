// project_memberships_proxy_transition_gaps_test.go — remaining branch
// coverage for TransitionMembershipProxy (project_memberships_proxy.go)
// beyond project_memberships_proxy_transition_test.go's #1546 ceiling tests:
// invalid path param, malformed body, missing target state, and the
// #G42 lost-CAS-race ("matched":false) branch.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

func TestTransitionMembershipProxy_InvalidID(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	req := httptest.NewRequest("PUT", "/", bytes.NewReader([]byte(`{}`)))
	req = withChiParams(req, map[string]string{"id": "abc"})
	w := httptest.NewRecorder()
	h.TransitionMembershipProxy(w, req)
	assert.Equal(t, 400, w.Code)
}

func TestTransitionMembershipProxy_BadJSON(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	req := httptest.NewRequest("PUT", "/", bytes.NewReader([]byte("{bad json}")))
	req = withChiParams(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()
	h.TransitionMembershipProxy(w, req)
	assert.Equal(t, 400, w.Code)
}

func TestTransitionMembershipProxy_MissingTargetState(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	body, _ := json.Marshal(map[string]interface{}{
		"membership": map[string]interface{}{"id": 1, "project_id": 1},
	})
	req := httptest.NewRequest("PUT", "/", bytes.NewReader(body))
	req = withChiParams(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()
	h.TransitionMembershipProxy(w, req)
	assert.Equal(t, 400, w.Code)
}

// raceLosingStorage wraps a real storage.Storage and forces
// TransitionProjectMembershipState to report a lost CAS race (matched=false,
// no error) — the #G42 branch that is otherwise only reachable via a genuine
// concurrent second writer.
type raceLosingStorage struct {
	coreStorage.Storage
}

func (r *raceLosingStorage) TransitionProjectMembershipState(ctx context.Context, m *models.ProjectMembership, fromState string) (bool, error) {
	return false, nil
}

// TestTransitionMembershipProxy_LostRace_MatchedFalse exercises the #G42
// "another writer already moved this row" outcome: a legal transition
// (provisioned -> revoked, no admin-role ceiling involved) whose conditional
// write is forced to report zero rows matched. The wire contract treats this
// as a normal 200 with matched:false, not a server error.
func TestTransitionMembershipProxy_LostRace_MatchedFalse(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	ctx := context.Background()

	project, err := cs.Storage().CreateProject(ctx, &models.Project{Name: "g42-race-project"})
	require.NoError(t, err)
	target, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "g42-race-target", Email: "g42-race-target@example.com",
		DisplayName: "G42 Race Target", Password: "NotArealpassword123!",
	})
	require.NoError(t, err)
	membership, err := cs.Storage().CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: project.ID, UserID: target.ID, Role: "member", State: core.MembershipProvisioned,
	})
	require.NoError(t, err)

	raceCore := core.NewKeyorixCore(&raceLosingStorage{Storage: cs.Storage()})
	h := NewCatalogHandler(raceCore)

	body, _ := json.Marshal(map[string]interface{}{
		"membership": map[string]interface{}{"id": membership.ID, "project_id": membership.ProjectID, "state": core.MembershipRevoked},
		"from_state": core.MembershipProvisioned,
	})
	req := httptest.NewRequest("PUT", "/", bytes.NewReader(body))
	uc := &middleware.UserContext{UserID: 1}
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	req = withChiParams(req, map[string]string{"id": machineUintToStr(membership.ID)})
	w := httptest.NewRecorder()
	h.TransitionMembershipProxy(w, req)
	require.Equal(t, 200, w.Code, w.Body.String())

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Matched bool `json:"matched"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.False(t, resp.Data.Matched)

	// The row itself must be untouched by the lost-race branch (the fake
	// never actually wrote anything).
	reloaded, err := cs.Storage().GetProjectMembership(ctx, membership.ID)
	require.NoError(t, err)
	assert.Equal(t, core.MembershipProvisioned, reloaded.State)
}
