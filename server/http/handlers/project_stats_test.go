// project_stats_test.go — coverage for GetProjectStats (project_stats.go),
// previously untested (0% coverage). Uses freshCoreS12WithAdmin rather than
// project_health_handler_test.go's lighter fixture: core.GetProjectStats'
// ListProjectRoleAssignments call unconditionally queries the user_roles/
// group_roles tables, which the lighter fixture doesn't migrate.
package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newProjectStatsHandler(t *testing.T) *SecretHandler {
	t.Helper()
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return h
}

func TestGetProjectStats_Unauthorized(t *testing.T) {
	h := newProjectStatsHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/stats", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetProjectStats(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetProjectStats_InvalidProjectID(t *testing.T) {
	h := newProjectStatsHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/projects/abc/stats", nil), "id", "abc")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.GetProjectStats(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetProjectStats_NotFound — a well-formed but nonexistent project ID:
// core.GetProjectStats' initial GetProject lookup fails, which the handler
// maps to a generic 500 (no not-found branch of its own).
func TestGetProjectStats_NotFound(t *testing.T) {
	h := newProjectStatsHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/projects/999/stats", nil), "id", "999")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.GetProjectStats(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetProjectStats_Success(t *testing.T) {
	h := newProjectStatsHandler(t)
	proj, err := h.coreService.Storage().CreateProject(context.Background(), &models.Project{Name: "stats-proj"})
	require.NoError(t, err)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/stats", nil), "id", machineUintToStr(proj.ID))
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.GetProjectStats(w, req)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "total_secrets")
}
