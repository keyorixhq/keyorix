// rotation_dryrun_test.go — coverage for SimulateRotation (rotation_dryrun.go),
// previously untested (0% coverage).
package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestSimulateRotation_Unauthorized(t *testing.T) {
	h, _ := newProjectHealthHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/rotation/simulate", nil), "id", "1")
	w := httptest.NewRecorder()
	h.SimulateRotation(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSimulateRotation_InvalidSecretID(t *testing.T) {
	h, _ := newProjectHealthHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/secrets/abc/rotation/simulate", nil), "id", "abc")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.SimulateRotation(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSimulateRotation_SecretNotFound(t *testing.T) {
	h, _ := newProjectHealthHandler(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/secrets/999/rotation/simulate", nil), "id", "999")
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.SimulateRotation(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestSimulateRotation_Success seeds a real secret (no rotation policy/backend
// configured) and confirms the dry run returns 200 with an invalid (but
// non-error) result -- SimulateRotation only errors when the secret itself
// can't be found.
func TestSimulateRotation_Success(t *testing.T) {
	h, _ := newProjectHealthHandler(t)
	ctx := context.Background()
	proj, err := h.coreService.Storage().CreateProject(ctx, &models.Project{Name: "dryrun-proj"})
	require.NoError(t, err)
	env, err := h.coreService.Storage().CreateEnvironment(ctx, &models.Environment{Name: "dryrun-env", ProjectID: proj.ID})
	require.NoError(t, err)
	secret, err := h.coreService.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "dryrun-secret", Value: []byte("val"),
		ProjectID: proj.ID, EnvironmentID: env.ID,
		Type: "generic", CreatedBy: "tester", OwnerID: 1,
	})
	require.NoError(t, err)

	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/rotation/simulate", nil), "id", machineUintToStr(secret.ID))
	req = withUserCtx(req)
	w := httptest.NewRecorder()
	h.SimulateRotation(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"valid":false`)
}
