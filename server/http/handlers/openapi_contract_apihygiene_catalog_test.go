// openapi_contract_apihygiene_catalog_test.go — proving tests for the 6
// operationIds backfilled with a real response schema by the API-hygiene
// casing campaign's PR C2 (catalog: Projects/Environments): getProject,
// createProject, updateProject, listEnvironments, createProjectEnvironment,
// cloneEnvironment. See catalog_wire.go and checks_test.go's
// TestEnforcedSetMatchesADR074 comment for the same set.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

func TestContractAPIHygiene_GetProject(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "contract-ah-getproject", "")
	require.NoError(t, err)

	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1", nil), "id", itoa(proj.ID)))
	w := httptest.NewRecorder()
	h.GetProject(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractAPIHygiene_CreateProject(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	body, _ := json.Marshal(map[string]any{"name": "contract-ah-createproject"})

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateProject(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractAPIHygiene_UpdateProject(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "contract-ah-updateproject", "")
	require.NoError(t, err)
	body, _ := json.Marshal(map[string]any{"name": "contract-ah-updateproject-renamed"})

	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/api/v1/projects/1", bytes.NewReader(body)), "id", itoa(proj.ID)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateProject(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractAPIHygiene_ListEnvironments(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "contract-ah-listenvironments", "")
	require.NoError(t, err)
	_, err = cs.CreateEnvironment(context.Background(), proj.ID, "contract-env")
	require.NoError(t, err)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/environments", nil))
	w := httptest.NewRecorder()
	h.ListEnvironments(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractAPIHygiene_CreateProjectEnvironment(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	proj, err := cs.CreateProject(context.Background(), "contract-ah-createprojectenv", "")
	require.NoError(t, err)
	body, _ := json.Marshal(map[string]any{"name": "contract-new-env"})

	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments", bytes.NewReader(body)), "id", itoa(proj.ID)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateProjectEnvironment(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractAPIHygiene_CloneEnvironment(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	ctx := context.Background()

	proj, err := cs.Storage().CreateProject(ctx, &models.Project{Name: "contract-ah-clone-proj"})
	require.NoError(t, err)
	src, err := cs.Storage().CreateEnvironment(ctx, &models.Environment{Name: "src", ProjectID: proj.ID})
	require.NoError(t, err)
	dst, err := cs.Storage().CreateEnvironment(ctx, &models.Environment{Name: "dst", ProjectID: proj.ID})
	require.NoError(t, err)
	_, err = cs.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "contract-ah-clone-secret", Value: []byte("v"),
		ProjectID: proj.ID, EnvironmentID: src.ID,
		Type: "generic", CreatedBy: "owner", OwnerID: 1,
	})
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{"destination_environment_id": dst.ID})
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments/1/clone", bytes.NewReader(body)),
		map[string]string{"id": itoa(proj.ID), "envId": itoa(src.ID)}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CloneEnvironment(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}
