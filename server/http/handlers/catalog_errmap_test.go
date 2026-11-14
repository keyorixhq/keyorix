package handlers

// catalog_errmap_test.go — ERRMAP-CATALOG-NOV-1 item 1. The project and environment routes
// answered an ordinary refusal (a project that still holds secrets, a duplicate name, a
// restore of something that is not deleted, an absent target) with a text match or a blanket
// 500. They answer through answerCoreError now; the table pins case -> status, with the
// refusal's client text where the client reads it.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/errclass"
)

type catalogErrmapWorld struct {
	cs *core.KeyorixCore
	db *gorm.DB
	h  *CatalogHandler
}

func newCatalogErrmapWorld(t *testing.T) *catalogErrmapWorld {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	// The live-name uniqueness is an index ensureProjectNameIndex creates, not an AutoMigrate tag.
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_projects_name_active "+
		"ON projects (name_folded) WHERE deleted_at IS NULL AND name <> ''").Error)
	return &catalogErrmapWorld{cs: cs, db: db, h: NewCatalogHandler(cs)}
}

// project creates a live project (with its default environments) through core.
func (w *catalogErrmapWorld) project(t *testing.T, name string) *models.Project {
	t.Helper()
	p, err := w.cs.CreateProject(context.Background(), name, "")
	require.NoError(t, err)
	return p
}

func (w *catalogErrmapWorld) env(t *testing.T, projectID uint) *models.Environment {
	t.Helper()
	var e models.Environment
	require.NoError(t, w.db.Where("project_id = ?", projectID).Order("id").First(&e).Error)
	return &e
}

func (w *catalogErrmapWorld) secretIn(t *testing.T, p *models.Project, e *models.Environment) {
	t.Helper()
	require.NoError(t, w.db.Create(&models.SecretNode{
		ProjectID: p.ID, EnvironmentID: e.ID, Name: "kx-" + strconv.Itoa(int(e.ID)), IsSecret: true, Status: "active",
	}).Error)
}

func catalogCall(fn http.HandlerFunc, method, body string, params map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(withChiParams(req, params))
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

func TestCatalogRoutes_RefusalsAnswerTheirStatus(t *testing.T) {
	w := newCatalogErrmapWorld(t)
	id := func(p *models.Project) string { return strconv.Itoa(int(p.ID)) }
	eid := func(e *models.Environment) string { return strconv.Itoa(int(e.ID)) }

	full := w.project(t, "has-secrets")
	w.secretIn(t, full, w.env(t, full.ID))
	other := w.project(t, "other-name")
	empty := w.project(t, "empty-one")
	live := w.project(t, "live-one")
	liveEnv := w.env(t, live.ID)

	// A project and an environment that were deleted: restore targets.
	gone := w.project(t, "gone-one")
	goneEnv := w.env(t, gone.ID)
	require.NoError(t, w.cs.DeleteProject(context.Background(), 1, gone.ID, true))
	envWithSecret := w.env(t, full.ID)

	cases := []struct {
		name   string
		fn     http.HandlerFunc
		method string
		body   string
		params map[string]string
		status int
		text   string // substring of the answer's message, "" = unchecked
	}{
		{"DeleteProject with secrets", w.h.DeleteProject, http.MethodDelete, "", map[string]string{"id": id(full)}, http.StatusConflict, "secret(s)"},
		{"DeleteProject absent", w.h.DeleteProject, http.MethodDelete, "", map[string]string{"id": "999999"}, http.StatusNotFound, ""},
		{"UpdateProject duplicate name", w.h.UpdateProject, http.MethodPut, `{"name":"has-secrets"}`, map[string]string{"id": id(other)}, http.StatusConflict, "already exists"},
		{"UpdateProject description too long", w.h.UpdateProject, http.MethodPut, `{"name":"other-name","description":"` + strings.Repeat("a", 1100) + `"}`, map[string]string{"id": id(other)}, http.StatusBadRequest, "exceeds"},
		{"UpdateProject absent", w.h.UpdateProject, http.MethodPut, `{"name":"nobody"}`, map[string]string{"id": "999999"}, http.StatusNotFound, ""},
		{"CreateProjectEnvironment duplicate", w.h.CreateProjectEnvironment, http.MethodPost, `{"name":"` + liveEnv.Name + `"}`, map[string]string{"id": id(live)}, http.StatusConflict, "already exists"},
		{"CreateProjectEnvironment bad name", w.h.CreateProjectEnvironment, http.MethodPost, `{"name":"bad/name"}`, map[string]string{"id": id(live)}, http.StatusBadRequest, ""},
		{"CreateProjectEnvironment absent project", w.h.CreateProjectEnvironment, http.MethodPost, `{"name":"x"}`, map[string]string{"id": "999999"}, http.StatusNotFound, ""},
		{"RestoreProject not deleted", w.h.RestoreProject, http.MethodPost, "", map[string]string{"id": id(empty)}, http.StatusNotFound, ""},
		{"RestoreProject absent", w.h.RestoreProject, http.MethodPost, "", map[string]string{"id": "999999"}, http.StatusNotFound, ""},
		{"RestoreEnvironment not deleted", w.h.RestoreEnvironment, http.MethodPost, "", map[string]string{"projectId": id(live), "id": eid(liveEnv)}, http.StatusNotFound, ""},
		{"RestoreEnvironment absent", w.h.RestoreEnvironment, http.MethodPost, "", map[string]string{"projectId": id(live), "id": "999999"}, http.StatusNotFound, ""},
		{"RestoreEnvironment absent project", w.h.RestoreEnvironment, http.MethodPost, "", map[string]string{"projectId": "999999", "id": "1"}, http.StatusNotFound, ""},
		{"RestoreEnvironment under a deleted project", w.h.RestoreEnvironment, http.MethodPost, "", map[string]string{"projectId": id(gone), "id": eid(goneEnv)}, http.StatusConflict, "parent project is deleted"},
		{"DeleteEnvironment with secrets", w.h.DeleteEnvironment, http.MethodDelete, "", map[string]string{"id": eid(envWithSecret)}, http.StatusConflict, "active secret(s)"},
		{"DeleteEnvironment absent", w.h.DeleteEnvironment, http.MethodDelete, "", map[string]string{"id": "999999"}, http.StatusNotFound, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := catalogCall(tc.fn, tc.method, tc.body, tc.params)
			require.Equal(t, tc.status, rec.Code, rec.Body.String())
			var env struct {
				Error   string `json:"error"`
				Message string `json:"message"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
			if tc.text != "" {
				assert.Contains(t, env.Message, tc.text)
			}
			assert.NotContains(t, rec.Body.String(), "UNIQUE constraint", "no driver text reaches the client")
		})
	}
}

// TestDeleteProject_SecretRefusalIsAPreconditionSentinel pins what REST and gRPC read: the
// refusal matches core.ErrProjectHasSecrets and classifies as a precondition (REST 409, gRPC
// FailedPrecondition through the shared table), and its text is unchanged.
func TestDeleteProject_SecretRefusalIsAPreconditionSentinel(t *testing.T) {
	w := newCatalogErrmapWorld(t)
	p := w.project(t, "keeps-secrets")
	w.secretIn(t, p, w.env(t, p.ID))

	err := w.cs.DeleteProject(context.Background(), 1, p.ID, false)
	require.ErrorIs(t, err, core.ErrProjectHasSecrets)
	assert.Equal(t, errclass.Precondition, errclass.Of(err))
	assert.Contains(t, err.Error(), "project has 1 secret(s)")
}

// TestRestoreEnvironment_PermissionRefusalKeepsCoreText pins that the 403 for a restore
// that would reinstate an administrative grant carries core's own wording, as it did
// before the route answered through answerCoreError.
func TestRestoreEnvironment_PermissionRefusalKeepsCoreText(t *testing.T) {
	w := newCatalogErrmapWorld(t)
	p := w.project(t, "admin-grant")
	e := w.env(t, p.ID)
	require.NoError(t, w.db.Exec("UPDATE environments SET deleted_at = CURRENT_TIMESTAMP WHERE id = ?", e.ID).Error)

	role := models.Role{Name: "bypass-role", BypassesPermissionChecks: true}
	require.NoError(t, w.db.Create(&role).Error)
	require.NoError(t, w.db.Create(&models.UserRole{UserID: 1, RoleID: role.ID, ProjectID: p.ID}).Error)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req = withChiParams(req, map[string]string{"projectId": strconv.Itoa(int(p.ID)), "id": strconv.Itoa(int(e.ID))})
	req = withUserCtxID(req, 2, "plain-user") // holds no global admin role
	rec := httptest.NewRecorder()
	w.h.RestoreEnvironment(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "only an administrator can restore")
}
