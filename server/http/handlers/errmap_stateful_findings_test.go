package handlers

// errmap_stateful_findings_test.go — FIX-ERRMAP-STRUCT-1 item 2 (#4132): the handler
// families the stateful OpenAPI fuzzer caught answering an undeclared 500 for a core
// refusal (OPENAPI-STATEFUL-1/2/3/5/8) answer the declared 4xx through the shared
// classifier (server/errclass, answerCoreError). One case per finding, driven through
// the real handler against SQLite with the state that triggers the refusal, under
// "en" and the translated pseudo-locale (a text match that worked in English is the
// bug class: INV-HTTP-classify-errors-by-sentinel-not-text).

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type errmapWorld struct {
	cs                     *core.KeyorixCore
	db                     *gorm.DB
	projectA, projectB     uint
	envA                   uint
	suspendedSecret        uint
	machineB               uint // a machine identity in project B
	machineByActor         uint // a machine identity in project A created by the acting admin
	viewerUser, viewerRole uint
}

func seedErrmapWorld(t *testing.T, cs *core.KeyorixCore, db *gorm.DB) errmapWorld {
	t.Helper()
	w := errmapWorld{cs: cs, db: db}
	pa := &models.Project{Name: "errmap-a"}
	pb := &models.Project{Name: "errmap-b"}
	require.NoError(t, db.Create(pa).Error)
	require.NoError(t, db.Create(pb).Error)
	w.projectA, w.projectB = pa.ID, pb.ID
	env := &models.Environment{Name: "errmap-env", ProjectID: pa.ID}
	require.NoError(t, db.Create(env).Error)
	w.envA = env.ID
	sec := &models.SecretNode{Name: "errmap-suspended", ProjectID: pa.ID, EnvironmentID: env.ID, OwnerID: secretsAdminID, Type: "static", Status: core.SecretStatusSuspended}
	require.NoError(t, db.Create(sec).Error)
	w.suspendedSecret = sec.ID
	mb := &models.MachineIdentity{ProjectID: pb.ID, Name: "errmap-machine-b", State: core.MachineActive}
	require.NoError(t, db.Create(mb).Error)
	w.machineB = mb.ID
	ma := &models.MachineIdentity{ProjectID: pa.ID, Name: "errmap-machine-a", State: core.MachineActive, CreatedBy: secretsAdminID}
	require.NoError(t, db.Create(ma).Error)
	w.machineByActor = ma.ID
	u := &models.User{Username: "errmap_viewer", UsernameFolded: "errmap_viewer", Email: "errmap-viewer@example.com", EmailFolded: "errmap-viewer@example.com", AccountState: "active"}
	require.NoError(t, db.Create(u).Error)
	w.viewerUser = u.ID
	r := &models.Role{Name: "errmap_project_viewer", NameFolded: "errmap_project_viewer", Description: "viewer", AssignableScope: "project"}
	require.NoError(t, db.Create(r).Error)
	w.viewerRole = r.ID
	return w
}

func errmapJSON(method, body string) *http.Request {
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return withUserCtxID(req, secretsAdminID, "admin")
}

type errmapCase struct {
	finding string
	name    string
	want    int
	// bodyHas is a substring the body must carry (the stable error code or text).
	bodyHas string
	call    func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder
}

func errmapCases() []errmapCase {
	return []errmapCase{
		{"OPENAPI-STATEFUL-2", "ListMachineTokens of a machine in another project is 404", http.StatusNotFound, "NotFound",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h := NewCatalogHandler(w.cs)
				req := withChiParams2_S25(errmapJSON(http.MethodGet, ""), "id", uintStrS28(w.projectA), "machineId", uintStrS28(w.machineB))
				rec := httptest.NewRecorder()
				h.ListMachineTokens(rec, req)
				return rec
			}},
		{"OPENAPI-STATEFUL-2", "CreateMachineIdentity with an unknown classification is 400", http.StatusBadRequest, "ValidationError",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h := NewCatalogHandler(w.cs)
				req := withChiParam(errmapJSON(http.MethodPost, `{"name":"bot","identity_type":"ci","classification":"ultra"}`), "id", uintStrS28(w.projectA))
				rec := httptest.NewRecorder()
				h.CreateMachineIdentity(rec, req)
				return rec
			}},
		{"OPENAPI-STATEFUL-5", "ResumeSecret whose environment was deleted is 404", http.StatusNotFound, "NotFound",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				require.NoError(t, w.db.Delete(&models.Environment{}, w.envA).Error)
				h, err := NewSecretHandler(w.cs)
				require.NoError(t, err)
				req := withChiParam(errmapJSON(http.MethodPost, ""), "id", uintStrS28(w.suspendedSecret))
				rec := httptest.NewRecorder()
				h.ResumeSecret(rec, req)
				return rec
			}},
		{"OPENAPI-STATEFUL-8", "RevokeProjectAccessReview of a role the user does not hold is 404", http.StatusNotFound, "NotFound",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h := NewCatalogHandler(w.cs)
				body := fmt.Sprintf(`{"source":"role","principal_type":"user","principal_id":%d,"role_id":%d}`, w.viewerUser, w.viewerRole)
				req := withChiParam(errmapJSON(http.MethodPost, body), "id", uintStrS28(w.projectA))
				rec := httptest.NewRecorder()
				h.RevokeProjectAccessReview(rec, req)
				return rec
			}},
		{"OPENAPI-STATEFUL-8", "RevokeProjectAccessReview by the machine's own provisioner is 403 (independent reviewer)", http.StatusForbidden, "Forbidden",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h := NewCatalogHandler(w.cs)
				body := fmt.Sprintf(`{"source":"role","principal_type":"machine","principal_id":%d,"role_id":%d}`, w.machineByActor, w.viewerRole)
				req := withChiParam(errmapJSON(http.MethodPost, body), "id", uintStrS28(w.projectA))
				rec := httptest.NewRecorder()
				h.RevokeProjectAccessReview(rec, req)
				return rec
			}},
		{"OPENAPI-STATEFUL-3", "GetProjectStats of a missing project is 404", http.StatusNotFound, "NotFound",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h, err := NewSecretHandler(w.cs)
				require.NoError(t, err)
				req := withChiParam(errmapJSON(http.MethodGet, ""), "id", "987654")
				rec := httptest.NewRecorder()
				h.GetProjectStats(rec, req)
				return rec
			}},
		{"OPENAPI-STATEFUL-3", "CreateSecretTemplate with an over-long name is 400", http.StatusBadRequest, "ValidationError",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h := NewSecretTemplateHandler(w.cs)
				req := errmapJSON(http.MethodPost, fmt.Sprintf(`{"name":%q}`, strings.Repeat("n", 600)))
				rec := httptest.NewRecorder()
				h.Create(rec, req)
				return rec
			}},
		{"OPENAPI-STATEFUL-3", "CreateSecretTemplate with an unknown classification is 400", http.StatusBadRequest, "ValidationError",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h := NewSecretTemplateHandler(w.cs)
				req := errmapJSON(http.MethodPost, `{"name":"tpl","default_classification":"ultra"}`)
				rec := httptest.NewRecorder()
				h.Create(rec, req)
				return rec
			}},
		{"OPENAPI-STATEFUL-3", "CreateRejectionReasonTemplate without a reason is 400", http.StatusBadRequest, "ValidationError",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h := NewCatalogHandler(w.cs)
				req := errmapJSON(http.MethodPost, `{"name":"needs-more"}`)
				rec := httptest.NewRecorder()
				h.CreateRejectionReasonTemplate(rec, req)
				return rec
			}},
		{"OPENAPI-STATEFUL-3", "RestoreSecret of a live secret is 409", http.StatusConflict, "",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h, err := NewSecretHandler(w.cs)
				require.NoError(t, err)
				req := withChiParam(errmapJSON(http.MethodPost, ""), "id", uintStrS28(w.suspendedSecret))
				rec := httptest.NewRecorder()
				h.RestoreSecret(rec, req)
				return rec
			}},
		{"OPENAPI-STATEFUL-3", "RestoreSecret of an absent secret is 404", http.StatusNotFound, "",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h, err := NewSecretHandler(w.cs)
				require.NoError(t, err)
				req := withChiParam(errmapJSON(http.MethodPost, ""), "id", "987654")
				rec := httptest.NewRecorder()
				h.RestoreSecret(rec, req)
				return rec
			}},
		{"OPENAPI-STATEFUL-3", "CreateFolder with a name the identifier policy rejects is 400", http.StatusBadRequest, "ValidationError",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h := NewFolderHandler(w.cs)
				body := fmt.Sprintf("{\"name\":\"bad\u202ename\",\"project_id\":%d,\"environment_id\":%d}", w.projectA, w.envA)
				rec := httptest.NewRecorder()
				h.CreateFolder(rec, errmapJSON(http.MethodPost, body))
				return rec
			}},
		{"OPENAPI-STATEFUL-3", "ShareSecret of an absent secret is 404", http.StatusNotFound, "NotFound",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h, err := NewShareHandler(w.cs)
				require.NoError(t, err)
				body := fmt.Sprintf(`{"recipient_id":%d,"permission":"read"}`, w.viewerUser)
				req := withChiParam(errmapJSON(http.MethodPost, body), "id", "987654")
				rec := httptest.NewRecorder()
				h.ShareSecret(rec, req)
				return rec
			}},
		{"OPENAPI-STATEFUL-3", "ShareSecret with a recipient outside the project is 403", http.StatusForbidden, "Forbidden",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h, err := NewShareHandler(w.cs)
				require.NoError(t, err)
				body := fmt.Sprintf(`{"recipient_id":%d,"permission":"read"}`, w.viewerUser)
				req := withChiParam(errmapJSON(http.MethodPost, body), "id", uintStrS28(w.suspendedSecret))
				rec := httptest.NewRecorder()
				h.ShareSecret(rec, req)
				return rec
			}},
		{"OPENAPI-STATEFUL-1", "GetSecretCertificate as a machine principal is a declared 4xx, not 500", http.StatusBadRequest, "ValidationError",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h, err := NewSecretHandler(w.cs)
				require.NoError(t, err)
				req := withChiParam(withMachineCtxS10(httptest.NewRequest(http.MethodGet, "/", nil)), "id", uintStrS28(w.suspendedSecret))
				rec := httptest.NewRecorder()
				h.GetSecretCertificate(rec, req)
				return rec
			}},
		{"OPENAPI-STATEFUL-1", "AccessHistory as a machine principal is a declared 4xx, not 500", http.StatusBadRequest, "ValidationError",
			func(t *testing.T, w errmapWorld) *httptest.ResponseRecorder {
				h, err := NewSecretHandler(w.cs)
				require.NoError(t, err)
				req := withChiParam(withMachineCtxS10(httptest.NewRequest(http.MethodGet, "/", nil)), "id", uintStrS28(w.suspendedSecret))
				rec := httptest.NewRecorder()
				h.AccessHistory(rec, req)
				return rec
			}},
	}
}

// TestErrMap_StatefulFindingsAnswerDeclaredStatus is the red/green test of #4132: every
// case answered an undeclared 500 (or a wrong 4xx) on origin/main before the handlers
// moved onto the shared classifier.
func TestErrMap_StatefulFindingsAnswerDeclaredStatus(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, tc := range errmapCases() {
			t.Run(lang+"/"+tc.finding+"/"+tc.name, func(t *testing.T) {
				cs, db := freshCoreS12WithAdmin(t)
				withErrorTextLocale(t, lang)
				w := seedErrmapWorld(t, cs, db)
				rec := tc.call(t, w)
				assert.Equal(t, tc.want, rec.Code, "body: %s", rec.Body.String())
				if tc.bodyHas != "" {
					assert.Contains(t, rec.Body.String(), tc.bodyHas)
				}
				assert.NotContains(t, rec.Body.String(), "pq:", "no driver text")
			})
		}
	}
}
