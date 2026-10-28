// secrets_graph_error_class_locale_test.go — the secret dependency-graph, certificate,
// rotation dry-run, version diff and version comment routes answer from the KIND of
// failure, not from the language of its message (ERRLOSS-SENTINELS-1 task 3.7, same
// class as #2461): missing secret/edge/version -> 404, invalid request -> 400,
// refusal -> 403, storage failure -> 5xx, under the shipped English text and under a
// translated locale. Like the other locale tests these flip the process-global
// localizer and are deliberately NOT t.Parallel().
package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// graphDo calls fn with the given chi params as actor.
func graphDo(fn http.HandlerFunc, method, body string, params map[string]string, actor uint) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtxID(req, actor, "actor")
	req = withChiParams(req, params)
	w := httptest.NewRecorder()
	fn(w, req)
	return w
}

type graphRoute struct {
	name string
	// fault is the first storage method this route reads for the path secret.
	fault string
	call  func(h *SecretHandler, id string, other uint, actor uint) *httptest.ResponseRecorder
}

func graphRoutes() []graphRoute {
	byID := func(name, fault string, fn func(h *SecretHandler) http.HandlerFunc) graphRoute {
		return graphRoute{name, fault, func(h *SecretHandler, id string, _ uint, a uint) *httptest.ResponseRecorder {
			return graphDo(fn(h), http.MethodGet, "", map[string]string{"id": id}, a)
		}}
	}
	return []graphRoute{
		byID("ListSecretDependencies", "GetSecret", func(h *SecretHandler) http.HandlerFunc { return h.ListSecretDependencies }),
		byID("GetSecretImpact", "GetSecret", func(h *SecretHandler) http.HandlerFunc { return h.GetSecretImpact }),
		byID("GetSecretImpactPreview", "GetSecret", func(h *SecretHandler) http.HandlerFunc { return h.GetSecretImpactPreview }),
		{"AddSecretDependency", "GetSecret", func(h *SecretHandler, id string, other uint, a uint) *httptest.ResponseRecorder {
			return graphDo(h.AddSecretDependency, http.MethodPost, `{"depends_on_id":`+strconv.Itoa(int(other))+`}`, map[string]string{"id": id}, a)
		}},
		{"RemoveSecretDependency", "GetSecret", func(h *SecretHandler, id string, _ uint, a uint) *httptest.ResponseRecorder {
			return graphDo(h.RemoveSecretDependency, http.MethodDelete, "", map[string]string{"id": id, "depId": "1"}, a)
		}},
		byID("GetSecretCertificate", "GetSecret", func(h *SecretHandler) http.HandlerFunc { return h.GetSecretCertificate }),
		{"SimulateRotation", "GetSecret", func(h *SecretHandler, id string, _ uint, a uint) *httptest.ResponseRecorder {
			return graphDo(h.SimulateRotation, http.MethodPost, "", map[string]string{"id": id}, a)
		}},
		{"DiffSecretVersions", "GetSecret", func(h *SecretHandler, id string, _ uint, a uint) *httptest.ResponseRecorder {
			return graphDo(h.DiffSecretVersions, http.MethodGet, "", map[string]string{"id": id, "from": "1", "to": "2"}, a)
		}},
	}
}

// seedGraphSecondSecret adds a second secret in the fixture's project and environment.
func seedGraphSecondSecret(t *testing.T, db *gorm.DB, fx secretsFixture) uint {
	t.Helper()
	other := &models.SecretNode{Name: "ec-other", ProjectID: fx.projectID, EnvironmentID: fx.envID,
		OwnerID: secretsAdminID, Type: "static", IsSecret: true}
	require.NoError(t, db.Create(other).Error)
	// seedSecretsFixture's own secret is created without IsSecret; the graph needs both ends to be secrets.
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", fx.secretID).Update("is_secret", true).Error)
	return other.ID
}

func TestGraphRoutes_MissingSecretIs404InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range graphRoutes() {
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				h, db, fx := newSecretsHandlerWithDB(t, lang)
				other := seedGraphSecondSecret(t, db, fx)
				w := rt.call(h, secretsMissingID, other, secretsAdminID)
				assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// A storage failure reading the path secret is a 5xx in every locale: never a 404
// ("no such secret"), and the driver text never reaches the client.
func TestGraphRoutes_StorageFaultIs5xxInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range graphRoutes() {
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				_, db, fx := newSecretsHandlerWithDB(t, lang)
				other := seedGraphSecondSecret(t, db, fx)
				faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
					Method: rt.fault, NthCall: 1, Kind: faultstorage.KindError,
					Err: errors.New("open /var/db: not found"),
				})
				fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
				require.NoError(t, err)

				w := rt.call(fh, strconv.Itoa(int(fx.secretID)), other, secretsAdminID)
				require.True(t, faulty.Fired(), "%s must reach storage method %s", rt.name, rt.fault)
				assert.GreaterOrEqual(t, w.Code, 500, "body: %s", w.Body.String())
				assert.NotContains(t, w.Body.String(), "/var/db", "the storage error text never reaches the client")
			})
		}
	}
}

// Adding a dependency: a storage failure reading the TARGET is a 5xx, not the opaque
// 400 that a missing or foreign target gets.
func TestAddSecretDependency_TargetLookupFaultIs5xxInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang, func(t *testing.T) {
			_, db, fx := newSecretsHandlerWithDB(t, lang)
			other := seedGraphSecondSecret(t, db, fx)
			faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
				Method: "GetSecret", NthCall: 2, Kind: faultstorage.KindError,
				Err: errors.New("open /var/db: not found"),
			})
			fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
			require.NoError(t, err)

			w := graphDo(fh.AddSecretDependency, http.MethodPost, `{"depends_on_id":`+strconv.Itoa(int(other))+`}`,
				map[string]string{"id": strconv.Itoa(int(fx.secretID))}, secretsAdminID)
			require.True(t, faulty.Fired(), "the target read must hit GetSecret")
			assert.GreaterOrEqual(t, w.Code, 500, "body: %s", w.Body.String())
			assert.NotContains(t, w.Body.String(), "/var/db")
		})
	}
}

func TestAddSecretDependency_InvalidRequestIs400InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang+"/self", func(t *testing.T) {
			h, db, fx := newSecretsHandlerWithDB(t, lang)
			seedGraphSecondSecret(t, db, fx)
			w := graphDo(h.AddSecretDependency, http.MethodPost, `{"depends_on_id":`+strconv.Itoa(int(fx.secretID))+`}`,
				map[string]string{"id": strconv.Itoa(int(fx.secretID))}, secretsAdminID)
			assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
		})
		t.Run(lang+"/missing-target", func(t *testing.T) {
			h, db, fx := newSecretsHandlerWithDB(t, lang)
			seedGraphSecondSecret(t, db, fx)
			w := graphDo(h.AddSecretDependency, http.MethodPost, `{"depends_on_id":99999}`,
				map[string]string{"id": strconv.Itoa(int(fx.secretID))}, secretsAdminID)
			assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
		})
		t.Run(lang+"/duplicate", func(t *testing.T) {
			h, db, fx := newSecretsHandlerWithDB(t, lang)
			other := seedGraphSecondSecret(t, db, fx)
			params := map[string]string{"id": strconv.Itoa(int(fx.secretID))}
			body := `{"depends_on_id":` + strconv.Itoa(int(other)) + `}`
			require.Equal(t, http.StatusOK, graphDo(h.AddSecretDependency, http.MethodPost, body, params, secretsAdminID).Code)
			w := graphDo(h.AddSecretDependency, http.MethodPost, body, params, secretsAdminID)
			assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
		})
		t.Run(lang+"/cycle", func(t *testing.T) {
			h, db, fx := newSecretsHandlerWithDB(t, lang)
			other := seedGraphSecondSecret(t, db, fx)
			body := `{"depends_on_id":` + strconv.Itoa(int(other)) + `}`
			require.Equal(t, http.StatusOK, graphDo(h.AddSecretDependency, http.MethodPost, body,
				map[string]string{"id": strconv.Itoa(int(fx.secretID))}, secretsAdminID).Code)
			w := graphDo(h.AddSecretDependency, http.MethodPost, `{"depends_on_id":`+strconv.Itoa(int(fx.secretID))+`}`,
				map[string]string{"id": strconv.Itoa(int(other))}, secretsAdminID)
			assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
		})
	}
}

// A caller with no grant on the dependency target is refused 403 in every locale.
func TestAddSecretDependency_RefusalIs403InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang, func(t *testing.T) {
			h, db, fx := newSecretsHandlerWithDB(t, lang)
			other := seedGraphSecondSecret(t, db, fx)
			w := graphDo(h.AddSecretDependency, http.MethodPost, `{"depends_on_id":`+strconv.Itoa(int(other))+`}`,
				map[string]string{"id": strconv.Itoa(int(fx.secretID))}, secretsPlainID)
			assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
		})
	}
}

// Removing: an unknown edge is 404; a storage failure reading the edge is a 5xx.
func TestRemoveSecretDependency_EdgeLookupInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang+"/missing", func(t *testing.T) {
			h, db, fx := newSecretsHandlerWithDB(t, lang)
			seedGraphSecondSecret(t, db, fx)
			w := graphDo(h.RemoveSecretDependency, http.MethodDelete, "",
				map[string]string{"id": strconv.Itoa(int(fx.secretID)), "depId": "99999"}, secretsAdminID)
			assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
		})
		t.Run(lang+"/fault", func(t *testing.T) {
			_, db, fx := newSecretsHandlerWithDB(t, lang)
			seedGraphSecondSecret(t, db, fx)
			faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
				Method: "GetSecretDependency", NthCall: 1, Kind: faultstorage.KindError,
				Err: errors.New("open /var/db: not found"),
			})
			fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
			require.NoError(t, err)
			w := graphDo(fh.RemoveSecretDependency, http.MethodDelete, "",
				map[string]string{"id": strconv.Itoa(int(fx.secretID)), "depId": "1"}, secretsAdminID)
			require.True(t, faulty.Fired())
			assert.GreaterOrEqual(t, w.Code, 500, "body: %s", w.Body.String())
			assert.NotContains(t, w.Body.String(), "/var/db")
		})
	}
}

// Certificate inspection of a secret that has no version is 404; a storage failure
// reading the latest version is a 5xx; a caller with no grant is 403.
func TestGetSecretCertificate_KindsInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang+"/no-version", func(t *testing.T) {
			h, _, fx := newSecretsHandlerWithDB(t, lang)
			w := graphDo(h.GetSecretCertificate, http.MethodGet, "", map[string]string{"id": fx.id()}, secretsAdminID)
			assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
		})
		t.Run(lang+"/version-fault", func(t *testing.T) {
			_, db, fx := newSecretsHandlerWithDB(t, lang)
			faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
				Method: "GetLatestSecretVersion", NthCall: 1, Kind: faultstorage.KindError,
				Err: errors.New("open /var/db: not found"),
			})
			fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
			require.NoError(t, err)
			w := graphDo(fh.GetSecretCertificate, http.MethodGet, "", map[string]string{"id": fx.id()}, secretsAdminID)
			require.True(t, faulty.Fired())
			assert.GreaterOrEqual(t, w.Code, 500, "body: %s", w.Body.String())
			assert.NotContains(t, w.Body.String(), "/var/db")
		})
		t.Run(lang+"/refusal", func(t *testing.T) {
			h, _, fx := newSecretsHandlerWithDB(t, lang)
			w := graphDo(h.GetSecretCertificate, http.MethodGet, "", map[string]string{"id": fx.id()}, secretsPlainID)
			assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
		})
	}
}

// Version diff: identical versions are 400, unknown versions of a real secret are
// 404, and a storage failure listing the versions is a 5xx.
func TestDiffSecretVersions_KindsInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang+"/same-version", func(t *testing.T) {
			h, _, fx := newSecretsHandlerWithDB(t, lang)
			w := graphDo(h.DiffSecretVersions, http.MethodGet, "", map[string]string{"id": fx.id(), "from": "1", "to": "1"}, secretsAdminID)
			assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
		})
		t.Run(lang+"/unknown-version", func(t *testing.T) {
			h, _, fx := newSecretsHandlerWithDB(t, lang)
			w := graphDo(h.DiffSecretVersions, http.MethodGet, "", map[string]string{"id": fx.id(), "from": "1", "to": "2"}, secretsAdminID)
			assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
		})
		t.Run(lang+"/versions-fault", func(t *testing.T) {
			_, db, fx := newSecretsHandlerWithDB(t, lang)
			faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
				Method: "GetSecretVersions", NthCall: 1, Kind: faultstorage.KindError,
				Err: errors.New("open /var/db: not found"),
			})
			fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
			require.NoError(t, err)
			w := graphDo(fh.DiffSecretVersions, http.MethodGet, "", map[string]string{"id": fx.id(), "from": "1", "to": "2"}, secretsAdminID)
			require.True(t, faulty.Fired())
			assert.GreaterOrEqual(t, w.Code, 500, "body: %s", w.Body.String())
			assert.NotContains(t, w.Body.String(), "/var/db")
		})
	}
}

// Version comments: a version that is not one of the secret's is 404; a storage
// failure listing the secret's versions is a 5xx.
func TestVersionCommentRoutes_KindsInEveryLocale(t *testing.T) {
	type call func(h *SecretVersionCommentHandler, secretID, versionID string) *httptest.ResponseRecorder
	calls := map[string]call{
		"CreateComment": func(h *SecretVersionCommentHandler, s, v string) *httptest.ResponseRecorder {
			return graphDo(h.CreateComment, http.MethodPost, `{"comment":"c"}`, map[string]string{"id": s, "versionId": v}, secretsAdminID)
		},
		"ListComments": func(h *SecretVersionCommentHandler, s, v string) *httptest.ResponseRecorder {
			return graphDo(h.ListComments, http.MethodGet, "", map[string]string{"id": s, "versionId": v}, secretsAdminID)
		},
		"DeleteComment": func(h *SecretVersionCommentHandler, s, v string) *httptest.ResponseRecorder {
			return graphDo(h.DeleteComment, http.MethodDelete, "", map[string]string{"id": s, "versionId": v, "commentId": "1"}, secretsAdminID)
		},
	}
	for _, lang := range errorClassLocales {
		for name, c := range calls {
			t.Run(lang+"/"+name+"/unknown-version", func(t *testing.T) {
				_, db, fx := newSecretsHandlerWithDB(t, lang)
				h := NewSecretVersionCommentHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
				w := c(h, fx.id(), "99999")
				assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
			})
			t.Run(lang+"/"+name+"/versions-fault", func(t *testing.T) {
				_, db, fx := newSecretsHandlerWithDB(t, lang)
				faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
					Method: "GetSecretVersions", NthCall: 1, Kind: faultstorage.KindError,
					Err: errors.New("open /var/db: not found"),
				})
				h := NewSecretVersionCommentHandler(core.NewKeyorixCore(faulty))
				w := c(h, fx.id(), "1")
				require.True(t, faulty.Fired())
				assert.GreaterOrEqual(t, w.Code, 500, "body: %s", w.Body.String())
				assert.NotContains(t, w.Body.String(), "/var/db")
			})
		}
	}
}
