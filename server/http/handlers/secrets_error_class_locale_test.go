// secrets_error_class_locale_test.go — the secret CRUD / version routes must
// answer from the KIND of failure, not from the language of its message
// (ERRLOSS-SENTINELS-1 task 3.3, same class as #2461/#2905): not-found -> 404,
// refusal -> 403, duplicate -> 409, invalid target -> 422, storage failure ->
// 5xx, under the shipped English text and under a translated locale.
//
// These handlers matched strings.Contains(err.Error(), "not found" /
// "permission denied" / "already exists"). Under a translated locale the i18n
// part no longer matches, so a real 404 became a 500; and core wraps a driver
// error under the not-found text, so a storage failure on the secret lookup was
// answered 404 even in English. Like the other locale tests these flip the
// process-global localizer and are deliberately NOT t.Parallel().
package handlers

import (
	"errors"
	"fmt"
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

const (
	secretsMissingID = "99999"
	// secretsAdminID is the global admin freshCoreS12WithAdmin wires up;
	// secretsPlainID holds no role anywhere.
	secretsAdminID uint = 1
	secretsPlainID uint = 2
)

type secretsFixture struct {
	secretID, projectID, envID uint
}

func (f secretsFixture) id() string { return strconv.FormatUint(uint64(f.secretID), 10) }

func seedSecretsFixture(t *testing.T, db *gorm.DB) secretsFixture {
	t.Helper()
	require.NoError(t, db.Create(&models.User{Username: "plain_user", UsernameFolded: "plain_user",
		Email: "plain@example.com", EmailFolded: "plain@example.com", AccountState: "active"}).Error)
	proj := &models.Project{Name: "ec-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "ec-env", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	secret := &models.SecretNode{Name: "ec-secret", ProjectID: proj.ID, EnvironmentID: env.ID, OwnerID: secretsAdminID, Type: "static"}
	require.NoError(t, db.Create(secret).Error)
	return secretsFixture{secretID: secret.ID, projectID: proj.ID, envID: env.ID}
}

func secretsDo(fn http.HandlerFunc, method, body, id string, actor uint) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtxID(req, actor, "actor")
	req = withChiParam(req, "id", id)
	w := httptest.NewRecorder()
	fn(w, req)
	return w
}

type secretsRoute struct {
	name string
	// fault is the storage method whose failure this route must surface as 5xx.
	fault string
	call  func(h *SecretHandler, id string, actor uint) *httptest.ResponseRecorder
}

func secretsIDRoutes() []secretsRoute {
	return []secretsRoute{
		{"GetSecret", "GetSecret", func(h *SecretHandler, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.GetSecret, http.MethodGet, "", id, a)
		}},
		{"DeleteSecret", "GetSecret", func(h *SecretHandler, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.DeleteSecret, http.MethodDelete, "", id, a)
		}},
		{"GetSecretVersions", "GetSecret", func(h *SecretHandler, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.GetSecretVersions, http.MethodGet, "", id, a)
		}},
		{"ClassifySecret", "GetSecret", func(h *SecretHandler, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.ClassifySecret, http.MethodPatch, `{"classification":"internal"}`, id, a)
		}},
		{"SetAutoRotate", "GetSecret", func(h *SecretHandler, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.SetAutoRotate, http.MethodPatch, `{"enabled":false}`, id, a)
		}},
		{"RotateSecret", "GetSecret", func(h *SecretHandler, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.RotateSecret, http.MethodPost, `{"new_value":"v2"}`, id, a)
		}},
		{"RollbackSecret", "GetSecretVersions", func(h *SecretHandler, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.RollbackSecret, http.MethodPost, `{"version":1}`, id, a)
		}},
	}
}

func newSecretsHandlerWithDB(t *testing.T, lang string) (*SecretHandler, *gorm.DB, secretsFixture) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	withErrorTextLocale(t, lang)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return h, db, seedSecretsFixture(t, db)
}

// Every secret-by-id route answers 404 for a missing secret in both locales.
func TestSecretRoutes_MissingSecretIs404InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range secretsIDRoutes() {
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				h, _, _ := newSecretsHandlerWithDB(t, lang)
				w := rt.call(h, secretsMissingID, secretsAdminID)
				assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// A rollback to a version the secret never had is a 404 too.
func TestSecretRoutes_MissingVersionIs404InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang, func(t *testing.T) {
			h, db, fx := newSecretsHandlerWithDB(t, lang)
			require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: fx.secretID, VersionNumber: 1, EncryptedValue: []byte("x")}).Error)
			w := secretsDo(h.RollbackSecret, http.MethodPost, `{"version":7}`, fx.id(), secretsAdminID)
			assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
		})
	}
}

// A caller holding no grant is refused 403 in every locale on the routes that
// authorize in core (read, versions list, delete).
func TestSecretRoutes_RefusalIs403InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, name := range []string{"GetSecret", "DeleteSecret", "GetSecretVersions"} {
			t.Run(lang+"/"+name, func(t *testing.T) {
				h, _, fx := newSecretsHandlerWithDB(t, lang)
				var rt secretsRoute
				for _, c := range secretsIDRoutes() {
					if c.name == name {
						rt = c
					}
				}
				w := rt.call(h, fx.id(), secretsPlainID)
				assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// A storage failure on the secret lookup is a 5xx in every locale: never a 404
// that a client would read as "no such secret", and never the raw driver text.
func TestSecretRoutes_StorageFaultIs5xxInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range secretsIDRoutes() {
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				_, db, fx := newSecretsHandlerWithDB(t, lang)
				faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
					Method: rt.fault, NthCall: 1, Kind: faultstorage.KindError,
					Err: errors.New("injected: " + rt.fault),
				})
				fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
				require.NoError(t, err)

				w := rt.call(fh, fx.id(), secretsAdminID)
				require.True(t, faulty.Fired(), "%s must reach storage method %s", rt.name, rt.fault)
				assert.GreaterOrEqual(t, w.Code, 500, "body: %s", w.Body.String())
				assert.NotContains(t, w.Body.String(), "injected", "the storage error text never reaches the client")
			})
		}
	}
}

// CreateSecret: a duplicate name is 409 and a target environment that is not the
// project's is 422, in every locale.
func TestSecretCreate_DuplicateAndBadTargetInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang, func(t *testing.T) {
			h, _, fx := newSecretsHandlerWithDB(t, lang)
			create := func(name string, env uint) *httptest.ResponseRecorder {
				body := fmt.Sprintf(`{"name":%q,"value":"v","project_id":%d,"environment_id":%d,"type":"static"}`, name, fx.projectID, env)
				return secretsDo(h.CreateSecret, http.MethodPost, body, "", secretsAdminID)
			}
			first := create("dup-name", fx.envID)
			require.Equal(t, http.StatusCreated, first.Code, "first create: %s", first.Body.String())
			assert.Equal(t, http.StatusConflict, create("dup-name", fx.envID).Code, "duplicate name")
			assert.Equal(t, http.StatusUnprocessableEntity, create("other-name", 98765).Code, "environment that does not exist")
		})
	}
}
