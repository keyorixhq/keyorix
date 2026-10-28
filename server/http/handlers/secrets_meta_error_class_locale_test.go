// secrets_meta_error_class_locale_test.go — the secret tag, description, move and
// copy routes answer from the KIND of failure, not from the language of its
// message (ERRLOSS-SENTINELS-1 task 3.4, same class as #2461): not-found -> 404,
// refusal -> 403, invalid input -> 400, storage failure -> 5xx, under the shipped
// English text and under a translated locale. Like the other locale tests these
// flip the process-global localizer and are deliberately NOT t.Parallel().
package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

type secretsMetaRoute struct {
	name string
	call func(h *SecretHandler, fx secretsFixture, id string, actor uint) *httptest.ResponseRecorder
}

func secretsMetaRoutes() []secretsMetaRoute {
	return []secretsMetaRoute{
		{"SetTags", func(h *SecretHandler, _ secretsFixture, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.SetTags, http.MethodPut, `{"tags":["a"]}`, id, a)
		}},
		{"DescribeSecret", func(h *SecretHandler, _ secretsFixture, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.DescribeSecret, http.MethodPatch, `{"description":"note"}`, id, a)
		}},
		{"MoveSecret", func(h *SecretHandler, _ secretsFixture, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.MoveSecret, http.MethodPost, `{"parent_id":0}`, id, a)
		}},
		{"CopySecret", func(h *SecretHandler, fx secretsFixture, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.CopySecret, http.MethodPost, fmt.Sprintf(`{"environment_id":%d,"name":"copy"}`, fx.envID), id, a)
		}},
	}
}

func TestSecretMetaRoutes_MissingSecretIs404InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range secretsMetaRoutes() {
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				h, _, fx := newSecretsHandlerWithDB(t, lang)
				w := rt.call(h, fx, secretsMissingID, secretsAdminID)
				assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// A caller holding no grant is refused 403 in every locale (copy refuses at the
// target-environment authorization, the others in core).
func TestSecretMetaRoutes_RefusalIs403InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range secretsMetaRoutes() {
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				h, _, fx := newSecretsHandlerWithDB(t, lang)
				w := rt.call(h, fx, fx.id(), secretsPlainID)
				assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// A storage failure on the secret lookup is a 5xx in every locale: never a 404
// that a client would read as "no such secret", never the raw driver text.
func TestSecretMetaRoutes_StorageFaultIs5xxInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range secretsMetaRoutes() {
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				_, db, fx := newSecretsHandlerWithDB(t, lang)
				faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
					Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError,
					Err: errors.New("injected: GetSecret"),
				})
				fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
				require.NoError(t, err)

				w := rt.call(fh, fx, fx.id(), secretsAdminID)
				require.True(t, faulty.Fired(), "%s must reach storage method GetSecret", rt.name)
				assert.GreaterOrEqual(t, w.Code, 500, "body: %s", w.Body.String())
				assert.NotContains(t, w.Body.String(), "injected", "the storage error text never reaches the client")
			})
		}
	}
}

// Copying a source whose own state refuses the value read is answered with that
// refusal's status and stable code, never the 500 default: suspended and
// max-reads-exhausted are 409, outside the access schedule is 403, in every locale.
func TestCopySecret_SourceStateRefusalKeepsItsStatusInEveryLocale(t *testing.T) {
	states := []struct {
		name   string
		status int
		code   string
		apply  func(t *testing.T, db *gorm.DB, id uint)
	}{
		{"suspended", http.StatusConflict, core.SecretReadRefusalCodeSuspended, func(t *testing.T, db *gorm.DB, id uint) {
			require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", id).Update("status", core.SecretStatusSuspended).Error)
		}},
		{"max reads exhausted", http.StatusConflict, core.SecretReadRefusalCodeMaxReadsExhausted, func(t *testing.T, db *gorm.DB, id uint) {
			require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", id).Updates(map[string]any{"max_reads": 1, "read_count": 1}).Error)
		}},
		{"outside schedule", http.StatusForbidden, core.SecretReadRefusalCodeOutsideSchedule, func(t *testing.T, db *gorm.DB, id uint) {
			require.NoError(t, db.Create(&models.SecretAccessSchedule{
				SecretNodeID: id, AllowedDays: "*", StartHour: 0, EndHour: 0, Timezone: "UTC",
			}).Error)
		}},
	}
	for _, lang := range errorClassLocales {
		for _, st := range states {
			t.Run(lang+"/"+st.name, func(t *testing.T) {
				h, db, fx := newSecretsHandlerWithDB(t, lang)
				created := secretsDo(h.CreateSecret, http.MethodPost,
					fmt.Sprintf(`{"name":"copy-src","value":"v","project_id":%d,"environment_id":%d,"type":"static"}`, fx.projectID, fx.envID),
					"", secretsAdminID)
				require.Equal(t, http.StatusCreated, created.Code, "create source: %s", created.Body.String())
				var src models.SecretNode
				require.NoError(t, db.Where("name = ?", "copy-src").First(&src).Error)
				st.apply(t, db, src.ID)

				w := secretsDo(h.CopySecret, http.MethodPost, fmt.Sprintf(`{"environment_id":%d,"name":"copy"}`, fx.envID),
					fmt.Sprint(src.ID), secretsAdminID)
				assert.Equal(t, st.status, w.Code, "body: %s", w.Body.String())
				assert.Contains(t, w.Body.String(), st.code)
			})
		}
	}
}

// Invalid input is a 400 in every locale: too many tags, an over-long
// description, a node moved into itself, a copy into an environment of another
// project or one that does not exist.
func TestSecretMetaRoutes_InvalidInputIs400InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang, func(t *testing.T) {
			h, db, fx := newSecretsHandlerWithDB(t, lang)

			tags := make([]string, 21)
			for i := range tags {
				tags[i] = fmt.Sprintf(`"t%d"`, i)
			}
			w := secretsDo(h.SetTags, http.MethodPut, `{"tags":[`+strings.Join(tags, ",")+`]}`, fx.id(), secretsAdminID)
			assert.Equal(t, http.StatusBadRequest, w.Code, "too many tags: %s", w.Body.String())

			w = secretsDo(h.DescribeSecret, http.MethodPatch, `{"description":"`+strings.Repeat("x", 1025)+`"}`, fx.id(), secretsAdminID)
			assert.Equal(t, http.StatusBadRequest, w.Code, "long description: %s", w.Body.String())

			w = secretsDo(h.MoveSecret, http.MethodPost, fmt.Sprintf(`{"parent_id":%d}`, fx.secretID), fx.id(), secretsAdminID)
			assert.Equal(t, http.StatusBadRequest, w.Code, "move into itself: %s", w.Body.String())

			// Copy needs a source with a readable value: create it through core.
			created := secretsDo(h.CreateSecret, http.MethodPost,
				fmt.Sprintf(`{"name":"copy-src","value":"v","project_id":%d,"environment_id":%d,"type":"static"}`, fx.projectID, fx.envID),
				"", secretsAdminID)
			require.Equal(t, http.StatusCreated, created.Code, "create source: %s", created.Body.String())
			var src models.SecretNode
			require.NoError(t, db.Where("name = ?", "copy-src").First(&src).Error)

			other := &models.Project{Name: "other-proj"}
			require.NoError(t, db.Create(other).Error)
			otherEnv := &models.Environment{Name: "other-env", ProjectID: other.ID}
			require.NoError(t, db.Create(otherEnv).Error)
			for name, env := range map[string]uint{"other project": otherEnv.ID, "missing environment": 98765} {
				w = secretsDo(h.CopySecret, http.MethodPost, fmt.Sprintf(`{"environment_id":%d,"name":"c"}`, env),
					fmt.Sprint(src.ID), secretsAdminID)
				assert.Equal(t, http.StatusBadRequest, w.Code, "copy into %s: %s", name, w.Body.String())
			}

			// A name that breaks the configured naming policy is the client's
			// error: CreateSecret rejects it and the copy answers 400, not 500.
			require.NoError(t, h.coreService.SetSecretNamePolicy(core.SecretNamePolicy{Enabled: true, Pattern: "^[a-z-]+$"}))
			w = secretsDo(h.CopySecret, http.MethodPost, fmt.Sprintf(`{"environment_id":%d,"name":"BAD_NAME_1"}`, fx.envID),
				fmt.Sprint(src.ID), secretsAdminID)
			assert.Equal(t, http.StatusBadRequest, w.Code, "copy with a name outside the policy: %s", w.Body.String())
		})
	}
}
