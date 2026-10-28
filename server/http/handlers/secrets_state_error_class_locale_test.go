// secrets_state_error_class_locale_test.go — the secret suspend, resume,
// ownership-transfer, ownership-history, bulk-reassign and render routes answer
// from the KIND of failure, not from the language of its message
// (ERRLOSS-SENTINELS-1 task 3.5, same class as #2461): not-found -> 404,
// refusal -> 403, invalid input -> 400, storage failure -> 5xx, under the
// shipped English text and under a translated locale. Like the other locale
// tests these flip the process-global localizer and are deliberately NOT
// t.Parallel().
package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

type secretsStateRoute struct {
	name string
	// fault is the storage method whose failure this route must surface as 5xx.
	fault string
	call  func(h *SecretHandler, fx secretsFixture, id string, actor uint) *httptest.ResponseRecorder
}

func secretsStateRoutes() []secretsStateRoute {
	return []secretsStateRoute{
		{"SuspendSecret", "GetSecret", func(h *SecretHandler, _ secretsFixture, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.SuspendSecret, http.MethodPost, `{"reason":"test"}`, id, a)
		}},
		{"ResumeSecret", "GetSecret", func(h *SecretHandler, _ secretsFixture, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.ResumeSecret, http.MethodPost, "", id, a)
		}},
		{"TransferOwnership", "GetSecret", func(h *SecretHandler, _ secretsFixture, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.TransferOwnership, http.MethodPost, fmt.Sprintf(`{"new_owner_id":%d}`, secretsPlainID), id, a)
		}},
		{"OwnershipHistory", "GetSecret", func(h *SecretHandler, _ secretsFixture, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(h.OwnershipHistory, http.MethodGet, "", id, a)
		}},
	}
}

func TestSecretStateRoutes_MissingSecretIs404InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range secretsStateRoutes() {
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				h, _, fx := newSecretsHandlerWithDB(t, lang)
				w := rt.call(h, fx, secretsMissingID, secretsAdminID)
				assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// A storage failure on the secret lookup is a 5xx in every locale: core used to
// wrap the driver error under the translated not-found text, which the handler
// then read as "no such secret".
func TestSecretStateRoutes_StorageFaultIs5xxInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range secretsStateRoutes() {
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				_, db, fx := newSecretsHandlerWithDB(t, lang)
				faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
					Method: rt.fault, NthCall: 1, Kind: faultstorage.KindError,
					Err: errors.New("injected: " + rt.fault),
				})
				fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
				require.NoError(t, err)

				w := rt.call(fh, fx, fx.id(), secretsAdminID)
				require.True(t, faulty.Fired(), "%s must reach storage method %s", rt.name, rt.fault)
				assert.GreaterOrEqual(t, w.Code, 500, "body: %s", w.Body.String())
				assert.NotContains(t, w.Body.String(), "injected", "the storage error text never reaches the client")
			})
		}
	}
}

// Ownership: a caller who is not the owner is refused 403, a transfer to the
// current owner is 400, a new owner that does not exist is 404; history of a
// secret the caller cannot read is 403.
func TestSecretOwnershipRoutes_RefusalAndInvalidInputInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang, func(t *testing.T) {
			h, _, fx := newSecretsHandlerWithDB(t, lang)

			w := secretsDo(h.TransferOwnership, http.MethodPost, fmt.Sprintf(`{"new_owner_id":%d}`, secretsPlainID), fx.id(), secretsPlainID)
			assert.Equal(t, http.StatusForbidden, w.Code, "transfer by a non-owner: %s", w.Body.String())

			w = secretsDo(h.TransferOwnership, http.MethodPost, fmt.Sprintf(`{"new_owner_id":%d}`, secretsAdminID), fx.id(), secretsAdminID)
			assert.Equal(t, http.StatusBadRequest, w.Code, "transfer to the current owner: %s", w.Body.String())

			w = secretsDo(h.TransferOwnership, http.MethodPost, `{"new_owner_id":98765}`, fx.id(), secretsAdminID)
			assert.Equal(t, http.StatusNotFound, w.Code, "transfer to a missing user: %s", w.Body.String())

			w = secretsDo(h.OwnershipHistory, http.MethodGet, "", fx.id(), secretsPlainID)
			assert.Equal(t, http.StatusForbidden, w.Code, "history for a caller without access: %s", w.Body.String())
		})
	}
}

// Bulk reassignment: no roles.assign -> 403, from == to -> 400, a new owner that
// does not exist -> 400, a storage failure -> 5xx.
func TestReassignOwner_ErrorKindsInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang, func(t *testing.T) {
			h, db, fx := newSecretsHandlerWithDB(t, lang)
			call := func(actor uint, from, to uint) *httptest.ResponseRecorder {
				return secretsDo(h.ReassignOwner, http.MethodPost,
					fmt.Sprintf(`{"from_owner_id":%d,"to_owner_id":%d}`, from, to), fmt.Sprint(fx.projectID), actor)
			}
			assert.Equal(t, http.StatusForbidden, call(secretsPlainID, secretsAdminID, secretsPlainID).Code, "no roles.assign")
			assert.Equal(t, http.StatusBadRequest, call(secretsAdminID, secretsPlainID, secretsPlainID).Code, "from == to")
			w := call(secretsAdminID, secretsAdminID, 98765)
			assert.Equal(t, http.StatusBadRequest, w.Code, "missing new owner: %s", w.Body.String())

			faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
				Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected: GetUser"),
			})
			fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
			require.NoError(t, err)
			w = secretsDo(fh.ReassignOwner, http.MethodPost,
				fmt.Sprintf(`{"from_owner_id":%d,"to_owner_id":%d}`, secretsAdminID, secretsPlainID), fmt.Sprint(fx.projectID), secretsAdminID)
			require.True(t, faulty.Fired(), "the reassignment must reach GetUser")
			assert.GreaterOrEqual(t, w.Code, 500, "storage failure on the new owner lookup: %s", w.Body.String())
		})
	}
}

// Render: a template the renderer rejects is 400; a referenced secret the caller
// cannot read is 403 (same body as a missing one); a storage failure reading the
// referenced secret's latest version is a 5xx, not "not found".
func TestRenderTemplate_ErrorKindsInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang, func(t *testing.T) {
			h, db, fx := newSecretsHandlerWithDB(t, lang)
			render := func(h *SecretHandler, actor uint, tmpl string) *httptest.ResponseRecorder {
				return secretsDo(h.RenderTemplate, http.MethodPost, fmt.Sprintf(`{"template":%q}`, tmpl), fmt.Sprint(fx.projectID), actor)
			}
			ref := "${secret:ec-env/ec-secret}"

			w := render(h, secretsAdminID, "x ${secret:unterminated")
			assert.Equal(t, http.StatusBadRequest, w.Code, "unterminated placeholder: %s", w.Body.String())
			w = render(h, secretsAdminID, "${secret:no-slash}")
			assert.Equal(t, http.StatusBadRequest, w.Code, "reference without an environment: %s", w.Body.String())

			w = render(h, secretsPlainID, ref)
			assert.Equal(t, http.StatusForbidden, w.Code, "caller without read access: %s", w.Body.String())

			faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
				Method: "GetLatestSecretVersion", NthCall: 1, Kind: faultstorage.KindError,
				Err: errors.New("injected: GetLatestSecretVersion"),
			})
			fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
			require.NoError(t, err)
			w = render(fh, secretsAdminID, ref)
			require.True(t, faulty.Fired(), "the render must reach GetLatestSecretVersion")
			assert.GreaterOrEqual(t, w.Code, 500, "storage failure on the latest version: %s", w.Body.String())
			assert.NotContains(t, w.Body.String(), "injected")
		})
	}
}
