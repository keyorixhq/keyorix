// secrets_read_error_class_locale_test.go — the secret read-metadata routes
// (access list, history, stats, audit trail, access-log export, read summary,
// risk) answer from the KIND of failure, not from the language of its message
// (ERRLOSS-SENTINELS-1 task 3.6, same class as #2461): missing secret -> 404,
// refusal -> 403, bad export format -> 400, storage failure -> 5xx, under the
// shipped English text and under a translated locale. Like the other locale
// tests these flip the process-global localizer and are deliberately NOT
// t.Parallel().
package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func secretsReadRoutes() []secretsRoute {
	get := func(name string, fn func(h *SecretHandler) http.HandlerFunc) secretsRoute {
		return secretsRoute{name, "GetSecret", func(h *SecretHandler, id string, a uint) *httptest.ResponseRecorder {
			return secretsDo(fn(h), http.MethodGet, "", id, a)
		}}
	}
	return []secretsRoute{
		get("ListAccessors", func(h *SecretHandler) http.HandlerFunc { return h.ListAccessors }),
		get("AccessHistory", func(h *SecretHandler) http.HandlerFunc { return h.AccessHistory }),
		get("GetSecretAccessStats", func(h *SecretHandler) http.HandlerFunc { return h.GetSecretAccessStats }),
		get("AuditTrail", func(h *SecretHandler) http.HandlerFunc { return h.AuditTrail }),
		get("ExportAccessLog", func(h *SecretHandler) http.HandlerFunc { return h.ExportAccessLog }),
		get("GetSecretReadSummary", func(h *SecretHandler) http.HandlerFunc { return h.GetSecretReadSummary }),
		get("GetSecretRisk", func(h *SecretHandler) http.HandlerFunc { return h.GetSecretRisk }),
	}
}

func TestSecretReadRoutes_MissingSecretIs404InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range secretsReadRoutes() {
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				h, _, _ := newSecretsHandlerWithDB(t, lang)
				w := rt.call(h, secretsMissingID, secretsAdminID)
				assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// A caller with no grant on the secret is refused 403. Risk has no per-user gate
// in core (the router's scoped permission is the gate), so it is not in this set.
func TestSecretReadRoutes_RefusalIs403InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range secretsReadRoutes() {
			if rt.name == "GetSecretRisk" {
				continue
			}
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				h, _, fx := newSecretsHandlerWithDB(t, lang)
				w := rt.call(h, fx.id(), secretsPlainID)
				assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// A storage failure on the secret lookup is a 5xx in every locale and never
// reads as "no such secret" or leaks the driver text.
func TestSecretReadRoutes_StorageFaultIs5xxInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range secretsReadRoutes() {
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

// An export format core does not know is a 400.
func TestExportAccessLog_UnsupportedFormatIs400InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang, func(t *testing.T) {
			h, _, fx := newSecretsHandlerWithDB(t, lang)
			req := httptest.NewRequest(http.MethodGet, "/?format=xml", nil)
			req = withUserCtxID(req, secretsAdminID, "actor")
			req = withChiParam(req, "id", fx.id())
			w := httptest.NewRecorder()
			h.ExportAccessLog(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
		})
	}
}
