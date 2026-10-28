// users_error_class_locale_test.go — the user routes must map "no such user"
// to 404 and a storage failure to 5xx in every locale (ERRLOSS-SENTINELS-1,
// same class as #2461/#2905).
//
// These handlers used to classify core's error with
// strings.Contains(err.Error(), "not found"). The text embeds i18n output, so
// under a translated locale a real 404 became a 500. They now use errors.Is on
// storage.ErrUserNotFound. Like the break-glass locale tests these flip the
// process-global localizer and are deliberately NOT t.Parallel().
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

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const missingUserID = "99999"

type userRoute struct {
	name string
	// fault is the storage method whose failure this route must surface as 5xx.
	fault string
	call  func(uh *UserHandler, id string) *httptest.ResponseRecorder
}

func userByID(method string, h func(uh *UserHandler) http.HandlerFunc, body string) func(uh *UserHandler, id string) *httptest.ResponseRecorder {
	return func(uh *UserHandler, id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/users/"+id, strings.NewReader(body))
		req = withChiParam(withUserCtx(req), "id", id)
		w := httptest.NewRecorder()
		h(uh)(w, req)
		return w
	}
}

func userByQuery(query string, h func(uh *UserHandler) http.HandlerFunc) func(uh *UserHandler, id string) *httptest.ResponseRecorder {
	return func(uh *UserHandler, _ string) *httptest.ResponseRecorder {
		req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/lookup?"+query, nil))
		w := httptest.NewRecorder()
		h(uh)(w, req)
		return w
	}
}

func userRoutes() []userRoute {
	return []userRoute{
		{"GetUser", "GetUser", userByID(http.MethodGet, func(uh *UserHandler) http.HandlerFunc { return uh.GetUser }, "")},
		{"GetUserByEmail", "GetUserByEmail", userByQuery("email=nobody@example.com", func(uh *UserHandler) http.HandlerFunc { return uh.GetUserByEmail })},
		{"GetUserByUsername", "GetUserByUsername", userByQuery("username=nobody", func(uh *UserHandler) http.HandlerFunc { return uh.GetUserByUsername })},
		{"GetUserByExternalID", "GetUserByExternalID", userByQuery("external_id=nobody", func(uh *UserHandler) http.HandlerFunc { return uh.GetUserByExternalID })},
		{"UpdateUser", "GetUser", userByID(http.MethodPut, func(uh *UserHandler) http.HandlerFunc { return uh.UpdateUser }, `{"display_name":"x"}`)},
		{"DeleteUser", "GetUser", userByID(http.MethodDelete, func(uh *UserHandler) http.HandlerFunc { return uh.DeleteUser }, "")},
		{"RestoreUser", "", userByID(http.MethodPost, func(uh *UserHandler) http.HandlerFunc { return uh.RestoreUser }, "")},
		{"UnlockUser", "GetUser", userByID(http.MethodPost, func(uh *UserHandler) http.HandlerFunc { return uh.UnlockUser }, "")},
		{"SuspendUser", "SetAccountState", userByID(http.MethodPost, func(uh *UserHandler) http.HandlerFunc { return uh.SuspendUser }, "")},
		{"ReactivateUser", "SetAccountState", userByID(http.MethodPost, func(uh *UserHandler) http.HandlerFunc { return uh.ReactivateUser }, "")},
		{"RequirePasswordReset", "SetAccountState", userByID(http.MethodPost, func(uh *UserHandler) http.HandlerFunc { return uh.RequirePasswordReset }, "")},
		{"RevokeSessions", "GetUser", userByID(http.MethodPost, func(uh *UserHandler) http.HandlerFunc { return uh.RevokeSessions }, "")},
		{"ResendSetupLink", "GetUser", userByID(http.MethodPost, func(uh *UserHandler) http.HandlerFunc { return uh.ResendSetupLink }, "")},
	}
}

func TestUserRoutes_MissingUserIs404InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range userRoutes() {
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				withErrorTextLocale(t, lang)
				uh, _, _ := freshUserHandlerS12(t)
				w := rt.call(uh, missingUserID)
				assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// A storage failure on the lookup is a 5xx in every locale: never a 404 the
// admin would read as "no such user", and never the raw driver text.
func TestUserRoutes_StorageFaultIs5xxInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range userRoutes() {
			if rt.fault == "" {
				continue
			}
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				withErrorTextLocale(t, lang)
				_, cs, db := freshUserHandlerS12(t)
				// A REAL target: with the missing id a genuine not-found from another
				// call could masquerade as the fault's result.
				target := strconv.FormatUint(uint64(newReissueTarget(t, cs, "fault-target")), 10)
				faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
					Method: rt.fault, NthCall: 1, Kind: faultstorage.KindError,
					Err: errors.New("injected: " + rt.fault),
				})
				fuh, err := NewUserHandler(core.NewKeyorixCore(faulty))
				require.NoError(t, err)

				w := rt.call(fuh, target)
				require.True(t, faulty.Fired(), "%s must reach storage method %s", rt.name, rt.fault)
				assert.GreaterOrEqual(t, w.Code, 500, "body: %s", w.Body.String())
				assert.NotContains(t, w.Body.String(), "injected", "the storage error text never reaches the client")
			})
		}
	}
}

func startImpersonation(t *testing.T, h *ImpersonationHandler, targetID string) *httptest.ResponseRecorder {
	t.Helper()
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/admin/impersonate",
		strings.NewReader(`{"user_id":`+targetID+`}`)))
	w := httptest.NewRecorder()
	h.Start(w, req)
	return w
}

// StartImpersonation reported every GetUser failure on the target as
// "target user not found", which the handler read as a 404. A missing target is
// still a 404 in every locale; a storage failure is a 5xx.
func TestImpersonationStart_TargetLookupClassifiedByFailureInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang+"/missing target", func(t *testing.T) {
			withErrorTextLocale(t, lang)
			cs, _ := freshCoreS12WithAdmin(t)
			w := startImpersonation(t, NewImpersonationHandler(cs, false), missingUserID)
			assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
		})
		t.Run(lang+"/storage fault", func(t *testing.T) {
			withErrorTextLocale(t, lang)
			cs, db := freshCoreS12WithAdmin(t)
			target := strconv.FormatUint(uint64(newReissueTarget(t, cs, "imp-fault-target")), 10)
			// GetUser call 1 is the acting admin, call 2 the target.
			faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
				Method: "GetUser", NthCall: 2, Kind: faultstorage.KindError,
				Err: errors.New("injected: GetUser"),
			})
			w := startImpersonation(t, NewImpersonationHandler(core.NewKeyorixCore(faulty), false), target)
			require.True(t, faulty.Fired(), "the target lookup must have been reached")
			assert.GreaterOrEqual(t, w.Code, 500, "body: %s", w.Body.String())
			assert.NotContains(t, w.Body.String(), "injected")
		})
	}
}
