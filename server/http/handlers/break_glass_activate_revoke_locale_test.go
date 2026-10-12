// break_glass_activate_revoke_locale_test.go — ActivateBreakGlass and
// RevokeBreakGlass must map refusals to the same HTTP status in every locale
// (#2905, the follow-up #2461 left for these two routes).
//
// Both handlers classified core's error with strings.Contains over err.Error(),
// which embeds i18n.T(...) output ("permission denied", "Resource not found").
// Under ru that text is translated, the arms stop matching, and a deliberate
// 403/404 falls through to 500. Core now returns sentinel errors and the
// handlers use errors.Is, so the status is a function of the failure, not of
// the deployment's language.
//
// Like break_glass_review_locale_test.go these run the real handler over the
// real core and storage, flip the process-global localizer, and are therefore
// deliberately NOT t.Parallel().
package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pseudoLocale is a language no shipped locale provides (en, de, es, fr, ru), so
// the translation it carries can never collide with a real one.
const pseudoLocale = "it"

// withTranslatedErrorMessages switches the process-global localizer to a locale
// that translates EVERY error prefix core puts in front of a break-glass
// refusal, including ErrorPermissionDenied, which no shipped locale translates
// (they all leave it as "permission denied"). That is the point: the handler's
// status must not change when a deployment, or a future translation commit,
// changes this wording.
func withTranslatedErrorMessages(t *testing.T) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	restore, err := i18n.RegisterPseudoLocaleForTesting(pseudoLocale, map[string]string{
		"ErrorPermissionDenied": "доступ запрещён",
		"ErrorValidation":       "ошибка проверки",
		"ErrorNotFound":         "ресурс отсутствует",
		"ErrorRetrievalFailed":  "сбой получения данных",
		"ErrorStorageFailed":    "сбой хранилища",
	})
	require.NoError(t, err)
	t.Cleanup(restore)
	// Floor: if the override ever stopped applying, the locale-flipped half of
	// these tests would silently run in English and prove nothing.
	require.Equal(t, "доступ запрещён", i18n.T("ErrorPermissionDenied", nil))
	require.NotContains(t, i18n.T("ErrorNotFound", nil), "not found")
}

func doActivateBreakGlass(t *testing.T, h *CatalogHandler, projectID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)),
		map[string]string{"id": projectID}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ActivateBreakGlass(w, req)
	return w
}

func doRevokeBreakGlass(t *testing.T, h *CatalogHandler, projectID, activationID string) *httptest.ResponseRecorder {
	t.Helper()
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", nil),
		map[string]string{"id": projectID, "activationId": activationID}))
	w := httptest.NewRecorder()
	h.RevokeBreakGlass(w, req)
	return w
}

// TestActivateBreakGlass_RefusalStatusesAreLocaleIndependent runs every refusal
// the handler maps, once per locale, and requires the same status in both.
func TestActivateBreakGlass_RefusalStatusesAreLocaleIndependent(t *testing.T) {
	cases := []struct {
		name      string
		enabled   bool
		projectID string // "" = 1
		body      string
		want      int
	}{
		// core: ErrorPermissionDenied and nothing else -- once translated it
		// contains neither "permission denied" nor "not enabled".
		{name: "feature disabled", enabled: false,
			body: `{"justification":"prod incident, db is down"}`, want: http.StatusForbidden},
		// core: ErrorPermissionDenied + english detail; user 1 holds only a
		// global admin grant, which is not project membership.
		{name: "not a project member", enabled: true,
			body: `{"justification":"prod incident, db is down"}`, want: http.StatusForbidden},
		{name: "justification too short", enabled: true,
			body: `{"justification":"short"}`, want: http.StatusBadRequest},
		{name: "project id zero", enabled: true, projectID: "0",
			body: `{"justification":"prod incident, db is down"}`, want: http.StatusBadRequest},
	}
	for _, lang := range []string{"en", pseudoLocale} {
		for _, tc := range cases {
			t.Run(lang+"/"+tc.name, func(t *testing.T) {
				if lang == pseudoLocale {
					withTranslatedErrorMessages(t)
				}
				cs, _ := freshCoreS12WithAdmin(t)
				cs.SetBreakGlassPolicy(core.BreakGlassPolicy{
					Enabled: tc.enabled, EmergencyRole: "project_developer", DefaultTTL: time.Hour, MaxTTL: time.Hour,
				})
				projectID := "1"
				if tc.projectID != "" {
					projectID = tc.projectID
				}
				w := doActivateBreakGlass(t, NewCatalogHandler(cs), projectID, tc.body)
				assert.Equal(t, tc.want, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// TestRevokeBreakGlass_RefusalStatusesAreLocaleIndependent is the Revoke twin.
func TestRevokeBreakGlass_RefusalStatusesAreLocaleIndependent(t *testing.T) {
	cases := []struct {
		name       string
		projectID  string
		seedState  string
		activation string // "" = the seeded one
		want       int
	}{
		// core: ErrorNotFound + the storage error; the text match was the only
		// thing classifying it.
		{name: "no such activation", projectID: "1", seedState: "active", activation: "999999", want: http.StatusNotFound},
		// core: ErrorNotFound and nothing else.
		{name: "activation belongs to another project", projectID: "2", seedState: "active", want: http.StatusNotFound},
		{name: "already revoked", projectID: "1", seedState: "revoked", want: http.StatusBadRequest},
		{name: "project id zero", projectID: "0", seedState: "active", want: http.StatusBadRequest},
		{name: "revokes an active one", projectID: "1", seedState: "active", want: http.StatusOK},
	}
	for _, lang := range []string{"en", pseudoLocale} {
		for _, tc := range cases {
			t.Run(lang+"/"+tc.name, func(t *testing.T) {
				if lang == pseudoLocale {
					withTranslatedErrorMessages(t)
				}
				cs, db := freshCoreS12WithAdmin(t)
				id := fmt.Sprint(seedBreakGlassActivationS13(t, db, 2, tc.seedState))
				if tc.activation != "" {
					id = tc.activation
				}
				w := doRevokeBreakGlass(t, NewCatalogHandler(cs), tc.projectID, id)
				assert.Equal(t, tc.want, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}

// TestRevokeBreakGlass_StorageFailureIs500NotNotFound: a genuine retrieval
// FAILURE must not be laundered into a 404. Core wraps whatever the lookup
// returned behind the i18n "Resource not found" prefix, and the old text match
// turned the prefix into a 404 for every error -- including a dead database.
// Red in English, so it also proves the sentinel is what decides.
func TestRevokeBreakGlass_StorageFailureIs500NotNotFound(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	id := fmt.Sprint(seedBreakGlassActivationS13(t, db, 2, "active"))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	w := doRevokeBreakGlass(t, NewCatalogHandler(cs), "1", id)
	assert.Equal(t, http.StatusInternalServerError, w.Code, "body: %s", w.Body.String())
}
