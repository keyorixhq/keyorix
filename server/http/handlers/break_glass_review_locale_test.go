// break_glass_review_locale_test.go — ReviewBreakGlass's status mapping must
// not depend on the deployment's configured LOCALE (#2461 round 2).
//
// The handler used to classify refusals with strings.Contains over
// err.Error(), and those messages are built from i18n.T(...), whose output is
// translated. The project-ID-mismatch refusal is the clearest case: core
// returns i18n.T("ErrorNotFound") and nothing else, so under ru that error
// reads "Ресурс не найден" — which does not contain the English words "not
// found" — and the 404 arm stopped matching, dropping a deliberate 404 through
// to the default 500. The fix maps by sentinel (errors.Is) instead.
//
// These tests run the real handler over the real core and storage, flipping
// the global localizer the same way handlers_s36_test.go's
// TestDiffSecretVersions_InternalError_S36 already does; they are deliberately
// NOT t.Parallel() because that localizer is process-global.
package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withRussianLocale switches the process-global localizer to ru for the
// duration of the test and restores en afterwards.
func withRussianLocale(t *testing.T) {
	t.Helper()
	// Idempotent (sync.Once): a no-op when an earlier test already initialized
	// the bundle, and required when this test runs first (-run filtered).
	require.NoError(t, i18n.InitializeForTesting())
	loc := i18n.GetLocalizer()
	loc.SetLanguage("ru")
	t.Cleanup(func() { loc.SetLanguage("en") })
	// Floor: if ErrorNotFound ever stopped being translated, these tests would
	// pass for the wrong reason (they would still be running in English).
	require.NotContains(t, i18n.T("ErrorNotFound", nil), "not found",
		"the ru locale must not render ErrorNotFound in English, or this test proves nothing")
}

// TestReviewBreakGlass_ProjectMismatchIs404UnderNonEnglishLocale is the
// red-pre-fix case: an activation that exists but belongs to a DIFFERENT
// project must be 404 (never disclosing that the ID exists elsewhere, and
// never reading as a server fault), in every locale.
func TestReviewBreakGlass_ProjectMismatchIs404UnderNonEnglishLocale(t *testing.T) {
	withRussianLocale(t)
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	// seedBreakGlassActivationS13 inserts under ProjectID 1; ask for it under 2.
	id := seedBreakGlassActivationS13(t, db, 2, "revoked")

	body := strings.NewReader(`{"note":"reviewing via the wrong project id"}`)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", body),
		map[string]string{"id": "2", "activationId": fmt.Sprint(id)}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ReviewBreakGlass(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
}

// TestReviewBreakGlass_RefusalStatusesSurviveANonEnglishLocale pins the rest
// of the mapping in the same locale, so a future refusal added by text match
// is caught here rather than in production.
func TestReviewBreakGlass_RefusalStatusesSurviveANonEnglishLocale(t *testing.T) {
	withRussianLocale(t)
	longNote := strings.Repeat("x", 4096)
	cases := []struct {
		name       string
		projectID  string
		seedUserID uint
		seedState  string
		note       string
		want       int
	}{
		{name: "no such activation", projectID: "1", seedUserID: 2, seedState: "revoked",
			note: "a perfectly good review note", want: http.StatusNotFound},
		{name: "self review", projectID: "1", seedUserID: 1, seedState: "revoked",
			note: "I reviewed my own emergency access", want: http.StatusForbidden},
		{name: "still active", projectID: "1", seedUserID: 2, seedState: "active",
			note: "reviewing while the grant is still live", want: http.StatusBadRequest},
		{name: "note too short", projectID: "1", seedUserID: 2, seedState: "revoked",
			note: "ok", want: http.StatusBadRequest},
		{name: "note too long", projectID: "1", seedUserID: 2, seedState: "revoked",
			note: longNote, want: http.StatusBadRequest},
		{name: "project id zero", projectID: "0", seedUserID: 2, seedState: "revoked",
			note: "a perfectly good review note", want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs, db := freshCoreS12WithAdmin(t)
			h := NewCatalogHandler(cs)
			id := seedBreakGlassActivationS13(t, db, tc.seedUserID, tc.seedState)
			activationID := fmt.Sprint(id)
			if tc.name == "no such activation" {
				activationID = "999999"
			}

			body := strings.NewReader(fmt.Sprintf(`{"note":%q}`, tc.note))
			req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", body),
				map[string]string{"id": tc.projectID, "activationId": activationID}))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ReviewBreakGlass(w, req)
			assert.Equal(t, tc.want, w.Code, "body: %s", w.Body.String())
		})
	}
}

// TestReviewBreakGlass_StorageFailureIs500NotNotFound is the other half of
// mapping by sentinel: a genuine retrieval FAILURE must not be laundered into
// a 404. GetBreakGlassActivation already separates gorm.ErrRecordNotFound
// (storage.ErrBreakGlassNotFound) from everything else — local_break_glass.go's
// own comment records the proxy path having had exactly this bug — but the old
// text match caught both, because the i18n "Resource not found" prefix core
// put in front of the storage error matched "not found" either way.
func TestReviewBreakGlass_StorageFailureIs500NotNotFound(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	id := seedBreakGlassActivationS13(t, db, 2, "revoked")

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	body := strings.NewReader(`{"note":"reviewing against a dead database"}`)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", body),
		map[string]string{"id": "1", "activationId": fmt.Sprint(id)}))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ReviewBreakGlass(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code, "body: %s", w.Body.String())
}
