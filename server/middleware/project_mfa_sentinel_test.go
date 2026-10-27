// project_mfa_sentinel_test.go — ERRLOSS-MFA-1: the per-project MFA gate
// classifies a GetProject failure by sentinel (storage.IsProjectNotFound),
// never by the error's text.
//
// ProjectMFABlocked used to let a request through whenever the lookup error's
// text contained "not found". A storage failure that merely says "not found"
// (a driver/replica message, a wrapped lower-layer error) is not a verdict
// that the project is absent, so it must deny like any other lookup failure.
// A genuinely missing project still passes the gate so the handler's own
// existence check answers (the #G17 carve-out, unchanged).
//
// The fault is injected with internal/faultstorage on GetProject over a real
// LocalStorage → core path. Each case also runs under the ru locale (same
// switch as handlers' break_glass_review_locale_test.go, #2461): not
// t.Parallel() because the localizer is process-global.
package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// lookalikeNotFoundErr reads like an absence but is a storage failure: it
// carries the words "not found" and is NOT storage.ErrProjectNotFound.
var lookalikeNotFoundErr = errors.New("failed to get project: replica 3: relation snapshot not found")

func pmsLocales(t *testing.T, fn func(t *testing.T)) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	for _, lang := range []string{"en", "ru"} {
		t.Run(lang, func(t *testing.T) {
			loc := i18n.GetLocalizer()
			loc.SetLanguage(lang)
			t.Cleanup(func() { loc.SetLanguage("en") })
			if lang == "ru" {
				require.NotContains(t, i18n.T("ErrorNotFound", nil), "not found",
					"the ru locale must not render ErrorNotFound in English, or this run proves nothing")
			}
			fn(t)
		})
	}
}

// newPMSStorage seeds project 1 (RequireMFA) over a real LocalStorage.
func newPMSStorage(t *testing.T) corestorage.Storage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.AuditEvent{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "needs-mfa", RequireMFA: true}).Error)
	return store.NewLocalStorage(db)
}

// servePMS runs the scoped-permission chokepoint (permission already granted)
// in front of a handler that answers 404, standing in for the handler's own
// existence check.
func servePMS(cs *core.KeyorixCore, projectID uint) (code int, reached bool) {
	sessionNoMFA := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: false}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNotFound)
	})
	w := httptest.NewRecorder()
	finishScopedPermissionRequest(next, w, reqWithUser(sessionNoMFA), cs, core.Scope{ProjectID: projectID}, true, nil, "denied")
	return w.Code, reached
}

// TestProjectMFABlocked_LookalikeNotFoundErrorDenies is the red-pre-fix case.
func TestProjectMFABlocked_LookalikeNotFoundErrorDenies(t *testing.T) {
	pmsLocales(t, func(t *testing.T) {
		fs := faultstorage.NewFaultyStorage(newPMSStorage(t), &faultstorage.FaultSpec{
			Method: "GetProject", NthCall: 1, Kind: faultstorage.KindError, Err: lookalikeNotFoundErr,
		})
		cs := core.NewKeyorixCore(fs)
		code, reached := servePMS(cs, 1)
		require.True(t, fs.Fired(), "precondition: the MFA lookup must hit the injected fault")
		assert.False(t, reached, "a storage error that only says \"not found\" must not let the request through")
		assert.Equal(t, http.StatusForbidden, code)

		fs.Arm(&faultstorage.FaultSpec{Method: "GetProject", NthCall: 1, Kind: faultstorage.KindError, Err: lookalikeNotFoundErr})
		sessionNoMFA := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: false}
		assert.True(t, ProjectsMFABlocked(reqWithUser(sessionNoMFA), cs, []uint{1}),
			"the aggregate gate must deny on the same lookalike error")
	})
}

// TestProjectMFABlocked_MissingProjectPassesToHandler404: a genuinely missing
// project is not an MFA question; the handler's own 404 answers.
func TestProjectMFABlocked_MissingProjectPassesToHandler404(t *testing.T) {
	pmsLocales(t, func(t *testing.T) {
		cs := core.NewKeyorixCore(newPMSStorage(t))
		code, reached := servePMS(cs, 999)
		assert.True(t, reached, "a nonexistent project must reach the handler")
		assert.Equal(t, http.StatusNotFound, code)

		code, reached = servePMS(cs, 1)
		assert.False(t, reached, "control: the MFA-required project still denies a session without MFA")
		assert.Equal(t, http.StatusForbidden, code)
	})
}
