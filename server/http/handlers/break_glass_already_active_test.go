// break_glass_already_active_test.go — a second "Request emergency access" while
// one is active is a conflict with the caller's current state, not an internal
// error. Core refuses it with a clean validation message; the handler used to
// fall through to its default arm and answer 500 "an internal error occurred",
// so the UI showed "Something went wrong" instead of the reason.
//
// Like the other locale tests in this package these flip the process-global
// localizer and are deliberately NOT t.Parallel().
package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActivateBreakGlass_SecondActivationWhileActiveIs409(t *testing.T) {
	for _, lang := range []string{"en", pseudoLocale} {
		t.Run(lang, func(t *testing.T) {
			if lang == pseudoLocale {
				withTranslatedErrorMessages(t)
			}
			cs, db := freshCoreS12WithAdmin(t)
			// User 1 (the withUserCtx caller) must be a member of project 1 and the
			// emergency role must exist, so the request reaches the "already active"
			// check rather than an earlier refusal.
			devRole := &models.Role{Name: "project_developer", NameFolded: "project_developer", Description: "Developer"}
			require.NoError(t, db.Create(devRole).Error)
			pid := uint(1)
			require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: devRole.ID, ProjectID: pid}).Error)
			cs.SetBreakGlassPolicy(core.BreakGlassPolicy{
				Enabled: true, EmergencyRole: "project_developer", DefaultTTL: time.Hour, MaxTTL: time.Hour,
			})
			seedBreakGlassActivationS13(t, db, 1, "active")

			w := doActivateBreakGlass(t, NewCatalogHandler(cs), "1", `{"justification":"prod incident, db is down"}`)

			assert.Equal(t, http.StatusConflict, w.Code, "body: %s", w.Body.String())
			var body struct {
				Message string `json:"message"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), w.Body.String())
			assert.Contains(t, body.Message, "you already have an active break-glass grant",
				"the UI shows this message, so the 4xx must carry core's reason, not the generic 500 text")
		})
	}
}
