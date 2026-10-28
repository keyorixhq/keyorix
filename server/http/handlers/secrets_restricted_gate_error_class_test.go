// secrets_restricted_gate_error_class_test.go — a restricted-classification gate
// refusal is a 403 in every locale on the routes that run the gate, never the 500
// default (#3796 review finding 1): the gate refusals match core.ErrPermissionDenied.
// Like the other locale tests these flip the process-global localizer and are
// deliberately NOT t.Parallel().
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newRestrictedGateHandler is newSecretsHandlerWithDB with the fixture secret
// restricted and owned by the plain user, who also holds secrets.read (but not
// secrets.read.restricted) at the secret's project: the plain user passes the read
// check, and with gateOn the restricted-read permission gate then refuses.
func newRestrictedGateHandler(t *testing.T, lang string, gateOn bool) (*SecretHandler, secretsFixture) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	withErrorTextLocale(t, lang)
	cs.SetClassificationRestrictedRequiresPermission(gateOn)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	fx := seedSecretsFixture(t, db)
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", fx.secretID).
		Updates(map[string]any{"owner_id": secretsPlainID, "classification": core.ClassificationRestricted}).Error)
	perm := &models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}
	require.NoError(t, db.Create(perm).Error)
	role := &models.Role{Name: "ec-reader", NameFolded: "ec-reader"}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: secretsPlainID, RoleID: role.ID, ProjectID: fx.projectID}).Error)
	return h, fx
}

type restrictedGateRoute struct {
	name string
	call func(h *SecretHandler, fx secretsFixture) *httptest.ResponseRecorder
	// ungated is the status the same reader gets with the gate off: proof that the
	// 403 below comes from the gate and not from the read check.
	ungated int
}

func restrictedGateRoutes() []restrictedGateRoute {
	return []restrictedGateRoute{
		// The fixture secret has no version, so an ungated inspection is a 404.
		{"GetSecretCertificate", func(h *SecretHandler, fx secretsFixture) *httptest.ResponseRecorder {
			return graphDo(h.GetSecretCertificate, http.MethodGet, "", map[string]string{"id": fx.id()}, secretsPlainID)
		}, http.StatusNotFound},
		// Ungated, the value read gets past every guard and fails on the missing
		// version (this route's 500 default); gated, it never gets that far.
		{"GetSecret?include_value", func(h *SecretHandler, fx secretsFixture) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodGet, "/?include_value=true", strings.NewReader(""))
			req = withUserCtxID(req, secretsPlainID, "actor")
			req = withChiParam(req, "id", fx.id())
			w := httptest.NewRecorder()
			h.GetSecret(w, req)
			return w
		}, http.StatusInternalServerError},
	}
}

func TestRestrictedGateRefusal_Is403InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		for _, rt := range restrictedGateRoutes() {
			t.Run(lang+"/"+rt.name+"/gate-off", func(t *testing.T) {
				h, fx := newRestrictedGateHandler(t, lang, false)
				w := rt.call(h, fx)
				require.Equal(t, rt.ungated, w.Code, "body: %s", w.Body.String())
			})
			t.Run(lang+"/"+rt.name+"/gate-on", func(t *testing.T) {
				h, fx := newRestrictedGateHandler(t, lang, true)
				w := rt.call(h, fx)
				assert.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
			})
		}
	}
}
