package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestSCIM_CreateRefusesSSONamespaceExternalID: a SCIM create may not mint an
// account in the "sso:" external_id namespace reserved for SSO-bound identities
// (#3418). The refusal is a 400 that names the problem, not the generic message.
func TestSCIM_CreateRefusesSSONamespaceExternalID(t *testing.T) {
	h, db := setupSCIMTest(t)
	body := `{"userName":"eve@corp.com","externalId":"sso:okta:sub-eve","active":true}`
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(body))))
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `reserved \"sso:\" prefix`)
	var n int64
	require.NoError(t, db.Model(&models.User{}).Count(&n).Error)
	assert.Zero(t, n)
}
