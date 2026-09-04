// webauthn_proxy_1622_authz_test.go — #1714 (reclassified authz-bypass, not
// audit-completeness): UpdateWebAuthnCredentialProxy used to trust an
// attacker-controlled full-row body, unconditionally. These tests assert the
// narrowed contract: the ONLY reachable transition is disable-on-clone,
// identified by (credential_id, user_id) matching the URL {id}, and any
// rejection leaves the stored row completely unchanged.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func putUpdateWebAuthnCredential(t *testing.T, h *AuthHandler, urlID string, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/api/v1/system/webauthn/credentials/"+urlID, bytes.NewReader(b)), "id", urlID)
	w := httptest.NewRecorder()
	h.UpdateWebAuthnCredentialProxy(w, req)
	return w
}

// TestUpdateWebAuthnCredentialProxy_1622_LegitimateDisable_HappyPath is the
// route's one remaining legitimate use: a well-formed disable, identified
// consistently across URL id and body (user_id, credential_id).
func TestUpdateWebAuthnCredentialProxy_1622_LegitimateDisable_HappyPath(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	credIDBytes := []byte(fmt.Sprintf("cred-1622-happy-%d", s4UniqueCounter.Add(1)))
	cred := &models.WebAuthnCredential{
		UserID:         501,
		CredentialID:   credIDBytes,
		Name:           "legit-key",
		CredentialBlob: []byte(`{}`),
	}
	require.NoError(t, h.coreService.Storage().CreateWebAuthnCredential(t.Context(), cred))
	require.NotZero(t, cred.ID)

	idStr := strconv.FormatUint(uint64(cred.ID), 10)
	w := putUpdateWebAuthnCredential(t, h, idStr, map[string]interface{}{
		"user_id": 501, "credential_id": credIDBytes, "disabled": true,
	})
	assert.Equal(t, http.StatusOK, w.Code)

	updated, err := h.coreService.Storage().GetWebAuthnCredentialByCredID(t.Context(), credIDBytes, 501)
	require.NoError(t, err)
	assert.True(t, updated.Disabled)
}

// TestUpdateWebAuthnCredentialProxy_1622_RefusesOwnershipReassignment: the
// original vulnerability. A caller supplying a user_id that does not
// actually own the named credential_id must not have that credential
// silently reassigned to it -- GetWebAuthnCredentialByCredID's scoped lookup
// (the same one rejectIfCloned itself relies on, #307) makes the mismatched
// pair resolve to nothing, so this fails as NOT_FOUND, not as a successful
// reassignment. The real owner's row is completely untouched.
func TestUpdateWebAuthnCredentialProxy_1622_RefusesOwnershipReassignment(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	credIDBytes := []byte(fmt.Sprintf("cred-1622-reassign-%d", s4UniqueCounter.Add(1)))
	cred := &models.WebAuthnCredential{
		UserID:         502,
		CredentialID:   credIDBytes,
		Name:           "victim-key",
		CredentialBlob: []byte(`{}`),
	}
	require.NoError(t, h.coreService.Storage().CreateWebAuthnCredential(t.Context(), cred))
	require.NotZero(t, cred.ID)

	idStr := strconv.FormatUint(uint64(cred.ID), 10)
	// Attacker claims a DIFFERENT user_id than the credential's real owner.
	w := putUpdateWebAuthnCredential(t, h, idStr, map[string]interface{}{
		"user_id": 999999, "credential_id": credIDBytes, "disabled": true,
	})
	assert.Equal(t, http.StatusNotFound, w.Code,
		"a user_id that doesn't own credential_id must not resolve to anything, let alone reassign it")

	// The real row is untouched: still owned by 502, still enabled.
	reloaded, err := h.coreService.Storage().GetWebAuthnCredentialByCredID(t.Context(), credIDBytes, 502)
	require.NoError(t, err)
	assert.False(t, reloaded.Disabled, "the victim's credential must remain unchanged")
}

// TestUpdateWebAuthnCredentialProxy_1622_RefusesReEnable: models.WebAuthnCredential's
// own doc says Disabled is "Never auto-re-enabled". disabled:false must be
// unreachable via this route regardless of the credential's current state --
// tested here against an already clone-disabled credential specifically,
// since that's the state where a re-enable would actually matter.
func TestUpdateWebAuthnCredentialProxy_1622_RefusesReEnable(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	credIDBytes := []byte(fmt.Sprintf("cred-1622-reenable-%d", s4UniqueCounter.Add(1)))
	cred := &models.WebAuthnCredential{
		UserID:         503,
		CredentialID:   credIDBytes,
		Name:           "cloned-key",
		CredentialBlob: []byte(`{}`),
		Disabled:       true, // already disabled by a prior clone-detection event
	}
	require.NoError(t, h.coreService.Storage().CreateWebAuthnCredential(t.Context(), cred))
	require.NotZero(t, cred.ID)

	idStr := strconv.FormatUint(uint64(cred.ID), 10)
	w := putUpdateWebAuthnCredential(t, h, idStr, map[string]interface{}{
		"user_id": 503, "credential_id": credIDBytes, "disabled": false,
	})
	assert.Equal(t, http.StatusBadRequest, w.Code,
		"disabled:false must never be reachable via this route")

	reloaded, err := h.coreService.Storage().GetWebAuthnCredentialByCredID(t.Context(), credIDBytes, 503)
	require.NoError(t, err)
	assert.True(t, reloaded.Disabled, "a clone-disabled credential must stay disabled")
}

// TestUpdateWebAuthnCredentialProxy_1622_RefusesIDMismatch: (credential_id,
// user_id) resolves to a REAL, owned row -- just not the one the URL {id}
// names. The check must run BEFORE any mutation: neither the row actually
// named by the URL nor the row actually named by the body may be touched.
func TestUpdateWebAuthnCredentialProxy_1622_RefusesIDMismatch(t *testing.T) {
	h := newAuthHandlerWithWebAuthn(t)
	n := s4UniqueCounter.Add(1)
	credA := &models.WebAuthnCredential{
		UserID: 504, CredentialID: []byte(fmt.Sprintf("cred-1622-mismatch-a-%d", n)),
		Name: "key-a", CredentialBlob: []byte(`{}`),
	}
	credB := &models.WebAuthnCredential{
		UserID: 504, CredentialID: []byte(fmt.Sprintf("cred-1622-mismatch-b-%d", n)),
		Name: "key-b", CredentialBlob: []byte(`{}`),
	}
	require.NoError(t, h.coreService.Storage().CreateWebAuthnCredential(t.Context(), credA))
	require.NoError(t, h.coreService.Storage().CreateWebAuthnCredential(t.Context(), credB))
	require.NotZero(t, credA.ID)
	require.NotZero(t, credB.ID)
	require.NotEqual(t, credA.ID, credB.ID)

	// URL names A's id, but the body's (credential_id, user_id) names B.
	w := putUpdateWebAuthnCredential(t, h, strconv.FormatUint(uint64(credA.ID), 10), map[string]interface{}{
		"user_id": 504, "credential_id": credB.CredentialID, "disabled": true,
	})
	assert.Equal(t, http.StatusConflict, w.Code)

	reloadedA, err := h.coreService.Storage().GetWebAuthnCredentialByCredID(t.Context(), credA.CredentialID, 504)
	require.NoError(t, err)
	assert.False(t, reloadedA.Disabled, "the URL-named credential must be untouched")

	reloadedB, err := h.coreService.Storage().GetWebAuthnCredentialByCredID(t.Context(), credB.CredentialID, 504)
	require.NoError(t, err)
	assert.False(t, reloadedB.Disabled, "the body-named credential must ALSO be untouched -- rejected before any mutation")
}
