// machine_identities_proxy_credential_narrow_test.go — G80 overnight campaign,
// Tier 1 Group A fix #2. UpdateMachineIdentityCredentialProxy used to persist a
// full caller-supplied replacement row (storage.Storage.UpdateMachineIdentityCredential
// is an unconditional full-row Save), which meant a caller could overwrite an
// EXISTING credential's TokenHash to a value they know (hijacking whatever
// identity/roles that credential carries) or flip Revoked back to false
// (resurrecting a credential an admin explicitly killed) — neither of which
// core.ClassifyMachineToken, the only legitimate caller of this storage
// primitive, has ever done. Fixed by fetching the existing row and applying
// only Classification from the wire body.
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateMachineIdentityCredentialProxy_IgnoresTokenHashAndRevoked_RealServer
// issues a real credential, then attempts to hijack it via the proxy by
// submitting an attacker-chosen TokenHash and Revoked:true alongside a
// legitimate-looking classification change. Only the classification change may
// take effect.
func TestUpdateMachineIdentityCredentialProxy_IgnoresTokenHashAndRevoked_RealServer(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	ctx := t.Context()

	proj, err := cs.CreateProject(ctx, "g80-credential-narrow-proj", "")
	require.NoError(t, err)
	m, err := cs.CreateMachineIdentity(ctx, proj.ID, "g80-credential-narrow-machine", core.MachineTypeOther, "", "", 0)
	require.NoError(t, err)
	// actorID must belong to a real user holding admin/roles.assign authority
	// now that IssueMachineToken enforces RequireMachinePrivilegeCeiling; user
	// ID 1 is the system_admin seeded by freshCoreS12WithAdmin.
	issued, err := cs.IssueMachineToken(ctx, proj.ID, m.ID, 1, core.IssueMachineTokenParams{
		Name: "g80-credential-narrow-cred", Classification: "internal",
	})
	require.NoError(t, err)
	originalHash := issued.Credential.TokenHash
	require.NotEmpty(t, originalHash)

	attackerBody, err := json.Marshal(map[string]interface{}{
		"id":                  issued.Credential.ID,
		"machine_identity_id": m.ID,
		"token_hash":          "attacker-known-hash-0123456789",
		"revoked":             true,
		"classification":      "confidential",
	})
	require.NoError(t, err)
	req := withChiParams(httptest.NewRequest("PUT", "/", bytes.NewReader(attackerBody)),
		map[string]string{"id": machineUintToStr(issued.Credential.ID)})
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityCredentialProxy(w, req)
	require.Equal(t, 200, w.Code, "the classification-only write must still succeed: %s", w.Body.String())

	reloaded, err := cs.Storage().GetMachineIdentityCredentialByID(ctx, issued.Credential.ID)
	require.NoError(t, err)
	assert.Equal(t, originalHash, reloaded.TokenHash, "TokenHash must not be caller-overwritable")
	assert.False(t, reloaded.Revoked, "Revoked must not be caller-settable through this proxy")
	assert.Equal(t, "confidential", reloaded.Classification, "the legitimate classification change must still apply")
}
