package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/require"
)

// storeCallerCredential stores an opaque credential for machineID with the
// given AllowedCIDRs column and returns its plaintext.
func storeCallerCredential(t *testing.T, st storage.Storage, machineID uint, name, allowedCIDRs string) string {
	t.Helper()
	raw := "kx_machine_caller-" + name
	sum := sha256.Sum256([]byte(raw))
	_, err := st.CreateMachineIdentityCredential(context.Background(), &models.MachineIdentityCredential{
		MachineIdentityID: machineID,
		Name:              name,
		TokenHash:         hex.EncodeToString(sum[:]),
		TokenPrefix:       raw[:len("kx_machine_")+6],
		AllowedCIDRs:      allowedCIDRs,
	})
	require.NoError(t, err)
	return raw
}

// assignOnlyRoleMachine creates a machine holding a custom, non-bypass role
// that bundles only roles.assign at project 1 (the review's probe), plus a
// plain peer.
func assignOnlyRoleMachine(t *testing.T, suffix string) (*CatalogHandler, storage.Storage, *models.MachineIdentity, *models.MachineIdentity) {
	t.Helper()
	cs := freshCoreS11(t)
	h := NewCatalogHandler(cs)
	bootstrapS11(t, cs, "tokcred"+suffix)
	ctx := context.Background()
	st := cs.Storage()

	caller, err := st.CreateMachineIdentity(ctx, &models.MachineIdentity{ProjectID: 1, Name: "cred-caller", State: "active"})
	require.NoError(t, err)
	peer, err := st.CreateMachineIdentity(ctx, &models.MachineIdentity{ProjectID: 1, Name: "cred-peer", State: "active"})
	require.NoError(t, err)
	folded, err := identity.NewFoldedName("assign_only_" + suffix)
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, folded, "test-only: roles.assign only")
	require.NoError(t, err)
	perms, err := st.ListPermissions(ctx)
	require.NoError(t, err)
	for _, p := range perms {
		if p.Name == "roles.assign" {
			require.NoError(t, st.AssignPermissionToRole(ctx, role.ID, p.ID))
		}
	}
	require.NoError(t, st.AssignMachineRole(ctx, caller.ID, role.ID, storage.Scope{ProjectID: 1}))
	return h, st, caller, peer
}

// postTokenAsMachine POSTs body to /projects/1/machine-identities/{target}/tokens
// as machine caller presenting bearer, with the restriction the auth middleware
// would have attached for that credential.
func postTokenAsMachine(h *CatalogHandler, caller *models.MachineIdentity, target uint, bearer string, restriction *core.MachineTokenRestriction, body string) *httptest.ResponseRecorder {
	uc := &middleware.UserContext{UserID: 0, ActorType: core.ActorTypeMachine, MachineIdentityID: &caller.ID, MachineTokenRestriction: restriction}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	req = withChiParams(req, map[string]string{"id": "1", "machineId": machineUintToStr(target)})
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	return w
}

func requireNoCredentialNamed(t *testing.T, st storage.Storage, machineID uint, name string) {
	t.Helper()
	creds, err := st.ListMachineIdentityCredentials(context.Background(), machineID)
	require.NoError(t, err)
	for _, c := range creds {
		require.NotEqual(t, name, c.Name, "a refused issue must not store a credential")
	}
}

// REVIEW-3993-DEEP-1 finding 1: a CIDR-restricted machine credential POSTing
// {"name":"escape"} to its own /tokens got 201 with an unrestricted,
// non-expiring token. It must be refused.
func TestIssueMachineToken_RestrictedMachineCannotSelfMintEscape(t *testing.T) {
	h, st, caller, _ := assignOnlyRoleMachine(t, "esc")
	raw := storeCallerCredential(t, st, caller.ID, "restricted", `["10.0.0.0/8"]`)

	w := postTokenAsMachine(h, caller, caller.ID, raw, &core.MachineTokenRestriction{AllowedCIDRs: []string{"10.0.0.0/8"}}, `{"name":"escape"}`)
	require.Equal(t, http.StatusForbidden, w.Code, "response body: %s", w.Body.String())
	requireNoCredentialNamed(t, st, caller.ID, "escape")
}

// A CIDR-restricted caller cannot launder its restriction through a peer either.
func TestIssueMachineToken_RestrictedMachineCannotMintForPeer(t *testing.T) {
	h, st, caller, peer := assignOnlyRoleMachine(t, "peer")
	raw := storeCallerCredential(t, st, caller.ID, "restricted", `["10.0.0.0/8"]`)

	w := postTokenAsMachine(h, caller, peer.ID, raw, &core.MachineTokenRestriction{AllowedCIDRs: []string{"10.0.0.0/8"}}, `{"name":"escape"}`)
	require.Equal(t, http.StatusForbidden, w.Code, "response body: %s", w.Body.String())
	requireNoCredentialNamed(t, st, peer.ID, "escape")
}

// An unrestricted machine still may not mint for itself.
func TestIssueMachineToken_UnrestrictedMachineCannotSelfMint(t *testing.T) {
	h, st, caller, _ := assignOnlyRoleMachine(t, "self")
	raw := storeCallerCredential(t, st, caller.ID, "plain", "")

	w := postTokenAsMachine(h, caller, caller.ID, raw, nil, `{"name":"escape"}`)
	require.Equal(t, http.StatusForbidden, w.Code, "response body: %s", w.Body.String())
	requireNoCredentialNamed(t, st, caller.ID, "escape")
}

// A federated machine (OIDC/Kubernetes JWT bearer) cannot mint a durable
// opaque token, which ADR-031's "no long-lived secret" rules out.
func TestIssueMachineToken_FederatedMachineCannotMintDurableToken(t *testing.T) {
	h, st, caller, peer := assignOnlyRoleMachine(t, "oidc")

	w := postTokenAsMachine(h, caller, peer.ID, "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjaSJ9.c2ln", nil, `{"name":"durable"}`)
	require.Equal(t, http.StatusForbidden, w.Code, "response body: %s", w.Body.String())
	requireNoCredentialNamed(t, st, peer.ID, "durable")
}

// The permitted shape: an unrestricted opaque caller issuing for a plain peer.
func TestIssueMachineToken_UnrestrictedMachineMintsForPeer(t *testing.T) {
	h, st, caller, peer := assignOnlyRoleMachine(t, "okpeer")
	raw := storeCallerCredential(t, st, caller.ID, "plain", "")

	w := postTokenAsMachine(h, caller, peer.ID, raw, nil, `{"name":"for-peer"}`)
	require.Equal(t, http.StatusCreated, w.Code, "response body: %s", w.Body.String())
}
