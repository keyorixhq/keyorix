// machine_privilege_ceiling_creation_test.go — regression coverage for the
// second half of the two-call system.write -> global system_admin escalation
// found during independent verification of the G80 campaign (2026-08-25):
// requireMachinePrivilegeCeiling only ever inspected the TARGET machine
// identity's CURRENT roles, never the actor's own standing, and was never
// consulted at machine-identity CREATION at all. Removing the node-credential
// OR-arm (ADR-085) closes the third step of the original exploit chain (the
// self-minted credential could no longer bypass the role-grant ceiling), but
// steps 1-2 — create a zero-role machine identity, then mint yourself a
// working credential for it — remained open independent of the node arm,
// because a brand-new identity trivially clears "target isn't admin-tier yet."
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// machinePrivilegeCeilingFixture is a self-contained fixture (deliberately not
// reusing ceilingTableFixtures, to avoid widening that shared struct for a
// handful of rows): a real server, a bootstrapped admin/project, a
// system.write-only human, and a system.write+roles.assign human.
type machinePrivilegeCeilingFixture struct {
	serverURL   string
	core        *core.KeyorixCore
	projectID   uint
	adminID     uint
	swToken     string
	assignToken string
}

func newMachinePrivilegeCeilingFixture(t *testing.T) *machinePrivilegeCeilingFixture {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	cfg := &config.Config{}
	testCore := newTestCore(t)
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	ctx := context.Background()
	createTestToken(t, testCore)
	admin, err := testCore.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	projects, err := testCore.Storage().ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)

	return &machinePrivilegeCeilingFixture{
		serverURL:   server.URL,
		core:        testCore,
		projectID:   projects[0].ID,
		adminID:     admin.ID,
		swToken:     createSystemWriteOnlyToken(t, testCore),
		assignToken: createSystemWriteAndRolesAssignToken(t, testCore),
	}
}

func (f *machinePrivilegeCeilingFixture) do(t *testing.T, token, method, path string, body any) (int, string) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, f.serverURL+path, reader)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, err = buf.ReadFrom(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, buf.String()
}

// TestMachinePrivilegeCeiling_CreateMachineIdentityProxy_RequiresRolesAssign is
// step 1 of the chain: a system.write-only human (no roles.assign anywhere)
// must no longer be able to create a machine identity at all — the SAME
// authority the human-facing POST /projects/{id}/machine-identities route
// already requires, which this proxy never enforced.
func TestMachinePrivilegeCeiling_CreateMachineIdentityProxy_RequiresRolesAssign(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)

	status, body := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/machine-identities", map[string]any{
		"name": "self-mint-chain-step1", "project_id": f.projectID, "identity_type": "node",
	})
	t.Logf("CreateMachineIdentityProxy(system.write-only, no roles.assign): status=%d body=%s", status, body)
	require.Equal(t, http.StatusForbidden, status,
		"a caller holding no roles.assign authority over this project must not be able to create a machine identity in it")
}

// TestMachinePrivilegeCeiling_CreateMachineIdentityCredentialProxy_ZeroRoleTarget_RequiresRolesAssign
// is step 2 in isolation: even for an ALREADY-EXISTING, currently zero-role
// machine identity (created here via a trusted setup path, standing in for
// "step 1 somehow already succeeded, or the identity predates this fix"), a
// system.write-only caller with no roles.assign at that project must still be
// refused a credential for it.
func TestMachinePrivilegeCeiling_CreateMachineIdentityCredentialProxy_ZeroRoleTarget_RequiresRolesAssign(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	zeroRoleMachine, err := f.core.CreateMachineIdentity(ctx, f.projectID, "zero-role-target", core.MachineTypeNode, "", "", f.adminID, 0)
	require.NoError(t, err)

	status, body := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/machine-credentials", map[string]any{
		"machine_identity_id": zeroRoleMachine.ID,
		"token_hash":          "cccc000000000000000000000000000000000000000000000000000000000003",
		"token_prefix":        "kx_machine_",
	})
	t.Logf("CreateMachineIdentityCredentialProxy(system.write-only, zero-role target %d, no roles.assign): status=%d body=%s", zeroRoleMachine.ID, status, body)
	require.Equal(t, http.StatusForbidden, status,
		"a caller holding no roles.assign authority over this project must not be able to mint a credential for ANY machine identity in it, admin-tier or not")
}

// TestMachinePrivilegeCeiling_CreateMachineIdentityCredentialProxy_RolesAssignHolder_Succeeds
// proves the other half: a caller who genuinely holds roles.assign at the
// target's project scope can still mint a credential for a zero-role
// machine identity — the fix is a real permission check, not a blanket denial.
func TestMachinePrivilegeCeiling_CreateMachineIdentityCredentialProxy_RolesAssignHolder_Succeeds(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	zeroRoleMachine, err := f.core.CreateMachineIdentity(ctx, f.projectID, "zero-role-target-2", core.MachineTypeNode, "", "", f.adminID, 0)
	require.NoError(t, err)

	status, body := f.do(t, f.assignToken, http.MethodPost, "/api/v1/system/machine-credentials", map[string]any{
		"machine_identity_id": zeroRoleMachine.ID,
		"token_hash":          "dddd000000000000000000000000000000000000000000000000000000000004",
		"token_prefix":        "kx_machine_",
	})
	t.Logf("CreateMachineIdentityCredentialProxy(roles.assign holder, zero-role target %d): status=%d body=%s", zeroRoleMachine.ID, status, body)
	require.Equal(t, http.StatusOK, status, "a genuine roles.assign holder must still be able to mint a credential for an ordinary machine identity")
}

// TestMachinePrivilegeCeiling_FullChain_SystemWriteToGlobalAdmin_NowBlocked is
// the literal three-step chain the independent verification session ran live
// against main, now confirmed blocked at step 1 (or, were step 1 ever to be
// separately reopened, step 2 blocks it independently — see the two tests
// above). Kept as one end-to-end row mirroring exactly how the chain was
// originally driven, not just its component parts in isolation.
func TestMachinePrivilegeCeiling_FullChain_SystemWriteToGlobalAdmin_NowBlocked(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)

	status, body := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/machine-identities", map[string]any{
		"name": "full-chain-node", "project_id": f.projectID, "identity_type": "node",
	})
	t.Logf("step 1 (create node identity): status=%d body=%s", status, body)
	if status != http.StatusOK {
		t.Logf("chain blocked at step 1 -- requireMachinePrivilegeCeiling denied creation, as expected")
		return
	}

	var parsed struct {
		Data struct {
			ID float64 `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))
	status, body = f.do(t, f.swToken, http.MethodPost, "/api/v1/system/machine-credentials", map[string]any{
		"machine_identity_id": parsed.Data.ID,
		"token_hash":          "eeee000000000000000000000000000000000000000000000000000000000005",
		"token_prefix":        "kx_machine_",
	})
	t.Logf("step 2 (mint credential): status=%d body=%s", status, body)
	require.NotEqual(t, http.StatusOK, status,
		"the full escalation chain must not reach step 2's success: a system.write-only caller must not mint a working credential for a machine it just created")
}
