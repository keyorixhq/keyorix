// system_write_ceiling_table_test.go generalizes system_write_ceiling_test.go's
// single finding into the fix wave's acceptance criteria: every write-shaped route
// in the /api/v1/system/machine-identities, /machine-credentials, and
// /machine-oidc-bindings groups (server/http/handlers/machine_identities_proxy.go),
// exercised end-to-end through a real HTTP server + real router + real auth
// middleware, as the SAME human caller — one holding ONLY system.write, no
// admin-tier role, no node credential (see createSystemWriteOnlyToken in
// system_write_ceiling_test.go).
//
// Each row's "ceiling" column names the internal/core check that route's OWN core
// wrapper enforces and the raw proxy either does or doesn't (see
// docs/g80-raw-storage-bypass-triage.md for the full investigation each row is
// drawn from). A row is RED today if its handler is still an unguarded raw
// storage passthrough; fixing that handler (routing the specific missing check
// through, without breaking the legitimate RemoteStorage-relay wire contract —
// see e.g. machine_identities_proxy_transition_ceiling_test.go's already-fixed
// precedent) must turn it green. This file is deliberately committed red for the
// still-open rows — that red set IS the fix wave's checklist; the all-green state
// is its definition of done.
//
// Scope note: this table does not cover the group's pure GET routes (no
// escalation-relevant ceiling — the group's own system.write-or-node-credential
// gate is the only check that applies to a read) or routes already confirmed
// no-independent-ceiling / documented-exception in the triage doc (e.g.
// TouchMachineIdentityCredentialProxy, UpdateMachineIdentityProxy). It also does
// not (yet) cover RevokeMachineIdentityCredentialProxy: the current wire contract
// (DELETE-by-bare-credential-ID, no project/scope parameter at all) can't express
// a scope check without a RemoteStorage client-side change first — a different,
// harder fix shape than the other rows here; deferred and filed as #1551, not
// asserted on below.
//
// A second dimension, added after the first fix pass: "Node-credential-path
// rows" below exercise the human-caller rows' SAME three write routes again, but
// as a genuine node-credential relay (f.nodeToken) instead of the system.write-
// only human (f.token) — see that section's own doc for why, and
// docs/g80-raw-storage-bypass-triage.md's "Fix status" section for the
// authoritative half-fixed/open status these rows pin.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ceilingTableFixtures holds every real row this table's requests reference,
// created once per test run and shared read-only across table cases (cases that
// mutate state use their OWN dedicated fixture, never one another case depends on
// reading unmutated).
type ceilingTableFixtures struct {
	serverURL     string
	token         string // system.write-only human caller under test
	nodeToken     string // genuine node-credential relay caller (createNodeToken)
	projectID     uint
	plainMachine  uint // ordinary machine identity, no roles
	adminMachine  uint // holds the admin-tier "system_admin" role at global scope
	revokedMach   uint // machine identity already in state=revoked
	plainCredID   uint // existing, non-revoked credential on plainMachine
	revokedCredID uint // existing, ALREADY-revoked credential on plainMachine
	bindingID     uint // existing OIDC binding on plainMachine
	normalRoleID  uint // a non-admin-tier role
	adminRoleID   uint // system_admin's role ID
}

func setupCeilingTableFixtures(t *testing.T) ceilingTableFixtures {
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
	createTestToken(t, testCore) // bootstrap admin + seed roles/permissions
	admin, err := testCore.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	projects, err := testCore.Storage().ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	projectID := projects[0].ID

	plainMachine, err := testCore.CreateMachineIdentity(ctx, projectID, "ceiling-table-plain", core.MachineTypeService, "", "", admin.ID)
	require.NoError(t, err)

	adminMachine, err := testCore.CreateMachineIdentity(ctx, projectID, "ceiling-table-admin-tier", core.MachineTypeService, "", "", admin.ID)
	require.NoError(t, err)
	adminRole, err := testCore.Storage().GetRoleByName(ctx, "system_admin")
	require.NoError(t, err)
	require.NoError(t, testCore.AssignMachineRole(ctx, adminMachine.ID, adminRole.ID, core.Scope{ProjectID: projectID}, admin.ID))

	revokedMachine, err := testCore.CreateMachineIdentity(ctx, projectID, "ceiling-table-revoked", core.MachineTypeService, "", "", admin.ID)
	require.NoError(t, err)
	revokedMachine.State = core.MachineRevoked
	matched, err := testCore.Storage().TransitionMachineIdentityState(ctx, revokedMachine, core.MachineActive)
	require.NoError(t, err)
	require.True(t, matched)

	plainCred, err := testCore.Storage().CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
		MachineIdentityID: plainMachine.ID, Name: "plain-cred", TokenHash: "aaaa000000000000000000000000000000000000000000000000000000000001", TokenPrefix: "mid_a",
	})
	require.NoError(t, err)

	revokedCred, err := testCore.Storage().CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
		MachineIdentityID: plainMachine.ID, Name: "revoked-cred", TokenHash: "bbbb000000000000000000000000000000000000000000000000000000000002", TokenPrefix: "mid_b", Revoked: true,
	})
	require.NoError(t, err)

	binding, err := testCore.Storage().CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: plainMachine.ID, Issuer: "https://ceiling-table.example", Subject: "table-subject", CreatedBy: admin.ID, CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	normalRole, err := testCore.Storage().CreateRole(ctx, &models.Role{Name: "ceiling_table_normal_role", Description: "non-admin"})
	require.NoError(t, err)

	token := createSystemWriteOnlyToken(t, testCore)
	// createNodeToken (integration_test.go) also calls createTestToken internally —
	// safe to call again here since createTestToken tolerates an already-initialized
	// system (logs and continues rather than failing).
	nodeToken := createNodeToken(t, testCore)

	return ceilingTableFixtures{
		serverURL:     server.URL,
		token:         token,
		nodeToken:     nodeToken,
		projectID:     projectID,
		plainMachine:  plainMachine.ID,
		adminMachine:  adminMachine.ID,
		revokedMach:   revokedMachine.ID,
		plainCredID:   plainCred.ID,
		revokedCredID: revokedCred.ID,
		bindingID:     binding.ID,
		normalRoleID:  normalRole.ID,
		adminRoleID:   adminRole.ID,
	}
}

// doCeilingRequest issues method/path with body (nil for none) as the table
// fixture's system.write-only human caller and returns the status code + raw body.
func doCeilingRequest(t *testing.T, f ceilingTableFixtures, method, path string, body any) (int, string) {
	t.Helper()
	return doCeilingRequestAs(t, f, f.token, method, path, body)
}

// doCeilingRequestAs is doCeilingRequest generalized to an explicit bearer token,
// so a row can exercise the SAME route as a different caller class — e.g.
// f.nodeToken (a genuine node-credential relay) instead of f.token (the
// system.write-only human).
func doCeilingRequestAs(t *testing.T, f ceilingTableFixtures, token, method, path string, body any) (int, string) {
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

// TestSystemWriteCeiling_CreateMachineIdentityProxy_ForcesActiveState is the
// table's CreateMachineIdentityProxy row. Ceiling: core.CreateMachineIdentity
// unconditionally forces State=MachineActive on every create (machine_identities.go
// :99) — a machine identity is never born in any other state. The raw proxy
// currently persists whatever State the caller supplies verbatim. RED today: a
// system.write-only caller can mint an identity already in state "revoked" (or
// any other value), never having been active.
func TestSystemWriteCeiling_CreateMachineIdentityProxy_ForcesActiveState(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequest(t, f, http.MethodPost, "/api/v1/system/machine-identities", map[string]any{
		"name": "ceiling-table-forged-state", "project_id": f.projectID,
		"identity_type": core.MachineTypeService, "state": core.MachineRevoked,
	})
	t.Logf("CreateMachineIdentityProxy(state=%s): status=%d body=%s", core.MachineRevoked, status, body)
	require.Equal(t, http.StatusOK, status, "request itself must be accepted (a 4xx here would mean a different regression)")
	var parsed struct {
		Data struct {
			State string `json:"state"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))
	require.Equal(t, core.MachineActive, parsed.Data.State,
		"CEILING VIOLATED: CreateMachineIdentityProxy must force State=MachineActive like core.CreateMachineIdentity does, "+
			"not persist a caller-supplied state verbatim")
}

// TestSystemWriteCeiling_CreateMachineIdentityCredentialProxy_EnforcesPrivilegeCeiling
// is the table's CreateMachineIdentityCredentialProxy row — the campaign's own
// "MOST SEVERE FINDING". Ceiling: core.IssueMachineToken calls
// requireMachinePrivilegeCeiling (MACH-001) — a non-global-admin actor cannot mint
// a credential for a machine identity that itself holds an admin-tier role,
// because that credential inherits the machine's roles (equivalent to a role
// grant). The raw proxy has no such check. RED today: a system.write-only caller
// (confirmed non-global-admin) can forge a working credential for f.adminMachine
// (holds system_admin) and authenticate as an admin-tier principal.
func TestSystemWriteCeiling_CreateMachineIdentityCredentialProxy_EnforcesPrivilegeCeiling(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequest(t, f, http.MethodPost, "/api/v1/system/machine-credentials", map[string]any{
		"machine_identity_id": f.adminMachine,
		"token_hash":          "cccc000000000000000000000000000000000000000000000000000000000003",
		"token_prefix":        "mid_forged_admin",
	})
	t.Logf("CreateMachineIdentityCredentialProxy(machine_identity_id=admin-tier %d): status=%d body=%s", f.adminMachine, status, body)
	require.Equal(t, http.StatusForbidden, status,
		"CEILING VIOLATED: a system.write-only, non-global-admin caller must be denied a credential for an "+
			"admin-tier machine identity (requireMachinePrivilegeCeiling, MACH-001) — got a real forged credential instead")
}

// TestSystemWriteCeiling_TransitionMachineIdentityStateProxy_RejectsIllegalTransition
// is the table's already-FIXED TransitionMachineIdentityStateProxy row (G80 Group
// A #1 — see machine_identities_proxy_transition_ceiling_test.go for the
// handler-level version of this same assertion). Included here for completeness
// of the acceptance-criteria table and to prove the fix holds at the real-server,
// real-auth layer too, not only in the direct handler-call test.
func TestSystemWriteCeiling_TransitionMachineIdentityStateProxy_RejectsIllegalTransition(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequest(t, f, http.MethodPut,
		fmt.Sprintf("/api/v1/system/machine-identities/%d/transition", f.revokedMach),
		map[string]any{
			"machine_identity": map[string]any{"id": f.revokedMach, "project_id": f.projectID, "name": "x", "state": core.MachineActive},
			"from_state":       core.MachineRevoked,
		})
	t.Logf("TransitionMachineIdentityStateProxy(revoked->active): status=%d body=%s", status, body)
	require.Equal(t, http.StatusBadRequest, status,
		"revoked must stay terminal (core.IsValidMachineTransition) — a 200 here would mean this Group A fix regressed")
}

// TestSystemWriteCeiling_AssignMachineRoleProxy_DeniesAdminTierGrant is the
// table's AssignMachineRoleProxy row — already routed through core.AssignMachineRole
// (#1542), which calls requireAuthorityForRole. A non-admin caller may still grant
// a NON-admin-tier role (roles.assign's own footprint); only an admin-tier grant
// must be refused.
func TestSystemWriteCeiling_AssignMachineRoleProxy_DeniesAdminTierGrant(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d/roles/%d?project_id=%d&environment_id=0", f.plainMachine, f.adminRoleID, f.projectID)
	status, body := doCeilingRequest(t, f, http.MethodPost, path, nil)
	t.Logf("AssignMachineRoleProxy(role=system_admin): status=%d body=%s", status, body)
	require.Equal(t, http.StatusInternalServerError, status,
		"a system.write-only caller must be refused when granting an admin-tier role (requireAuthorityForRole) — "+
			"internal/core wraps the denial as a storage error today (500), which is a real behavior gap of its own, "+
			"but the grant itself must not succeed")
}

// TestSystemWriteCeiling_AssignMachineRoleProxy_AllowsNonAdminGrant is the same
// route's companion control: a non-admin-tier grant is roles.assign's own,
// legitimate footprint and must still succeed for this caller.
func TestSystemWriteCeiling_AssignMachineRoleProxy_AllowsNonAdminGrant(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d/roles/%d?project_id=%d&environment_id=0", f.plainMachine, f.normalRoleID, f.projectID)
	status, body := doCeilingRequest(t, f, http.MethodPost, path, nil)
	t.Logf("AssignMachineRoleProxy(role=non-admin): status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status, "a non-admin-tier role grant is not gated by requireAuthorityForRole and must succeed")
}

// TestSystemWriteCeiling_UpdateMachineIdentityCredentialProxy_CannotResurrectRevoked
// is the table's already-FIXED UpdateMachineIdentityCredentialProxy row (G80 Group
// A #2): the handler now only ever applies Classification from the wire body,
// never Revoked/TokenHash/ExpiresAt.
func TestSystemWriteCeiling_UpdateMachineIdentityCredentialProxy_CannotResurrectRevoked(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequest(t, f, http.MethodPut,
		fmt.Sprintf("/api/v1/system/machine-credentials/%d", f.revokedCredID),
		map[string]any{"id": f.revokedCredID, "machine_identity_id": f.plainMachine, "revoked": false, "classification": "internal"})
	t.Logf("UpdateMachineIdentityCredentialProxy(resurrect attempt): status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status, "the update call itself must still succeed (it's a legitimate classification change)")

	status, body = doCeilingRequest(t, f, http.MethodGet, fmt.Sprintf("/api/v1/system/machine-credentials/%d", f.revokedCredID), nil)
	require.Equal(t, http.StatusOK, status)
	var parsed struct {
		Data struct {
			Revoked bool `json:"revoked"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))
	require.True(t, parsed.Data.Revoked,
		"the attempted resurrection (revoked:false in the update body) must have been silently ignored — "+
			"a real resurrection here would mean this Group A fix regressed")
}

// TestSystemWriteCeiling_CreateOIDCBindingProxy_RequiresInstallWideAdminAuthority
// is the table's CreateOIDCBindingProxy row. Ceiling: core.CreateOIDCBinding
// requires GLOBAL admin authority (requireAuthorityForRole(..., "system_admin"),
// #127) — (issuer, subject) is a global namespace, so binding one is scoped to
// what it actually claims, not merely project-scoped roles.assign. The raw proxy
// has no such check. RED today: a system.write-only caller can pre-claim any
// (issuer, subject) pair for a machine of their choosing.
func TestSystemWriteCeiling_CreateOIDCBindingProxy_RequiresInstallWideAdminAuthority(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequest(t, f, http.MethodPost, "/api/v1/system/machine-oidc-bindings", map[string]any{
		"machine_identity_id": f.plainMachine, "issuer": "https://ceiling-table-preclaim.example", "subject": "preclaimed-subject",
	})
	t.Logf("CreateOIDCBindingProxy: status=%d body=%s", status, body)
	require.Equal(t, http.StatusForbidden, status,
		"CEILING VIOLATED: a system.write-only caller must be denied — binding an OIDC subject requires install-wide "+
			"admin authority (core.CreateOIDCBinding's requireAuthorityForRole check), which this caller does not hold")
}

// TestSystemWriteCeiling_DeleteOIDCBindingProxy_VerifiesOwnership is the table's
// DeleteOIDCBindingProxy row. Ceiling: core.DeleteOIDCBinding verifies the binding
// actually belongs to the named machine (machineInProject + a MachineIdentityID
// match) before deleting, and writes the machine_identity.oidc_unbound audit
// event. FIXED for a direct, non-node-credential caller (see the
// TestDeleteOIDCBindingProxy_WritesAuditEvent_S21 regression test in
// server/http/handlers, which pins the audit trail this row's own status-code
// assertion can't observe). This row is necessarily a narrower assertion than
// "denied outright" — deleting a binding you're relaying on behalf of IS
// legitimate; the fix routes through core.DeleteOIDCBinding to resolve the
// real owning machine/project rather than trusting a caller-supplied one (this
// proxy takes no project parameter at all, so there is no mismatched-project
// fixture to assert a 403/404 against here).
func TestSystemWriteCeiling_DeleteOIDCBindingProxy_VerifiesOwnership(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequest(t, f, http.MethodDelete, fmt.Sprintf("/api/v1/system/machine-oidc-bindings/%d", f.bindingID), nil)
	t.Logf("DeleteOIDCBindingProxy: status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status, "the delete itself is expected to succeed for a binding that IS legitimately owned by its machine")
}

// ── Node-credential-path rows ────────────────────────────────────────────────
//
// The three rows below exercise the SAME routes above, but with f.nodeToken (a
// genuine node-type machine credential — createNodeToken, integration_test.go)
// instead of f.token (the system.write-only human). They exist because fixing
// CreateMachineIdentityCredentialProxy and CreateOIDCBindingProxy for a DIRECT
// caller (above) required an isNodeCredentialRequest(r) branch that routes a
// node-credential caller around the new check entirely, to the raw storage
// call — otherwise every legitimate node relay would ALSO be denied (a node
// always resolves actorID(r)==0, and both requireMachinePrivilegeCeiling and
// requireAuthorityForRole refuse actorID==0 outright). That branch is
// necessary — but it also means the exemption is real, not hypothetical, and
// needed its own visible, asserted coverage rather than living implicitly
// inside an if-statement with no test pinning what it actually permits.
//
// These rows assert CURRENT behavior (allowed) exactly as it is today — this
// is a KNOWN, DOCUMENTED GAP (see docs/g80-raw-storage-bypass-triage.md's "Fix
// status" section and knownUnfixedRawStorageBypasses' HALF-FIXED entries for
// CreateMachineIdentityCredentialProxy/CreateOIDCBindingProxy), NOT intended,
// approved-safe behavior. Nothing on the wire distinguishes a genuine relay of
// an already-checked downstream decision from a bare node credential calling
// the route directly with attacker-chosen parameters (ADR-085's still-unresolved
// "harder question" — see docs/adr-085-node-credential-permission-scope.md). If
// a future fix closes this (a wire-level actor-identity field, or removing the
// node bypass per ADR-085's proposed direction), these rows must go RED and get
// updated to assert denial — they are pinning the gap, not blessing it.

// TestSystemWriteCeiling_CreateMachineIdentityProxy_NodeCredential_AlsoForcesActiveState
// is NOT a gap: core.CreateMachineIdentity has no actor-authority check at all
// (only State/IdentityType/Classification validation), for ANY caller. A node
// credential behaves identically to the human caller in the row above. Included
// for symmetry/completeness of the node-credential dimension, not because this
// route has a caller-class-dependent exemption to pin.
func TestSystemWriteCeiling_CreateMachineIdentityProxy_NodeCredential_AlsoForcesActiveState(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.nodeToken, http.MethodPost, "/api/v1/system/machine-identities", map[string]any{
		"name": "ceiling-table-node-create", "project_id": f.projectID,
		"identity_type": core.MachineTypeService, "state": core.MachineRevoked,
	})
	t.Logf("CreateMachineIdentityProxy(node credential, state=%s): status=%d body=%s", core.MachineRevoked, status, body)
	require.Equal(t, http.StatusOK, status, "no actor-authority check exists for either caller class on this route")
	var parsed struct {
		Data struct {
			State string `json:"state"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))
	require.Equal(t, core.MachineActive, parsed.Data.State, "same forced-active behavior as the human-caller row — no caller-class difference here")
}

// TestSystemWriteCeiling_CreateMachineIdentityCredentialProxy_NodeCredential_StillBypassesPrivilegeCeiling
// pins the KNOWN, OPEN gap: unlike the human-caller row above (now 403), a node
// credential still reaches the raw storage.CreateMachineIdentityCredential call
// unconditionally (isNodeCredentialRequest branch, machine_identities_proxy.go),
// so it can still forge a working credential for f.adminMachine (holds
// system_admin) — the campaign's original "MOST SEVERE FINDING", now reachable
// only via a node credential instead of any system.write holder, not closed.
func TestSystemWriteCeiling_CreateMachineIdentityCredentialProxy_NodeCredential_StillBypassesPrivilegeCeiling(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.nodeToken, http.MethodPost, "/api/v1/system/machine-credentials", map[string]any{
		"machine_identity_id": f.adminMachine,
		"token_hash":          "dddd000000000000000000000000000000000000000000000000000000000004",
		"token_prefix":        "mid_forged_admin_node",
	})
	t.Logf("CreateMachineIdentityCredentialProxy(node credential, machine_identity_id=admin-tier %d): status=%d body=%s", f.adminMachine, status, body)
	require.Equal(t, http.StatusOK, status,
		"KNOWN GAP (not intended, pending ADR-085's wire-identity decision): a node credential still forges a "+
			"credential for an admin-tier machine identity — isNodeCredentialRequest routes it around "+
			"requireMachinePrivilegeCeiling entirely, on an unverified relay-trust assumption. If this ever goes "+
			"non-200, update this assertion — that would mean the gap closed, which is the goal, not a regression.")
}

// TestSystemWriteCeiling_CreateOIDCBindingProxy_NodeCredential_StillBypassesAdminAuthority
// pins the KNOWN, OPEN gap: unlike the human-caller row above (now 403), a node
// credential still reaches the raw storage.CreateOIDCBinding call unconditionally
// (isNodeCredentialRequest branch), so it can still pre-claim any (issuer,
// subject) pair for a machine of its choosing with no install-wide admin-authority
// check at all.
func TestSystemWriteCeiling_CreateOIDCBindingProxy_NodeCredential_StillBypassesAdminAuthority(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.nodeToken, http.MethodPost, "/api/v1/system/machine-oidc-bindings", map[string]any{
		"machine_identity_id": f.plainMachine, "issuer": "https://ceiling-table-node-preclaim.example", "subject": "node-preclaimed-subject",
	})
	t.Logf("CreateOIDCBindingProxy(node credential): status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status,
		"KNOWN GAP (not intended, pending ADR-085's wire-identity decision): a node credential still creates an "+
			"OIDC binding with no install-wide admin-authority check — isNodeCredentialRequest routes it around "+
			"requireAuthorityForRole entirely, on an unverified relay-trust assumption. If this ever goes non-200, "+
			"update this assertion — that would mean the gap closed, which is the goal, not a regression.")
}

// TestSystemWriteCeiling_DeleteOIDCBindingProxy_NodeCredential_StillBypassesOwnershipCheck
// pins the KNOWN, OPEN gap: unlike the direct-caller row above (now routed
// through core.DeleteOIDCBinding), a node credential still reaches the raw
// storage.DeleteOIDCBinding call unconditionally (isNodeCredentialRequest
// branch), so it can still delete any binding ID with no ownership/project
// resolution and no audit event at all.
func TestSystemWriteCeiling_DeleteOIDCBindingProxy_NodeCredential_StillBypassesOwnershipCheck(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.nodeToken, http.MethodDelete, fmt.Sprintf("/api/v1/system/machine-oidc-bindings/%d", f.bindingID), nil)
	t.Logf("DeleteOIDCBindingProxy(node credential): status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status,
		"KNOWN GAP (not intended, pending ADR-085's wire-identity decision): a node credential still deletes an "+
			"OIDC binding with no ownership check and no audit event — isNodeCredentialRequest routes it around "+
			"core.DeleteOIDCBinding entirely, on an unverified relay-trust assumption. If this ever goes non-200, "+
			"update this assertion — that would mean the gap closed, which is the goal, not a regression.")
}
