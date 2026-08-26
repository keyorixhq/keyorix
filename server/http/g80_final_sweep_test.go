// g80_final_sweep_test.go — the final documented-exception sweep (2026-08-26).
// Adversarial verification of every remaining "this bypass is deliberate and
// safe" comment in the codebase, run from a clean worktree off current
// origin/main. Each test constructs the caller class the claim's own gate
// implies, makes real HTTP requests against a real httptest server + real
// storage + real router/middleware chain (system_write_ceiling_test.go's
// pattern), and records observed status codes / response bodies / database
// state. No test here asserts a specific outcome -- verdicts are reported
// separately, not encoded as pass/fail, so a "the exception holds" result is
// not indistinguishable from "nobody looked."
package http

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type g80SweepFixture struct {
	serverURL string
	core      *core.KeyorixCore
	projectID uint
	adminID   uint
	swToken   string // system.write only, no other permission
}

func newG80SweepFixture(t *testing.T) *g80SweepFixture {
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

	return &g80SweepFixture{
		serverURL: server.URL,
		core:      testCore,
		projectID: projects[0].ID,
		adminID:   admin.ID,
		swToken:   createSystemWriteOnlyToken(t, testCore),
	}
}

func (f *g80SweepFixture) do(t *testing.T, token, method, path string, body any) (int, string) {
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
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
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

func validBcryptHash(t *testing.T) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte("G80SweepPlaceholderPassw0rd!"), bcrypt.MinCost)
	require.NoError(t, err)
	return string(h)
}

// TestG80Sweep01_CreateUserWithRoleGrantsProxy_EscalationCeiling is claim 1:
// misc_remote_proxy.go's CreateUserWithRoleGrantsProxy claims
// ValidateRoleGrantAuthority re-derives the escalation-ceiling +
// SoD checks a local create-user flow would apply, against actorID(r).
// Attack: a caller holding ONLY system.write (no roles.assign, no admin-tier
// role) creates a brand-new user and grants it the system_admin role at
// global scope in the SAME call.
func TestG80Sweep01_CreateUserWithRoleGrantsProxy_EscalationCeiling(t *testing.T) {
	f := newG80SweepFixture(t)
	ctx := context.Background()

	adminRole, err := f.core.Storage().GetRoleByName(ctx, "system_admin")
	require.NoError(t, err)

	status, body := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/users/with-role-grants", map[string]any{
		"username":      "g80sweep01target",
		"email":         "g80sweep01target@example.com",
		"password_hash": validBcryptHash(t),
		"is_active":     true,
		"account_state": "active",
		"grants": []map[string]any{
			{"role_id": adminRole.ID, "project_id": 0, "environment_id": 0},
		},
	})
	t.Logf("[claim 1] CreateUserWithRoleGrantsProxy(system.write-only, grants system_admin@global): status=%d body=%s", status, body)

	// Observed database state regardless of HTTP status, per "inspect the
	// database directly" -- a 200 with the grant silently dropped, or a
	// non-200 that still committed the user+grant, would both be misreported
	// by the status code alone.
	createdUser, uerr := f.core.GetUserByEmail(ctx, "g80sweep01target@example.com")
	if uerr != nil {
		t.Logf("[claim 1] database: no user row for g80sweep01target@example.com (lookup error: %v)", uerr)
		return
	}
	roleIDs, rerr := f.core.Storage().GetUserRoleIDsAt(ctx, createdUser.ID, core.Scope{ProjectID: 0})
	t.Logf("[claim 1] database: user id=%d created; global-scope role IDs=%v (lookup error=%v); system_admin role id=%d",
		createdUser.ID, roleIDs, rerr, adminRole.ID)
}

// TestG80Sweep02_DeleteProjectIfEmptyProxy_AtomicGuard is claim 2:
// project_catalog_proxy.go's DeleteProjectIfEmptyProxy claims the whole
// guard-count-then-cascade sequence runs in ONE call against real storage,
// closing a TOCTOU window a naive two-call (count, then delete) proxy would
// reopen. No actor-authority claim is made here (the group's system.write
// gate is the only ceiling) -- the claim under test is atomicity: does the
// guard actually block deletion of a NON-empty project, or can the cascade
// run anyway? Attack: create a project with a live secret in it, call the
// proxy, and check the database for whether the project (and its secret)
// still exist afterward.
func TestG80Sweep02_DeleteProjectIfEmptyProxy_AtomicGuard(t *testing.T) {
	f := newG80SweepFixture(t)
	ctx := context.Background()

	project, err := f.core.CreateProject(ctx, "g80sweep02-nonempty-project", "")
	require.NoError(t, err)
	secret, err := f.core.Storage().CreateSecret(ctx, &models.SecretNode{
		ProjectID: project.ID, Name: "g80sweep02-blocking-secret", Type: "generic",
	})
	require.NoError(t, err)

	status, body := f.do(t, f.swToken, http.MethodPost,
		fmt.Sprintf("/api/v1/system/projects/%d/delete-if-empty", project.ID), nil)
	t.Logf("[claim 2] DeleteProjectIfEmptyProxy(system.write-only, project has 1 live secret): status=%d body=%s", status, body)

	stillExists, gerr := f.core.Storage().GetProject(ctx, project.ID)
	t.Logf("[claim 2] database: project id=%d still exists=%v (lookup error=%v)", project.ID, gerr == nil, gerr)
	if gerr == nil {
		t.Logf("[claim 2] database: project row: %+v", stillExists)
	}
	secretStillExists, serr := f.core.Storage().GetSecret(ctx, secret.ID)
	t.Logf("[claim 2] database: secret id=%d still exists=%v (lookup error=%v)", secret.ID, serr == nil, serr)
	if serr == nil {
		t.Logf("[claim 2] database: secret row: %+v", secretStillExists)
	}
}

// TestG80Sweep03_CreateAccessReviewCampaignProxy_LifecycleFieldsNormalised is
// claim 3: access_review_campaigns_proxy.go's CreateAccessReviewCampaignProxy
// (ARC-003) claims lifecycle fields (state/closed_by/closed_at/forced_incomplete)
// are unconditionally normalised to the freshly-opened state before
// persisting -- "a caller cannot inject a pre-closed or force-completed
// campaign via this route." Attack: a system.write-only caller submits a
// campaign with state=closed, closed_by=a different real user,
// closed_at=a real timestamp, forced_incomplete=true, and CreatedBy forged to
// a different user. Checked against the actual persisted database row, not
// the response body.
func TestG80Sweep03_CreateAccessReviewCampaignProxy_LifecycleFieldsNormalised(t *testing.T) {
	f := newG80SweepFixture(t)
	ctx := context.Background()

	forgedCloser, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "g80sweep03forgedcloser", Email: "g80sweep03forgedcloser@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	closedAt := time.Now().Add(-24 * time.Hour)

	status, body := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/access-review-campaigns", map[string]any{
		"project_id":        f.projectID,
		"name":              "g80sweep03-injected-campaign",
		"state":             "closed",
		"closed_by":         forgedCloser.ID,
		"closed_at":         closedAt,
		"forced_incomplete": true,
		"created_by":        forgedCloser.ID,
	})
	t.Logf("[claim 3] CreateAccessReviewCampaignProxy(system.write-only, injected state=closed/closed_by/forced_incomplete): status=%d body=%s", status, body)

	if status != http.StatusOK {
		return
	}
	var parsed struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))
	campaign, gerr := f.core.Storage().GetAccessReviewCampaign(ctx, parsed.Data.ID)
	require.NoError(t, gerr)
	t.Logf("[claim 3] database: campaign id=%d persisted row: %+v", parsed.Data.ID, campaign)
}

// TestG80Sweep04_CreateAccessReviewItemsProxy_DecisionStateStripped is claim
// 4: access_review_campaigns_proxy.go's CreateAccessReviewItemsProxy
// (ARC-004) claims any pre-supplied decision state is stripped -- "every
// newly created item must start pending regardless of what the caller sent."
// Attack: submit an item already decided "approved" with decided_by forged
// to a real user and a real decided_at timestamp. Checked against the
// persisted database row.
func TestG80Sweep04_CreateAccessReviewItemsProxy_DecisionStateStripped(t *testing.T) {
	f := newG80SweepFixture(t)
	ctx := context.Background()

	campaign, err := f.core.Storage().CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: f.projectID, Name: "g80sweep04-campaign", State: core.CampaignStateOpen, CreatedBy: f.adminID, CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	forgedDecider, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "g80sweep04forgeddecider", Email: "g80sweep04forgeddecider@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	decidedAt := time.Now().Add(-time.Hour)

	status, body := f.do(t, f.swToken, http.MethodPost,
		fmt.Sprintf("/api/v1/system/access-review-campaigns/%d/items", campaign.ID), map[string]any{
			"items": []map[string]any{
				{
					"principal_type": "user", "principal_id": f.adminID, "principal_name": "admin",
					"source": "direct", "access_level": "read", "environment_id": 0,
					"decision": "approved", "decided_by": forgedDecider.ID, "decided_at": decidedAt,
				},
			},
		})
	t.Logf("[claim 4] CreateAccessReviewItemsProxy(system.write-only, injected decision=approved/decided_by): status=%d body=%s", status, body)

	items, ierr := f.core.Storage().ListAccessReviewItems(ctx, campaign.ID)
	require.NoError(t, ierr)
	for _, item := range items {
		t.Logf("[claim 4] database: item id=%d persisted row: %+v", item.ID, item)
	}
}

// TestG80Sweep05And06_SSOLoginState_CreateThenConsume is claims 5 and 6
// together, since claim 5's own text asserts there is no policy decision to
// test in isolation (sso_state_proxy.go's CreateSSOLoginStateProxy: "a raw
// persist, no policy decision" -- the model carries no user/session identity
// field at all) and claim 6 (ConsumeSSOLoginStateProxy) is the one that
// matters: it claims the SAME atomic conditional-delete
// (`WHERE id = ? AND state = ?`) local_sso.go's own ConsumeSSOLoginState
// does, so a state can be consumed exactly once, and -- per this handler's
// own package-level claim elsewhere in this campaign -- identity is bound
// only at consume time via IdP-signed crypto, never by the state row alone.
// Attack for claim 5: does simply creating a state row via this endpoint
// grant ANY capability by itself (a session, a token, an identity
// association)? Attack for claim 6: create a state via the (system.write-gated)
// proxy, then consume it TWICE concurrently-in-sequence and check whether
// both consumes report success (double-spend) or only one does.
func TestG80Sweep05And06_SSOLoginState_CreateThenConsume(t *testing.T) {
	f := newG80SweepFixture(t)

	stateToken := "g80sweep0506-attacker-chosen-state-000000000000000000000001"
	status, body := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/sso-state", map[string]any{
		"state": stateToken, "nonce": "g80sweep0506-nonce", "provider": "g80sweep0506-provider",
		"return_to": "/dashboard", "expires_at": time.Now().Add(time.Hour),
	})
	t.Logf("[claim 5] CreateSSOLoginStateProxy(system.write-only, attacker-chosen state/nonce): status=%d body=%s", status, body)

	// storage.Storage exposes no standalone read for SSOLoginState (only
	// Create and single-use Consume) -- inspected via the consume path below
	// instead, which is the only way to observe the row's actual content.
	if status != http.StatusOK {
		return
	}

	status1, body1 := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/sso-state/consume", map[string]any{"state": stateToken})
	t.Logf("[claim 6] ConsumeSSOLoginStateProxy first consume: status=%d body=%s", status1, body1)
	status2, body2 := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/sso-state/consume", map[string]any{"state": stateToken})
	t.Logf("[claim 6] ConsumeSSOLoginStateProxy second consume (replay of the same state): status=%d body=%s", status2, body2)
}

// TestG80Sweep07_ConsumeWebAuthnSessionProxy_SingleUseAndExpiry is claim 7:
// webauthn_proxy.go's ConsumeWebAuthnSessionProxy claims the same atomic
// "UPDATE ... WHERE used_at IS NULL AND expires_at > ?" single-use guarantee
// local_webauthn.go's ConsumeWebAuthnSession applies locally, unchanged
// across this HTTP hop.
//
// NOTE on the handler's own comment: it states "No .UTC(): no BeforeSave
// hook normalizes models.WebAuthnSession.ExpiresAt, so writes ... and reads
// must share the same (local) Location convention." That is stale --
// models.WebAuthnSession DOES have a BeforeSave hook that normalizes
// ExpiresAt to UTC (models.go:603), and ConsumeWebAuthnSession itself calls
// `now = now.UTC()` before comparing (local_webauthn.go:163) regardless of
// what the handler passes. The comment's REASONING is wrong (pre-dates the
// UTC-normalization fix and was never updated); tested live below to
// confirm whether the CONCLUSION (safe) still holds anyway, or whether the
// stale reasoning also means a real gap.
//
// Attack 1 (single-use): create a real session via storage, consume it
// twice through the proxy -- second consume must fail.
// Attack 2 (expiry): create a session already expired 1 hour ago, attempt
// to consume it -- must fail, not silently accepted despite the timezone
// mismatch the comment describes.
func TestG80Sweep07_ConsumeWebAuthnSessionProxy_SingleUseAndExpiry(t *testing.T) {
	f := newG80SweepFixture(t)
	ctx := context.Background()

	// Attack 1: single-use.
	err := f.core.Storage().CreateWebAuthnSession(ctx, &models.WebAuthnSession{
		UserID: f.adminID, TokenHash: "g80sweep07-single-use-hash-000000000000000000000000000001",
		Purpose: "login", Data: []byte("{}"), ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	status1, body1 := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/webauthn/sessions/consume", map[string]any{
		"token_hash": "g80sweep07-single-use-hash-000000000000000000000000000001",
	})
	t.Logf("[claim 7] ConsumeWebAuthnSessionProxy first consume (real, unexpired session): status=%d body=%s", status1, body1)
	status2, body2 := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/webauthn/sessions/consume", map[string]any{
		"token_hash": "g80sweep07-single-use-hash-000000000000000000000000000001",
	})
	t.Logf("[claim 7] ConsumeWebAuthnSessionProxy second consume (replay): status=%d body=%s", status2, body2)

	// Attack 2: expiry, specifically probing the timezone-mismatch the
	// handler's stale comment describes -- ExpiresAt set 1 hour in the past
	// in this process's LOCAL time.
	err = f.core.Storage().CreateWebAuthnSession(ctx, &models.WebAuthnSession{
		UserID: f.adminID, TokenHash: "g80sweep07-expired-hash-0000000000000000000000000000001",
		Purpose: "login", Data: []byte("{}"), ExpiresAt: time.Now().Add(-time.Hour),
	})
	require.NoError(t, err)
	status3, body3 := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/webauthn/sessions/consume", map[string]any{
		"token_hash": "g80sweep07-expired-hash-0000000000000000000000000000001",
	})
	t.Logf("[claim 7] ConsumeWebAuthnSessionProxy consume of a session expired 1h ago: status=%d body=%s", status3, body3)
}

// TestG80Sweep08_TransitionMachineIdentityStateProxy_LegalityAndCreatedBy is
// claim 8: machine_identities_proxy.go's TransitionMachineIdentityStateProxy
// claims two things -- (a) core.IsValidMachineTransition (the same legality
// table core.TransitionMachineIdentity's transaction enforces) blocks an
// illegal transition (e.g. un-revoking a revoked identity), closing the
// #1542-shape raw-CAS-with-no-legality-check gap; (b) CreatedBy is preserved
// from the EXISTING row, not taken from the wire, closing a second reachable
// path to the same forgeable-CreatedBy class CreateMachineIdentityProxy was
// separately fixed against. Both tested live against the database, not the
// response body alone.
func TestG80Sweep08_TransitionMachineIdentityStateProxy_LegalityAndCreatedBy(t *testing.T) {
	f := newG80SweepFixture(t)
	ctx := context.Background()

	machine, err := f.core.CreateMachineIdentity(ctx, f.projectID, "g80sweep08-machine", core.MachineTypeService, "", "", f.adminID)
	require.NoError(t, err)
	require.Equal(t, core.MachineActive, machine.State, "fixture assumption: CreateMachineIdentity starts a machine Active")

	// Attack (a): revoke it for real first (a legitimate transition), then
	// attempt to transition BACK from revoked to active -- must be illegal.
	revoked, err := f.core.Storage().TransitionMachineIdentityState(ctx, &models.MachineIdentity{
		ID: machine.ID, ProjectID: f.projectID, Name: machine.Name, IdentityType: machine.IdentityType,
		State: core.MachineRevoked, CreatedBy: machine.CreatedBy, CreatedAt: machine.CreatedAt, UpdatedAt: time.Now(),
	}, core.MachineActive)
	require.NoError(t, err)
	require.True(t, revoked, "fixture setup: the legitimate active->revoked transition must succeed")

	forgedCreator, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "g80sweep08forgedcreator", Email: "g80sweep08forgedcreator@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	status, body := f.do(t, f.swToken, http.MethodPut,
		fmt.Sprintf("/api/v1/system/machine-identities/%d/transition", machine.ID), map[string]any{
			"from_state": "revoked",
			"machine_identity": map[string]any{
				"id": machine.ID, "project_id": f.projectID, "name": machine.Name, "identity_type": machine.IdentityType,
				"state": "active", "created_by": forgedCreator.ID,
			},
		})
	t.Logf("[claim 8a] TransitionMachineIdentityStateProxy(revoked -> active, illegal un-revoke): status=%d body=%s", status, body)

	current, gerr := f.core.Storage().GetMachineIdentity(ctx, machine.ID)
	require.NoError(t, gerr)
	t.Logf("[claim 8a] database: machine id=%d state=%q (must still be revoked if the transition was correctly refused)", machine.ID, current.State)
	t.Logf("[claim 8b] database: machine id=%d created_by=%d (original=%d, forged attempt=%d)",
		machine.ID, current.CreatedBy, machine.CreatedBy, forgedCreator.ID)
}

// TestG80Sweep09_UpdateMachineIdentityCredentialProxy_OnlyClassificationApplies
// is claim 9: machine_identities_proxy.go's UpdateMachineIdentityCredentialProxy
// claims it fetches the existing credential row and applies ONLY
// Classification from the wire body, never trusting a full caller-supplied
// replacement row -- specifically closing "un-revoke any credential,
// overwrite TokenHash to hijack identity/roles, clear ExpiresAt." Attack: a
// system.write-only caller submits an update to an ALREADY-REVOKED
// credential with revoked=false (un-revoke attempt), a forged token_hash,
// and expires_at cleared (nil). Checked against the persisted database row.
func TestG80Sweep09_UpdateMachineIdentityCredentialProxy_OnlyClassificationApplies(t *testing.T) {
	f := newG80SweepFixture(t)
	ctx := context.Background()

	machine, err := f.core.CreateMachineIdentity(ctx, f.projectID, "g80sweep09-machine", core.MachineTypeService, "", "", f.adminID)
	require.NoError(t, err)
	originalExpiry := time.Now().Add(30 * 24 * time.Hour)
	cred, err := f.core.Storage().CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
		MachineIdentityID: machine.ID, Name: "g80sweep09-cred", TokenHash: "g80sweep09-original-hash-00000000000000000000000000000001",
		TokenPrefix: "mid_orig", Revoked: true, ExpiresAt: &originalExpiry,
	})
	require.NoError(t, err)

	status, body := f.do(t, f.swToken, http.MethodPut,
		fmt.Sprintf("/api/v1/system/machine-credentials/%d", cred.ID), map[string]any{
			"id": cred.ID, "machine_identity_id": machine.ID, "name": "g80sweep09-cred",
			"token_hash":  "g80sweep09-FORGED-hash-00000000000000000000000000000002",
			"revoked":     false,
			"expires_at":  nil,
			"classification": "internal",
		})
	t.Logf("[claim 9] UpdateMachineIdentityCredentialProxy(un-revoke + forged token_hash + cleared expiry): status=%d body=%s", status, body)

	current, gerr := f.core.Storage().GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, gerr)
	t.Logf("[claim 9] database: credential id=%d persisted row: %+v", cred.ID, current)
	t.Logf("[claim 9] database: TokenHash forged=%v (must still be original), Revoked=%v (must still be true), ExpiresAt-cleared=%v (must still be set)",
		current.TokenHash == "g80sweep09-FORGED-hash-00000000000000000000000000000002", current.Revoked, current.ExpiresAt == nil)
}

// TestG80Sweep10_DeleteProjectProxy_SystemWriteOnlyCannotDelete is claim 10:
// project_catalog_proxy.go's DeleteProjectProxy itself makes no authority
// claim at all -- "the plain, unconditional cascade... backing the CALLING
// server's force=true path." The ceiling (if any) lives entirely at the
// router level. Attack: a system.write-only caller (no secrets.delete
// anywhere) attempts to delete a real project via this route.
func TestG80Sweep10_DeleteProjectProxy_SystemWriteOnlyCannotDelete(t *testing.T) {
	f := newG80SweepFixture(t)
	ctx := context.Background()

	project, err := f.core.CreateProject(ctx, "g80sweep10-target-project", "")
	require.NoError(t, err)

	status, body := f.do(t, f.swToken, http.MethodDelete, fmt.Sprintf("/api/v1/system/projects/%d", project.ID), nil)
	t.Logf("[claim 10] DeleteProjectProxy(system.write-only, no secrets.delete): status=%d body=%s", status, body)

	stillExists, gerr := f.core.Storage().GetProject(ctx, project.ID)
	t.Logf("[claim 10] database: project id=%d still exists=%v (lookup error=%v)", project.ID, gerr == nil, gerr)
	if gerr == nil {
		t.Logf("[claim 10] database: project row: %+v", stillExists)
	}
}

// TestG80Sweep11_RemoveGlobalAdminRoleGuardedProxy_AuthorityAndLastAdmin is
// claim 11: rbac_role_grants_proxy.go's RemoveGlobalAdminRoleGuardedProxy
// claims (a) removing a global-admin role grant requires roles.assign at
// global scope, and (b) the underlying core.RemoveUserRole call enforces the
// last-global-admin lockout (ErrWouldStrandLastAdmin), routed through the
// SAME core.RemoveUserRole a legitimate DELETE /api/v1/user-roles caller
// uses. Two attacks: (a) a system.write-only caller (no roles.assign)
// attempts to remove a second admin's system_admin grant; (b) a genuine
// roles.assign holder attempts to remove the LAST global admin's own
// system_admin grant (the bootstrap admin, with the second admin's grant
// already gone from attack (a) or never having existed).
func TestG80Sweep11_RemoveGlobalAdminRoleGuardedProxy_AuthorityAndLastAdmin(t *testing.T) {
	f := newG80SweepFixture(t)
	ctx := context.Background()

	adminRole, err := f.core.Storage().GetRoleByName(ctx, "system_admin")
	require.NoError(t, err)
	secondAdmin, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "g80sweep11secondadmin", Email: "g80sweep11secondadmin@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	require.NoError(t, f.core.AssignRoleToUser(ctx, "g80sweep11secondadmin@example.com", "system_admin"))

	// Attack (a): system.write-only, no roles.assign.
	status1, body1 := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/rbac/global-admin-role/remove-guarded", map[string]any{
		"user_id": secondAdmin.ID, "role_id": adminRole.ID,
	})
	t.Logf("[claim 11a] RemoveGlobalAdminRoleGuardedProxy(system.write-only, no roles.assign): status=%d body=%s", status1, body1)
	roleIDs1, _ := f.core.Storage().GetUserRoleIDsAt(ctx, secondAdmin.ID, core.Scope{})
	t.Logf("[claim 11a] database: second admin's global-scope role IDs=%v (system_admin id=%d, must still be present if refused)", roleIDs1, adminRole.ID)

	// Attack (b): a genuine roles.assign holder attempts to strand the last
	// admin -- remove the bootstrap admin's own admin-tier grant while it is
	// the ONLY remaining one. First: remove the second admin's grant via a
	// TRUSTED setup path (direct core call, not the route under test) so
	// only the bootstrap admin remains admin-tier. Then discover what
	// role(s) the bootstrap admin actually holds (queried live, not
	// assumed) and attempt to remove one via the guarded route.
	require.NoError(t, f.core.RemoveUserRole(ctx, f.adminID, secondAdmin.ID, adminRole.ID, core.Scope{}))
	bootstrapRoleIDs, err := f.core.Storage().GetUserRoleIDsAt(ctx, f.adminID, core.Scope{})
	require.NoError(t, err)
	require.NotEmpty(t, bootstrapRoleIDs, "fixture assumption: the bootstrap admin holds at least one global-scope role")
	bootstrapRoleID := bootstrapRoleIDs[0]
	t.Logf("[claim 11b] bootstrap admin's actual global-scope role IDs=%v -- targeting role id=%d for the last-admin removal attempt", bootstrapRoleIDs, bootstrapRoleID)

	assignToken := createSystemWriteAndRolesAssignToken(t, f.core)
	status2, body2 := f.do(t, assignToken, http.MethodPost, "/api/v1/system/rbac/global-admin-role/remove-guarded", map[string]any{
		"user_id": f.adminID, "role_id": bootstrapRoleID,
	})
	t.Logf("[claim 11b] RemoveGlobalAdminRoleGuardedProxy(roles.assign holder, target=LAST remaining global admin's own role): status=%d body=%s", status2, body2)
	roleIDs2, _ := f.core.Storage().GetUserRoleIDsAt(ctx, f.adminID, core.Scope{})
	t.Logf("[claim 11b] database: bootstrap admin's global-scope role IDs=%v (must still contain role id=%d if the last-admin guard held)", roleIDs2, bootstrapRoleID)
}

// TestG80Sweep12_RevokeBreakGlassActivationProxy_RoleActuallyRemoved is claim
// 12: break_glass_proxy.go's RevokeBreakGlassActivationProxy claims a
// successful revoke actually removes the elevated role grant from
// user_roles, not merely flips the activation row's status field. Attack:
// activate a real break-glass grant (real role, real user), revoke it, then
// check user_roles directly for whether the grant is actually gone --
// exactly the check this campaign's own top finding required (a status flip
// with Authorize still returning true because the grant was never removed).
func TestG80Sweep12_RevokeBreakGlassActivationProxy_RoleActuallyRemoved(t *testing.T) {
	f := newG80SweepFixture(t)
	ctx := context.Background()

	role, err := f.core.Storage().CreateRole(ctx, &models.Role{Name: "g80sweep12-emergency-role"})
	require.NoError(t, err)
	scope := core.Scope{ProjectID: f.projectID}
	require.NoError(t, f.core.Storage().AssignRole(ctx, f.adminID, role.ID, scope))
	roleIDsBefore, err := f.core.Storage().GetUserRoleIDsAt(ctx, f.adminID, scope)
	require.NoError(t, err)
	require.Contains(t, roleIDsBefore, role.ID, "fixture setup: role grant must exist before the revoke")

	activation, err := f.core.Storage().CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: f.projectID, UserID: f.adminID, RoleID: role.ID, RoleName: role.Name,
		Justification: "g80 final sweep regression check", State: "active",
	})
	require.NoError(t, err)

	status, body := f.do(t, f.swToken, http.MethodPost,
		fmt.Sprintf("/api/v1/system/break-glass/%d/revoke", activation.ID), map[string]any{
			"revoked_by": f.adminID, "revoked_at": time.Now(),
		})
	t.Logf("[claim 12] RevokeBreakGlassActivationProxy(genuinely active activation): status=%d body=%s", status, body)

	roleIDsAfter, err := f.core.Storage().GetUserRoleIDsAt(ctx, f.adminID, scope)
	require.NoError(t, err)
	t.Logf("[claim 12] database: user_roles after revoke=%v (must NOT contain role id=%d if the grant was actually removed, not just the activation flipped)", roleIDsAfter, role.ID)
}

// TestG80Sweep13_RecordLoginAttemptProxy_ValidatesIPAndFutureTimestamp is
// claim 13: login_attempts_proxy.go's RecordLoginAttemptProxy claims it
// routes through core.RecordLoginAttemptRelay, which validates the ip key
// (a known prefix, e.g. "pwreset:"/"sso:", followed by a real IP -- or a
// bare real IP for ordinary login -- rejecting anything else, e.g. a
// garbage/non-IP remainder that isn't one of the relay's own supported
// namespaces) and REJECTS (not clamps) a future `at` timestamp. Three
// checks: (a) a known-prefix key with a REAL IP is legitimately accepted
// (the relay's own documented multi-namespace support, not a bypass); (b) a
// bare garbage string with no valid IP anywhere in it is rejected; (c) a
// far-future `at` timestamp intended to create a permanent, unclearable
// lockout row is rejected outright.
func TestG80Sweep13_RecordLoginAttemptProxy_ValidatesIPAndFutureTimestamp(t *testing.T) {
	f := newG80SweepFixture(t)

	status1, body1 := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/login-attempts", map[string]any{
		"ip": "pwreset:203.0.113.55", "at": time.Now(),
	})
	t.Logf("[claim 13a] RecordLoginAttemptProxy(known-prefix key, real IP, ip=\"pwreset:203.0.113.55\"): status=%d body=%s (expected: legitimately accepted, this IS the relay's documented multi-namespace support)", status1, body1)

	status2, body2 := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/login-attempts", map[string]any{
		"ip": "not-a-real-ip-at-all", "at": time.Now(),
	})
	t.Logf("[claim 13b] RecordLoginAttemptProxy(garbage non-IP key, no valid prefix+IP anywhere): status=%d body=%s", status2, body2)

	status3, body3 := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/login-attempts", map[string]any{
		"ip": "203.0.113.56", "at": time.Now().Add(50 * 365 * 24 * time.Hour),
	})
	t.Logf("[claim 13c] RecordLoginAttemptProxy(far-future timestamp, +50y): status=%d body=%s", status3, body3)
}

// TestG80Sweep14_CreateSetupTokenProxy_RequiresUsersWrite is claim 14:
// setup_tokens_proxy.go's CreateSetupTokenProxy claims every caller must
// hold users.write (global scope, matching the human-facing routes) before
// this handler persists a token, unconditionally. This is the exact exploit
// an independent verification session reported live against clean
// origin/main earlier in this campaign (mint as system.write-only, redeem
// unauthenticated, confirmed account takeover) -- re-run here as part of
// this sweep's own record, not cited from memory. Attack: a system.write-only
// caller who knows a real target's email mints a setup token and attempts
// to redeem it unauthenticated.
func TestG80Sweep14_CreateSetupTokenProxy_RequiresUsersWrite(t *testing.T) {
	f := newG80SweepFixture(t)
	ctx := context.Background()

	target, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "g80sweep14target", Email: "g80sweep14target@example.com", Password: "OriginalStr0ng!Passw0rd#1",
	})
	require.NoError(t, err)

	sum := sha256.Sum256([]byte("kx_setup_g80sweep14_attacker_chosen_000000000000000000000001"))
	tokenHash := hex.EncodeToString(sum[:])
	status1, body1 := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/setup-tokens", map[string]any{
		"token_hash": tokenHash, "purpose": "account_setup", "subject_email": target.Email,
		"subject_user_id": target.ID, "expires_at": time.Now().Add(time.Hour),
	})
	t.Logf("[claim 14] CreateSetupTokenProxy(system.write-only, known target email): status=%d body=%s", status1, body1)
	if status1 != http.StatusOK {
		return
	}
	status2, body2 := f.do(t, "", http.MethodPost, "/auth/setup/consume", map[string]any{
		"token": "kx_setup_g80sweep14_attacker_chosen_000000000000000000000001", "password": "AttackerChosenStr0ng!Passw0rd#2",
	})
	t.Logf("[claim 14] unauthenticated redeem: status=%d body=%s", status2, body2)
}
