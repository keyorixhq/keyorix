// system_write_ceiling_table_users_test.go is system_write_ceiling_table_test.go's
// sibling for the /api/v1/system/users/{id}/personal-access-tokens/revoke-all
// and /api/v1/system/users/{id}/sessions/delete-except routes
// (users_credentials_proxy.go) — kept as a separate file rather than folded
// into that one because those routes are, deliberately, NOT gated the same
// way as every other route that file covers: they require "users.write"
// authority for a direct caller (derived from the ONLY caller-authority check
// that actually governs a user deactivation today — see
// internal/core/users.go's requireUserCredentialsRevokeAuthority doc), not
// merely the group's blanket system.write-or-node-credential baseline. This
// file therefore exercises THREE caller shapes per route, not two: a
// system.write-ONLY human (must now be DENIED — the ceiling this fix adds;
// system.write alone satisfies the /system group's own blanket gate but not
// this fix's additional check), a human holding BOTH system.write AND
// users.write (must succeed — proves the permission that SHOULD work
// actually does; users.write alone can never reach this fix's own check at
// all, since the group's gate rejects it first), and a genuine
// node-credential relay (still succeeds — the same documented, tracked
// HALF-FIXED gap as CreateOIDCBindingProxy/CreateMachineIdentityCredentialProxy
// in system_write_ceiling_table_test.go).
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

// userCredentialsCeilingFixtures holds every row this file's requests
// reference, created once per test run.
type userCredentialsCeilingFixtures struct {
	serverURL       string
	sysWriteToken   string // holds ONLY system.write — must be denied by the new ceiling
	usersWriteToken string // holds system.write + users.write — must be allowed
	nodeToken       string // genuine node-credential relay — still allowed (known gap)
	targetUserID    uint   // the user whose PATs/sessions the requests act on
}

// createUsersWriteToken mirrors createSystemWriteOnlyToken
// (system_write_ceiling_test.go), but grants BOTH "system.write" (required to
// pass the /system route group's own blanket gate before a request ever
// reaches users_credentials_proxy.go's handlers at all) AND "users.write"
// (the additional ceiling this fix's handlers themselves enforce) — the
// combination this file's positive rows prove actually authorizes. A
// caller holding users.write alone, with no system.write, would be rejected
// by the route group's gate before this fix's own check is ever reached, so
// testing that narrower combination would not exercise this fix.
func createUsersWriteToken(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	ctx := context.Background()

	_, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "users_write_holder", Email: "users_write_holder@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	require.NoError(t, c.RemoveRoleFromUser(ctx, "users_write_holder@example.com", "system_viewer"))

	role, err := c.Storage().CreateRole(ctx, &models.Role{
		Name: "ceiling_test_users_and_system_writer", Description: "test-only role: system.write + users.write",
	})
	require.NoError(t, err)

	perms, err := c.ListPermissions(ctx)
	require.NoError(t, err)
	var systemWriteID, usersWriteID uint
	for _, p := range perms {
		switch p.Name {
		case "system.write":
			systemWriteID = p.ID
		case "users.write":
			usersWriteID = p.ID
		}
	}
	require.NotZero(t, systemWriteID, "system.write permission must already be seeded by bootstrap")
	require.NotZero(t, usersWriteID, "users.write permission must already be seeded by bootstrap")

	require.NoError(t, c.AssignPermissionToRole(ctx, 0, role.ID, systemWriteID))
	require.NoError(t, c.AssignPermissionToRole(ctx, 0, role.ID, usersWriteID))
	require.NoError(t, c.AssignRoleToUser(ctx, "users_write_holder@example.com", "ceiling_test_users_and_system_writer"))

	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "users_write_holder", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	return sess.SessionToken
}

func setupUserCredentialsCeilingFixtures(t *testing.T) userCredentialsCeilingFixtures {
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
	createTestToken(t, testCore) // bootstrap admin + seed roles/permissions (incl. system.write/users.write)
	sysWriteToken := createSystemWriteOnlyToken(t, testCore)
	usersWriteToken := createUsersWriteToken(t, testCore)
	nodeToken := createNodeToken(t, testCore)

	target, err := testCore.GetUserByEmail(ctx, "sys_write_only@example.com")
	require.NoError(t, err)

	return userCredentialsCeilingFixtures{
		serverURL:       server.URL,
		sysWriteToken:   sysWriteToken,
		usersWriteToken: usersWriteToken,
		nodeToken:       nodeToken,
		targetUserID:    target.ID,
	}
}

// doUserCredentialsCeilingRequestAs mirrors doCeilingRequestAs
// (system_write_ceiling_table_test.go) exactly, kept as its own copy since
// this file deliberately does not depend on that file's ceilingTableFixtures
// type (see the package doc above for why).
func doUserCredentialsCeilingRequestAs(t *testing.T, f userCredentialsCeilingFixtures, token, method, path string, body any) (int, string) {
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

// TestSystemWriteCeiling_RevokeAllPersonalAccessTokensForUserProxy_RequiresUsersWriteAuthority
// is the RED-before/GREEN-after proof: a caller holding ONLY system.write
// (which satisfies the /system route group's own blanket gate) must now be
// denied — the new users.write ceiling this fix adds on top of that baseline.
func TestSystemWriteCeiling_RevokeAllPersonalAccessTokensForUserProxy_RequiresUsersWriteAuthority(t *testing.T) {
	f := setupUserCredentialsCeilingFixtures(t)
	path := fmt.Sprintf("/api/v1/system/users/%d/personal-access-tokens/revoke-all", f.targetUserID)
	status, body := doUserCredentialsCeilingRequestAs(t, f, f.sysWriteToken, http.MethodPost, path, nil)
	t.Logf("RevokeAllPersonalAccessTokensForUserProxy(system.write only): status=%d body=%s", status, body)
	require.Equal(t, http.StatusForbidden, status,
		"CEILING VIOLATED: a system.write-only caller must be denied — revoking a user's personal access tokens "+
			"requires users.write authority (core.RevokeAllPersonalAccessTokensForUser's check), which this caller does not hold")
}

// TestSystemWriteCeiling_RevokeAllPersonalAccessTokensForUserProxy_UsersWriteSucceeds
// proves the OTHER half: a caller holding users.write (the derived ceiling)
// succeeds, so the fix is a real permission check, not an accidental blanket denial.
func TestSystemWriteCeiling_RevokeAllPersonalAccessTokensForUserProxy_UsersWriteSucceeds(t *testing.T) {
	f := setupUserCredentialsCeilingFixtures(t)
	path := fmt.Sprintf("/api/v1/system/users/%d/personal-access-tokens/revoke-all", f.targetUserID)
	status, body := doUserCredentialsCeilingRequestAs(t, f, f.usersWriteToken, http.MethodPost, path, nil)
	t.Logf("RevokeAllPersonalAccessTokensForUserProxy(users.write): status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status, "a users.write-holding caller must be allowed — that is the derived ceiling")
}

// TestSystemWriteCeiling_RevokeAllPersonalAccessTokensForUserProxy_NodeCredential_StillBypassesUsersWriteCheck
// pins the KNOWN, OPEN gap: a node credential still reaches the raw
// storage.RevokeAllPersonalAccessTokensForUser call unconditionally
// (isNodeCredentialRequest branch), so it can still revoke any user's PATs
// with no authority check and no audit event.
func TestSystemWriteCeiling_RevokeAllPersonalAccessTokensForUserProxy_NodeCredential_StillBypassesUsersWriteCheck(t *testing.T) {
	f := setupUserCredentialsCeilingFixtures(t)
	path := fmt.Sprintf("/api/v1/system/users/%d/personal-access-tokens/revoke-all", f.targetUserID)
	status, body := doUserCredentialsCeilingRequestAs(t, f, f.nodeToken, http.MethodPost, path, nil)
	t.Logf("RevokeAllPersonalAccessTokensForUserProxy(node credential): status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status,
		"KNOWN GAP (not intended, pending ADR-085's wire-identity decision): a node credential still revokes a "+
			"user's personal access tokens with no users.write-authority check and no audit event — "+
			"isNodeCredentialRequest routes it around core.RevokeAllPersonalAccessTokensForUser entirely, on an "+
			"unverified relay-trust assumption. If this ever goes non-200, update this assertion — that would "+
			"mean the gap closed, which is the goal, not a regression.")
}

// TestSystemWriteCeiling_DeleteSessionsForUserExceptProxy_RequiresUsersWriteAuthority
// is DeleteSessionsForUserExceptProxy's RED-before/GREEN-after row, mirroring
// the RevokeAllPersonalAccessTokensForUserProxy row above exactly.
func TestSystemWriteCeiling_DeleteSessionsForUserExceptProxy_RequiresUsersWriteAuthority(t *testing.T) {
	f := setupUserCredentialsCeilingFixtures(t)
	path := fmt.Sprintf("/api/v1/system/users/%d/sessions/delete-except", f.targetUserID)
	status, body := doUserCredentialsCeilingRequestAs(t, f, f.sysWriteToken, http.MethodPost, path, map[string]any{"except_session_id": 0})
	t.Logf("DeleteSessionsForUserExceptProxy(system.write only): status=%d body=%s", status, body)
	require.Equal(t, http.StatusForbidden, status,
		"CEILING VIOLATED: a system.write-only caller must be denied — deleting a user's sessions requires "+
			"users.write authority (core.DeleteSessionsForUserExcept's check), which this caller does not hold")
}

// TestSystemWriteCeiling_DeleteSessionsForUserExceptProxy_UsersWriteSucceeds
// proves the OTHER half for DeleteSessionsForUserExceptProxy.
func TestSystemWriteCeiling_DeleteSessionsForUserExceptProxy_UsersWriteSucceeds(t *testing.T) {
	f := setupUserCredentialsCeilingFixtures(t)
	path := fmt.Sprintf("/api/v1/system/users/%d/sessions/delete-except", f.targetUserID)
	status, body := doUserCredentialsCeilingRequestAs(t, f, f.usersWriteToken, http.MethodPost, path, map[string]any{"except_session_id": 0})
	t.Logf("DeleteSessionsForUserExceptProxy(users.write): status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status, "a users.write-holding caller must be allowed — that is the derived ceiling")
}

// TestSystemWriteCeiling_DeleteSessionsForUserExceptProxy_NodeCredential_StillBypassesUsersWriteCheck
// pins the KNOWN, OPEN gap for DeleteSessionsForUserExceptProxy, mirroring the
// RevokeAllPersonalAccessTokensForUserProxy node-credential row above.
func TestSystemWriteCeiling_DeleteSessionsForUserExceptProxy_NodeCredential_StillBypassesUsersWriteCheck(t *testing.T) {
	f := setupUserCredentialsCeilingFixtures(t)
	path := fmt.Sprintf("/api/v1/system/users/%d/sessions/delete-except", f.targetUserID)
	status, body := doUserCredentialsCeilingRequestAs(t, f, f.nodeToken, http.MethodPost, path, map[string]any{"except_session_id": 0})
	t.Logf("DeleteSessionsForUserExceptProxy(node credential): status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status,
		"KNOWN GAP (not intended, pending ADR-085's wire-identity decision): a node credential still deletes a "+
			"user's sessions with no users.write-authority check and no audit event — isNodeCredentialRequest "+
			"routes it around core.DeleteSessionsForUserExcept entirely, on an unverified relay-trust assumption. "+
			"If this ever goes non-200, update this assertion — that would mean the gap closed, which is the "+
			"goal, not a regression.")
}
