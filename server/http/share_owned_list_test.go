// share_owned_list_test.go — SHARE-3: a project-only owner can list (and revoke) the
// shares they created. GET /api/v1/shares/owned, driven through the real router with
// real session tokens (auth middleware -> RequirePermissionInAnyScope -> handler ->
// core.ListOwnedShareViews).
//
// Before it, the Sharing Management page loaded GET /api/v1/shares, gated on GLOBAL
// secrets.read, so a project_admin of P could share P's secrets but got 403 on the
// page that lists and revokes them (SESSION-SHARE-2's NEEDS ANDREI).
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ownedShareFixture struct {
	*recipientFixture
	// olga (project_admin of P and of payments) owns one secret in each and shares
	// both; wendy (secret_writer at P) owns one in P and shares it with alice.
	olgaShareP, olgaSharePayments, wendyShareP uint
}

func newOwnedShareFixture(t *testing.T) *ownedShareFixture {
	t.Helper()
	f := &ownedShareFixture{recipientFixture: newRecipientFixture(t)}
	ctx := context.Background()
	c := f.d.c
	require.NoError(t, c.AddProjectMember(ctx, f.d.adminID, f.otherProjectID, f.ownerID, "project_admin", false))

	envOf := func(projectID uint) uint {
		envs, err := c.ListEnvironments(ctx)
		require.NoError(t, err)
		for _, e := range envs {
			if e.ProjectID == projectID {
				return e.ID
			}
		}
		t.Fatalf("project %d has no environment", projectID)
		return 0
	}
	secret := func(name string, projectID, ownerID uint, owner string) uint {
		s, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: name, Value: []byte("v1"), ProjectID: projectID, EnvironmentID: envOf(projectID),
			Type: "generic", CreatedBy: owner, OwnerID: ownerID,
		})
		require.NoError(t, err)
		return s.ID
	}
	share := func(tok string, secretID, recipient uint) uint {
		code, raw := doMachineRequest(t, f.d.srv, tok, http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/share", secretID),
			[]byte(fmt.Sprintf(`{"recipient_id":%d,"is_group":false,"permission":"read"}`, recipient)))
		require.Equal(t, http.StatusCreated, code, raw)
		var out struct {
			Data struct {
				ID uint `json:"id"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
		require.NotZero(t, out.Data.ID, raw)
		return out.Data.ID
	}
	f.olgaShareP = share(f.ownerTok, secret("olga-p", f.d.projectID, f.ownerID, "olga"), f.d.aliceID)
	f.olgaSharePayments = share(f.ownerTok, secret("olga-pay", f.otherProjectID, f.ownerID, "olga"), f.ids["frank"])
	f.wendyShareP = share(f.writerTok, secret("wendy-p", f.d.projectID, f.ids["wendy"], "wendy"), f.d.aliceID)
	return f
}

type ownedShareResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		Data       []core.ShareView `json:"data"`
		Total      int              `json:"total"`
		Page       int              `json:"page"`
		PageSize   int              `json:"pageSize"`
		TotalPages int              `json:"totalPages"`
	} `json:"data"`
}

func (f *ownedShareFixture) owned(t *testing.T, tok, query string) (int, ownedShareResponse, string) {
	t.Helper()
	code, raw := doMachineRequest(t, f.d.srv, tok, http.MethodGet, "/api/v1/shares/owned"+query, nil)
	var out ownedShareResponse
	_ = json.Unmarshal([]byte(raw), &out)
	return code, out, raw
}

func shareIDs(views []core.ShareView) []uint {
	out := make([]uint, 0, len(views))
	for _, v := range views {
		out = append(out, v.ID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// The bug, stated as the user hits it: the page's list is 403 for the owner.
func TestOwnedShares_ProjectOnlyOwnerIsRefusedTheGlobalList(t *testing.T) {
	f := newOwnedShareFixture(t)
	code, raw := doMachineRequest(t, f.d.srv, f.ownerTok, http.MethodGet, "/api/v1/shares", nil)
	assert.Equal(t, http.StatusForbidden, code, "GET /shares stays a global secrets.read route: %s", raw)
}

func TestOwnedShares_OwnerSeesOwnSharesOnly(t *testing.T) {
	f := newOwnedShareFixture(t)
	code, out, raw := f.owned(t, f.ownerTok, "")
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, []uint{f.olgaShareP, f.olgaSharePayments}, shareIDs(out.Data.Data), raw)
	assert.Equal(t, 2, out.Data.Total)
	for _, v := range out.Data.Data {
		assert.Equal(t, "olga", v.CreatedBy, raw)
	}
	assert.NotContains(t, raw, `"createdBy":"wendy"`, "wendy's share in the same project is not olga's")

	// wendy, the other owner in P, sees hers and not olga's.
	code, out, raw = f.owned(t, f.writerTok, "")
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, []uint{f.wendyShareP}, shareIDs(out.Data.Data), raw)

	// alice RECEIVED two shares and created none: received shares are not listed.
	code, out, raw = f.owned(t, f.viewerTok, "")
	require.Equal(t, http.StatusOK, code, raw)
	assert.Empty(t, out.Data.Data, raw)
	assert.Equal(t, 0, out.Data.Total)
}

func TestOwnedShares_RemovalFromProjectHidesItsShares(t *testing.T) {
	f := newOwnedShareFixture(t)
	ctx := context.Background()
	// P must keep an administrator once olga leaves it (the last-admin guard).
	require.NoError(t, f.d.c.AddProjectMember(ctx, f.d.adminID, f.d.projectID, f.d.bobID, "project_admin", false))
	require.NoError(t, f.d.c.RemoveProjectMember(ctx, f.d.adminID, f.d.projectID, f.ownerID))

	code, out, raw := f.owned(t, f.ownerTok, "")
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, []uint{f.olgaSharePayments}, shareIDs(out.Data.Data), "the share in P must vanish once olga leaves P: %s", raw)

	require.NoError(t, f.d.c.RemoveProjectMember(ctx, f.d.adminID, f.otherProjectID, f.ownerID))
	code, out, raw = f.owned(t, f.ownerTok, "")
	assert.Equal(t, http.StatusForbidden, code, "no project role left, so no secrets.read anywhere: %s", raw)
	assert.Equal(t, core.OwnedShareListDeniedMessage, out.Message, raw)

	// Back in P: the share is still there (removal hid it, it did not revoke it).
	require.NoError(t, f.d.c.AddProjectMember(ctx, f.d.adminID, f.d.projectID, f.ownerID, "project_admin", false))
	code, out, raw = f.owned(t, f.ownerTok, "")
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, []uint{f.olgaShareP}, shareIDs(out.Data.Data), raw)
}

// Same paging and shape as GET /api/v1/shares (data/total/page/pageSize/totalPages,
// ?secretId=, ?recipientType=).
func TestOwnedShares_SameShapeAndPagingAsGlobalList(t *testing.T) {
	f := newOwnedShareFixture(t)
	var seen []uint
	for page := 1; page <= 2; page++ {
		code, out, raw := f.owned(t, f.ownerTok, fmt.Sprintf("?page=%d&pageSize=1", page))
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, 2, out.Data.Total)
		assert.Equal(t, 1, out.Data.PageSize)
		assert.Equal(t, page, out.Data.Page)
		assert.Equal(t, 2, out.Data.TotalPages)
		seen = append(seen, shareIDs(out.Data.Data)...)
	}
	sort.Slice(seen, func(i, j int) bool { return seen[i] < seen[j] })
	assert.Equal(t, []uint{f.olgaShareP, f.olgaSharePayments}, seen, "pages must partition the result")

	_, out, raw := f.owned(t, f.ownerTok, "?recipientType=group")
	assert.Empty(t, out.Data.Data, raw)

	code, raw := doMachineRequest(t, f.d.srv, f.ownerTok, http.MethodGet, "/api/v1/shares/owned", nil)
	require.Equal(t, http.StatusOK, code)
	var envelope struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &envelope))
	keys := make([]string, 0)
	for k := range envelope.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	assert.Equal(t, []string{"data", "page", "pageSize", "total", "totalPages"}, keys)
}

// A user with no secrets.read anywhere gets the uniform 403 with the reason.
func TestOwnedShares_NoProjectRoleGets403WithReason(t *testing.T) {
	f := newOwnedShareFixture(t)
	code, out, raw := f.owned(t, f.outsiderTok, "")
	assert.Equal(t, http.StatusForbidden, code, raw)
	assert.Equal(t, core.OwnedShareListDeniedMessage, out.Message, raw)
	assert.NotContains(t, raw, "olga")
}

// Global admins keep today's GET /api/v1/shares, and the owner-scoped rule does not
// widen for them on the new route either.
func TestOwnedShares_GlobalAdminPathUnchanged(t *testing.T) {
	f := newOwnedShareFixture(t)
	f.d.makeAdminMember(t)
	adminShare := f.d.shareOK(t, f.ids["carol"], "read")

	code, raw := doMachineRequest(t, f.d.srv, f.d.adminTok, http.MethodGet, "/api/v1/shares", nil)
	require.Equal(t, http.StatusOK, code, raw)
	var global ownedShareResponse
	require.NoError(t, json.Unmarshal([]byte(raw), &global))
	assert.Equal(t, []uint{adminShare}, shareIDs(global.Data.Data), "GET /shares: the admin's own shares, as before: %s", raw)

	code, out, raw := f.owned(t, f.d.adminTok, "")
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, []uint{adminShare}, shareIDs(out.Data.Data), "global secrets.read adds nobody else's shares here: %s", raw)
}

// Item 2: the owner revokes from the list as a project-only member; the share leaves it.
func TestOwnedShares_ProjectOnlyOwnerRevokesFromTheList(t *testing.T) {
	f := newOwnedShareFixture(t)
	code, raw := doMachineRequest(t, f.d.srv, f.ownerTok, http.MethodDelete, fmt.Sprintf("/api/v1/shares/%d", f.olgaShareP), nil)
	require.Contains(t, []int{http.StatusOK, http.StatusNoContent}, code, raw)

	code, out, raw := f.owned(t, f.ownerTok, "")
	require.Equal(t, http.StatusOK, code, raw)
	assert.Equal(t, []uint{f.olgaSharePayments}, shareIDs(out.Data.Data), raw)

	// wendy cannot revoke olga's share from her own list's route family.
	code, raw = doMachineRequest(t, f.d.srv, f.writerTok, http.MethodDelete, fmt.Sprintf("/api/v1/shares/%d", f.olgaSharePayments), nil)
	assert.Equal(t, http.StatusForbidden, code, raw)
}

// A machine identity with secrets.read at a project passes the route gate and is
// refused by core with the same reason: a share is created by a user.
func TestOwnedShares_MachineIsRefusedWithReason(t *testing.T) {
	srv, tok, _ := machineSecretFixture(t, "project_developer", 0)
	t.Cleanup(srv.Close)
	code, raw := doMachineRequest(t, srv, tok, http.MethodGet, "/api/v1/shares/owned", nil)
	assert.Equal(t, http.StatusForbidden, code, raw)
	var out ownedShareResponse
	require.NoError(t, json.Unmarshal([]byte(raw), &out), raw)
	assert.Equal(t, core.OwnedShareListDeniedMessage, out.Message, raw)
}
