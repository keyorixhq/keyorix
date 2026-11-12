package core

// legacy_role_access_requests_test.go — LEGACY-ROLES-TAILS-1 item 4 (finding 6 of
// the #4089 deep review): the upgrade check listed grants and invitations but not
// a pending access request whose SuggestedRole is a legacy role. Approving it with
// that role is refused (#3605), so the approver has to pick another one; the check
// names such requests. Read-only: it never resolves or edits a request.

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestListPendingAccessRequestsWithLegacyRole(t *testing.T) {
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()
	w := newRoleScopeWorld(t, c)

	newUser := func(name string) uint {
		u, err := c.CreateUser(ctx, &CreateUserRequest{Username: name, Email: name + "@example.com", DisplayName: name, Password: "Correct-Horse-Battery-9"})
		require.NoError(t, err)
		return u.ID
	}
	request := func(project uint, user uint, role string) uint {
		r, err := c.RequestProjectAccess(ctx, project, user, role, "need access")
		require.NoError(t, err)
		return r.ID
	}

	pendingViewer := request(w.p1, newUser("pend-viewer"), "viewer")
	pendingAdmin := request(w.p2, newUser("pend-admin"), "admin")

	// Not listed: a pending request with a project role or none, a request that
	// was approved (granted a project role) and one that was rejected, and one
	// whose TTL has passed (approving it is refused as expired).
	request(w.p1, newUser("pend-project"), "project_viewer")
	request(w.p1, newUser("pend-none"), "")
	approvedID := request(w.p1, newUser("was-approved"), "viewer")
	_, err := c.ApproveAccessRequestWithExpiry(ctx, w.p1, approvedID, w.adminID, 0, "project_viewer", 0)
	require.NoError(t, err)
	rejectedID := request(w.p1, newUser("was-rejected"), "editor")
	_, err = c.RejectAccessRequest(ctx, w.p1, rejectedID, w.adminID, 0, "no")
	require.NoError(t, err)
	expiredID := request(w.p2, newUser("was-expired"), "admin")
	expired, err := c.storage.GetAccessRequest(ctx, expiredID)
	require.NoError(t, err)
	past := time.Now().Add(-time.Hour)
	expired.ExpiresAt = &past
	_, err = c.storage.UpdateAccessRequest(ctx, expired)
	require.NoError(t, err)

	before := w.grantRows(t)
	got, err := c.ListPendingAccessRequestsWithLegacyRole(ctx)
	require.NoError(t, err)
	require.Len(t, got, 2, "%+v", got)
	require.Equal(t, pendingViewer, got[0].RequestID)
	require.Equal(t, "viewer", got[0].SuggestedRole)
	require.Equal(t, "project_viewer", got[0].Replacement)
	require.Equal(t, "rs-one", got[0].Project)
	require.Equal(t, "pend-viewer@example.com", got[0].User)
	require.Equal(t, pendingAdmin, got[1].RequestID)
	require.Equal(t, "project_admin", got[1].Replacement)
	require.ElementsMatch(t, before, w.grantRows(t), "the check is read-only")
	stillPending, err := c.storage.GetAccessRequest(ctx, pendingViewer)
	require.NoError(t, err)
	require.Equal(t, AccessRequestPending, stillPending.State, "nothing is resolved automatically")

	report := LegacyRoleAccessRequestReport(got, 0)
	t.Logf("upgrade check:\n%s", strings.Join(report, "\n"))
	require.Len(t, report, 3, "a heading and one line per request")
	require.Contains(t, report[0], "2 pending access request(s) suggest a legacy role")
	fmtID := func(id uint) string { return strconv.FormatUint(uint64(id), 10) }
	require.Contains(t, report[1], "access request "+fmtID(pendingViewer)+": ")
	require.Contains(t, report[1], "approve it as project_viewer")
	require.Contains(t, report[2], "access request "+fmtID(pendingAdmin)+": ")
	for _, id := range []uint{approvedID, rejectedID, expiredID} {
		require.NotContains(t, strings.Join(report, "\n"), "access request "+fmtID(id)+": ", "a resolved or expired request is not listed")
	}
}

func TestLegacyRoleAccessRequestReport(t *testing.T) {
	require.Nil(t, LegacyRoleAccessRequestReport(nil, 0), "none pending, no report")
	base := LegacyRoleAccessRequest{RequestID: 1, ProjectID: 2, Project: "payments", UserID: 3, User: "a@example.com",
		SuggestedRole: "editor", Replacement: "project_developer"}
	many := make([]LegacyRoleAccessRequest, 5)
	for i := range many {
		many[i] = base
		many[i].RequestID = uint(i + 1)
	}
	lines := LegacyRoleAccessRequestReport(many, 2)
	require.Len(t, lines, 4)
	require.Contains(t, lines[3], "and 3 more")
	require.Len(t, LegacyRoleAccessRequestReport(many, 0), 6, "0 names every request")

	// Unresolved names fall back to ids; hostile names stay on their own line.
	lone := base
	lone.Project, lone.User = "", ""
	require.Contains(t, LegacyRoleAccessRequestReport([]LegacyRoleAccessRequest{lone}, 0)[1], "user id 3")
	hostile := base
	hostile.User, hostile.Project = hostileName, hostileName
	out := LegacyRoleAccessRequestReport([]LegacyRoleAccessRequest{hostile}, 0)
	require.Len(t, out, 2)
	for _, line := range out {
		requireNoControl(t, line, "access request report line")
	}
}
