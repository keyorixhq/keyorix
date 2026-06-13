package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func uptr(u uint) *uint { return &u }

// GenerateProjectAccessReview reports every project-scoped role grant whose role
// confers a secrets.* permission (users and groups), with the highest action, and
// excludes roles that grant no secret access.
func TestGenerateProjectAccessReview(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	const proj = uint(2)
	// alice: editor (secrets.read+write) at project 2 → write.
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))
	// bob: auditor (audit.read, NO secrets.*) at project 2 → excluded.
	h.CreateTestUser(t, "bob", 11)
	h.AssignUserRole(t, 11, 5, uptr(proj))
	// carol: viewer (secrets.read) at a DIFFERENT project → excluded from project 2.
	h.CreateTestUser(t, "carol", 12)
	h.AssignUserRole(t, 12, 4, uptr(uint(3)))
	// devs group: viewer (secrets.read) at project 2 → read.
	h.CreateTestGroup(t, "devs", "", 100)
	h.AssignGroupRole(t, 100, 4, uptr(proj))

	review, err := h.CoreService.GenerateProjectAccessReview(context.Background(), proj)
	require.NoError(t, err)

	type got struct{ typ, name, level string }
	var rows []got
	for _, e := range review {
		rows = append(rows, got{e.PrincipalType, e.PrincipalName, e.AccessLevel})
	}
	assert.ElementsMatch(t, []got{
		{"user", "alice", "write"},
		{"group", "devs", "read"},
	}, rows, "alice (editor→write) and the devs group (viewer→read); bob (auditor, no secrets) and carol (other project) excluded")
}

func TestGenerateProjectAccessReview_RequiresProject(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	_, err := h.CoreService.GenerateProjectAccessReview(context.Background(), 0)
	require.Error(t, err)
}
