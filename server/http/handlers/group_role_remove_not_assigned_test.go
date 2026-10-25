package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRBACReal_RemoveRoleFromGroup_NotAssigned404 pins that removing a group
// role grant that does not exist at the requested scope answers 404, the same
// as DELETE /user-roles for a user. It used to answer 500 "Failed to remove
// role from group": the storage error carried no sentinel and the handler only
// mapped "not found" (MERGE-FIX-3585-2; seen in the e2e smoke when the grant
// before it was refused).
func TestRBACReal_RemoveRoleFromGroup_NotAssigned404(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	group := mustCreateGroup(t, db, "ungranted-team")
	role := mustCreateRole(t, db, "never-granted")

	for _, q := range []string{"", "?project_id=5", "?project_id=5&environment_id=3"} {
		t.Run("scope"+q, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete,
				fmt.Sprintf("/api/v1/groups/%d/roles/%d%s", group.ID, role.ID, q), nil)
			req = withUserCtx(withChiParams(req, map[string]string{
				"id":     fmt.Sprintf("%d", group.ID),
				"roleId": fmt.Sprintf("%d", role.ID),
			}))
			w := httptest.NewRecorder()

			handler.RemoveRoleFromGroup(w, req)

			assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
		})
	}
}
