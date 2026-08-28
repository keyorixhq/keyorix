// rbac_builtin_denial_audit_test.go — #1503: UpdateRole/DeleteRole refuse a
// built-in role (core.IsBuiltinRole) but, before this fix, wrote no audit
// event for the refusal — unlike every other RBAC/Connect deny path. These
// tests assert the audit event lands, not just that the request is refused
// (the 403 itself was already covered by TestDeleteRole_BuiltinRole_S26).
package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateRole_BuiltinRole_AuditsTheDenial is the HTTP-transport half of
// #1503: attempting to update a built-in role must both refuse (403,
// pre-existing behavior, unchanged) AND write a Success=false audit event
// naming the role -- previously it did neither.
func TestUpdateRole_BuiltinRole_AuditsTheDenial(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewRBACHandler(cs)

	var adminRole models.Role
	require.NoError(t, db.Where("name = ?", "system_admin").First(&adminRole).Error)

	body := bytes.NewBufferString(`{"description":"attempted rename"}`)
	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodPut, "/api/v1/roles/1", body),
		"id", uintStrS26(adminRole.ID),
	))
	w := httptest.NewRecorder()
	h.UpdateRole(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code, "the refusal itself must still happen")

	var event models.AuditEvent
	err := db.Where("event_type = ? AND success = ?", core.EventRoleUpdated, false).First(&event).Error
	require.NoError(t, err, "the denied update must write a Success=false audit event")
	assert.Contains(t, event.Description, adminRole.Name, "the audit description must name the target role")
}

// TestDeleteRole_BuiltinRole_AuditsTheDenial is the DeleteRole counterpart —
// see TestUpdateRole_BuiltinRole_AuditsTheDenial's doc comment.
func TestDeleteRole_BuiltinRole_AuditsTheDenial(t *testing.T) {
	cs, db := freshCoreS26WithAdmin(t)
	h := NewRBACHandler(cs)

	var adminRole models.Role
	require.NoError(t, db.Where("name = ?", "system_admin").First(&adminRole).Error)

	req := withUserCtx(withChiParam_S25(
		httptest.NewRequest(http.MethodDelete, "/api/v1/roles/1", nil),
		"id", uintStrS26(adminRole.ID),
	))
	w := httptest.NewRecorder()
	h.DeleteRole(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code, "the refusal itself must still happen")

	var event models.AuditEvent
	err := db.Where("event_type = ? AND success = ?", core.EventRoleDeleted, false).First(&event).Error
	require.NoError(t, err, "the denied delete must write a Success=false audit event")
	assert.Contains(t, event.Description, adminRole.Name, "the audit description must name the target role")
}
