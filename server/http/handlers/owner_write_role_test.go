package handlers

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedOwnerWriteRole gives userID a project role holding secrets.write, for
// fixtures whose secret owner writes tags, a description or a location. Since
// #4508 core no longer lets the owner pass alone authorize those writes (REST gates
// them on secrets.write), so an owner whose only role row names no real role is the
// viewer-owner the route refuses.
func seedOwnerWriteRole(t *testing.T, db *gorm.DB, userID, projectID uint) {
	t.Helper()
	role := &models.Role{Name: "owner-writer-fixture"}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{}
	if err := db.Where("name = ?", "secrets.write").First(perm).Error; err != nil {
		perm = &models.Permission{Name: "secrets.write", Resource: "secrets", Action: "write"}
		require.NoError(t, db.Create(perm).Error)
	}
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: userID, RoleID: role.ID, ProjectID: projectID}).Error)
}
