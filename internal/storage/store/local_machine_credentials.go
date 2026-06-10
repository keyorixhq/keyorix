// local_machine_credentials.go — machine-token credentials + machine role grants
// (ADR-030). Credentials mirror personal_access_tokens; role grants mirror
// user_roles. For the remote (HTTP) equivalent see remote_machine_identities.go.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// --- Machine-token credentials ---

func (ls *LocalStorage) CreateMachineIdentityCredential(ctx context.Context, c *models.MachineIdentityCredential) (*models.MachineIdentityCredential, error) {
	if err := ls.db.WithContext(ctx).Create(c).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return c, nil
}

func (ls *LocalStorage) GetMachineIdentityCredentialByHash(ctx context.Context, hash string) (*models.MachineIdentityCredential, error) {
	var c models.MachineIdentityCredential
	if err := ls.db.WithContext(ctx).Where("token_hash = ?", hash).First(&c).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &c, nil
}

func (ls *LocalStorage) GetMachineIdentityCredentialByID(ctx context.Context, id uint) (*models.MachineIdentityCredential, error) {
	var c models.MachineIdentityCredential
	if err := ls.db.WithContext(ctx).First(&c, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &c, nil
}

func (ls *LocalStorage) ListMachineIdentityCredentials(ctx context.Context, machineID uint) ([]*models.MachineIdentityCredential, error) {
	var rows []*models.MachineIdentityCredential
	err := ls.db.WithContext(ctx).
		Where("machine_identity_id = ?", machineID).
		Order("created_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) RevokeMachineIdentityCredential(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Model(&models.MachineIdentityCredential{}).
		Where("id = ?", id).UpdateColumn("revoked", true)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

func (ls *LocalStorage) TouchMachineIdentityCredential(ctx context.Context, id uint, usedAt time.Time, staleness time.Duration) error {
	cutoff := usedAt.Add(-staleness)
	return ls.db.WithContext(ctx).Model(&models.MachineIdentityCredential{}).
		Where("id = ? AND (last_used_at IS NULL OR last_used_at < ?)", id, cutoff).
		UpdateColumn("last_used_at", usedAt).Error
}

// --- Machine role grants ---

func (ls *LocalStorage) AssignMachineRole(ctx context.Context, machineID, roleID uint, scope storage.Scope) error {
	var existing models.MachineIdentityRole
	err := ls.db.WithContext(ctx).
		Where("machine_identity_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?",
			machineID, roleID, scope.ProjectID, scope.EnvironmentID).First(&existing).Error
	if err == nil {
		return fmt.Errorf("%s", i18n.T("ErrorRoleAlreadyAssigned", nil))
	}
	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	grant := models.MachineIdentityRole{
		MachineIdentityID: machineID,
		RoleID:            roleID,
		ProjectID:         scope.ProjectID,
		EnvironmentID:     scope.EnvironmentID,
	}
	if err := ls.db.WithContext(ctx).Create(&grant).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) RemoveMachineRole(ctx context.Context, machineID, roleID uint, scope storage.Scope) error {
	result := ls.db.WithContext(ctx).
		Where("machine_identity_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?",
			machineID, roleID, scope.ProjectID, scope.EnvironmentID).Delete(&models.MachineIdentityRole{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorRoleNotAssigned", nil))
	}
	return nil
}

// GetMachineRoleIDsAt returns the role IDs granted to the machine that apply at
// the target scope — a grant applies when its project is global or equal AND its
// environment is global or equal (mirrors GetUserRoleIDsAt).
func (ls *LocalStorage) GetMachineRoleIDsAt(ctx context.Context, machineID uint, scope storage.Scope) ([]uint, error) {
	var ids []uint
	err := ls.db.WithContext(ctx).Model(&models.MachineIdentityRole{}).
		Where("machine_identity_id = ?", machineID).
		Where("project_id = 0 OR project_id = ?", scope.ProjectID).
		Where("environment_id = 0 OR environment_id = ?", scope.EnvironmentID).
		Distinct().Pluck("role_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return ids, nil
}

// GetMachineRoles returns every role granted to the machine (any scope), for display.
func (ls *LocalStorage) GetMachineRoles(ctx context.Context, machineID uint) ([]*models.Role, error) {
	var roles []*models.Role
	err := ls.db.WithContext(ctx).Table("roles").
		Joins("JOIN machine_identity_roles ON roles.id = machine_identity_roles.role_id").
		Where("machine_identity_roles.machine_identity_id = ?", machineID).
		Find(&roles).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}
