package storage

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// backfillRoleAssignableScope is the one-time upgrade backfill of
// roles.assignable_scope (GROUP-ROLE-SCOPE-1 Phase 2, #3546), run by
// migrateDatabase in the same transaction that adds the column: every existing
// role becomes any (a custom role an install relies on keeps working at every
// scope it worked at), then each built-in role gets its fixed scope from
// models.BuiltinRoleAssignableScopes, matched by exact name.
//
// Idempotent: running it again writes the same values (it is gated on the
// column's absence anyway). It never touches a grant.
func backfillRoleAssignableScope(tx *gorm.DB) error {
	if err := tx.Model(&models.Role{}).Where("1 = 1").Update("assignable_scope", models.RoleAssignableAny).Error; err != nil {
		return fmt.Errorf("backfill roles.assignable_scope (existing roles = %s): %w", models.RoleAssignableAny, err)
	}
	for _, scope := range []string{models.RoleAssignableGlobal, models.RoleAssignableProject} {
		names := models.BuiltinRoleNamesWithAssignableScope(scope)
		if len(names) == 0 {
			continue
		}
		if err := tx.Model(&models.Role{}).Where("name IN ?", names).Update("assignable_scope", scope).Error; err != nil {
			return fmt.Errorf("backfill roles.assignable_scope (built-ins = %s): %w", scope, err)
		}
	}
	return nil
}
