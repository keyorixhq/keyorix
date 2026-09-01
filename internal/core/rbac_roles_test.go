// rbac_roles_test.go — #1660: CreateRole/UpdateRole are now internal/core
// functions, not something each transport reimplements against storage
// directly. These tests exercise the core layer alone (no HTTP/gRPC), to
// prove the validation genuinely lives here and isn't just something both
// transports happen to still do for themselves.
package core

import (
	"context"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newRoleCRUDTestCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Role{}, &models.AuditEvent{}))
	return &KeyorixCore{storage: store.NewLocalStorage(db)}, db
}

func TestCreateRole_RejectsReservedBuiltinName(t *testing.T) {
	c, _ := newRoleCRUDTestCore(t)
	_, err := c.CreateRole(context.Background(), 1, "super_admin", "d")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")
}

// TestCreateRole_RejectsReservedBuiltinName_CaseVariant is #294/#1642's own
// closed gap: IsBuiltinRole's exact map lookup only matches the folded form,
// so the reserved check must run AFTER folding, not against the raw name.
func TestCreateRole_RejectsReservedBuiltinName_CaseVariant(t *testing.T) {
	c, _ := newRoleCRUDTestCore(t)
	_, err := c.CreateRole(context.Background(), 1, "Super_Admin", "d")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")
}

func TestCreateRole_RejectsControlCharacters(t *testing.T) {
	c, _ := newRoleCRUDTestCore(t)
	_, err := c.CreateRole(context.Background(), 1, "readonly\n[AUDIT] granted admin", "d")
	require.Error(t, err)
}

func TestCreateRole_RejectsTooShortName(t *testing.T) {
	c, _ := newRoleCRUDTestCore(t)
	_, err := c.CreateRole(context.Background(), 1, "ab", "d")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "between")
}

func TestCreateRole_RejectsTooLongName(t *testing.T) {
	c, _ := newRoleCRUDTestCore(t)
	_, err := c.CreateRole(context.Background(), 1, strings.Repeat("a", RoleNameMaxLen+1), "d")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "between")
}

func TestCreateRole_HappyPathAudited(t *testing.T) {
	c, db := newRoleCRUDTestCore(t)
	role, err := c.CreateRole(context.Background(), 7, "custom-role", "a custom role")
	require.NoError(t, err)
	assert.Equal(t, "custom-role", role.Name)
	assert.NotZero(t, role.ID)

	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventRoleCreated).Count(&n).Error)
	assert.Equal(t, int64(1), n, "CreateRole must audit exactly once")
}

func TestCreateRole_DuplicateNameRejected(t *testing.T) {
	c, db := newRoleCRUDTestCore(t)
	// Mirrors factory.go's ensureRoleNameIndex, which AutoMigrate alone does
	// not create -- without it, this test's own duplicate-create wouldn't hit
	// a real constraint and would silently "succeed" twice.
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX uniq_roles_name_folded ON roles (name_folded)").Error)
	ctx := context.Background()
	_, err := c.CreateRole(ctx, 1, "dup-role", "d")
	require.NoError(t, err)
	_, err = c.CreateRole(ctx, 1, "dup-role", "d")
	require.Error(t, err)
}

func TestUpdateRole_RejectsBuiltin(t *testing.T) {
	c, db := newRoleCRUDTestCore(t)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "super_admin", NameFolded: "super_admin"}).Error)

	_, err := c.UpdateRole(context.Background(), 1, &models.Role{ID: 1, Name: "super_admin", Description: "hijacked"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "built-in")

	var role models.Role
	require.NoError(t, db.First(&role, 1).Error)
	assert.NotEqual(t, "hijacked", role.Description, "a rejected update must not persist")
}

func TestUpdateRole_HappyPathAudited(t *testing.T) {
	c, db := newRoleCRUDTestCore(t)
	created, err := c.CreateRole(context.Background(), 1, "editable-role", "old")
	require.NoError(t, err)

	created.Description = "new"
	updated, err := c.UpdateRole(context.Background(), 9, created)
	require.NoError(t, err)
	assert.Equal(t, "new", updated.Description)

	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventRoleUpdated).Count(&n).Error)
	assert.Equal(t, int64(1), n, "UpdateRole must audit exactly once")
}
