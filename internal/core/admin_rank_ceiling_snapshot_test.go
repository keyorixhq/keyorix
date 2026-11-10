package core

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// #4025: requireEqualOrGreaterAdminAuthority read the target's scope list and
// then the target's roles one scope at a time. Another administrator moving the
// target's admin grant from project A to project B between those reads left
// the check seeing the grant at neither: A came back empty, and B was never in
// the list. The target held the admin role the whole time, so the check must
// refuse an actor that does not hold it.
//
// The barrier sits below the Storage interface (a gorm callback), so it is the
// same for the old per-statement reads and the new one-statement read: right
// after the FIRST statement that reads the target's grants, it moves the grant.
func TestAdminRankCeiling_GrantMovedDuringTheCheckIsStillSeen(t *testing.T) {
	const (
		actorID, targetID          = uint(4101), uint(4202)
		projectA, projectB         = uint(11), uint(12)
		adminRoleID, writerRoleID  = uint(21), uint(22)
		usersWritePermID, otherPID = uint(31), uint(32)
	)
	dsn := "file:" + filepath.Join(t.TempDir(), "ceiling_snapshot.db") + "?_busy_timeout=10000&_journal_mode=WAL"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.AuditEvent{}, &models.PendingAuditEvent{},
	))
	for _, row := range []any{
		&models.Project{ID: projectA, Name: "a"}, &models.Project{ID: projectB, Name: "b"},
		&models.Permission{ID: usersWritePermID, Name: "users.write"}, &models.Permission{ID: otherPID, Name: "system.write"},
		&models.Role{ID: adminRoleID, Name: "project_super", BypassesPermissionChecks: true},
		&models.Role{ID: writerRoleID, Name: "user_writer"},
		&models.RolePermission{RoleID: writerRoleID, PermissionID: usersWritePermID},
		&models.User{ID: actorID, Username: "actor"}, &models.User{ID: targetID, Username: "target"},
		&models.UserRole{UserID: actorID, RoleID: writerRoleID},
		&models.UserRole{UserID: targetID, RoleID: adminRoleID, ProjectID: projectA},
	} {
		require.NoError(t, db.Create(row).Error)
	}

	var (
		mu         sync.Mutex
		targetRead []string
		moved      bool
	)
	readsTargetGrants := func(tx *gorm.DB) bool {
		sql := tx.Statement.SQL.String()
		return (strings.Contains(sql, "user_roles") || strings.Contains(sql, "group_roles")) &&
			slices.ContainsFunc(tx.Statement.Vars, func(v any) bool { u, ok := v.(uint); return ok && u == targetID })
	}
	barrier := func(tx *gorm.DB) {
		if !readsTargetGrants(tx) {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		targetRead = append(targetRead, tx.Statement.SQL.String())
		if moved {
			return
		}
		moved = true
		mover := db.Session(&gorm.Session{NewDB: true, Context: context.Background()})
		require.NoError(t, mover.Transaction(func(m *gorm.DB) error {
			if err := m.Where("user_id = ? AND role_id = ? AND project_id = ?", targetID, adminRoleID, projectA).
				Delete(&models.UserRole{}).Error; err != nil {
				return err
			}
			return m.Create(&models.UserRole{UserID: targetID, RoleID: adminRoleID, ProjectID: projectB}).Error
		}))
	}
	cb := db.Callback()
	require.NoError(t, cb.Query().After("gorm:query").Register("test:ceiling-barrier:q", barrier))
	require.NoError(t, cb.Row().After("gorm:row").Register("test:ceiling-barrier:row", barrier))

	c := &KeyorixCore{storage: store.NewLocalStorage(db), passwordPolicy: DefaultPasswordPolicy()}
	err = c.requireAdminRankCeilingForTarget(context.Background(), actorID, targetID, "modify")

	mu.Lock()
	defer mu.Unlock()
	require.True(t, moved, "the barrier never ran: the check no longer reads the target's grants this way")
	require.Error(t, err, "the target held an administrator role throughout (at A, then at B); "+
		"target-grant statements the check ran: %q", targetRead)
	require.True(t, errors.Is(err, ErrInsufficientAdminAuthority), "want a ceiling refusal, got %v", err)
	require.Len(t, targetRead, 1, "the target's grants must be read in one statement: %q", targetRead)
}
