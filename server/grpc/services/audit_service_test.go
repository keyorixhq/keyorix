package services

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// newAuditService builds an audit service over an in-memory DB with the
// audit_events + users tables and one seeded event by user "alice".
func newAuditService(t *testing.T) *AuditGRPCService {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// modernc.org/sqlite gives each pooled connection to ":memory:" its own
	// fresh, unmigrated database unless pinned to a single connection --
	// without this, concurrent queries can intermittently hit a connection
	// that never saw AutoMigrate ("no such table") (ADR-048).
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "alice@example.com"}).Error)
	// User 1 = super_admin (global) so core.Authorize admits the admin-context
	// tests; the denied test uses an ungranted user id.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "super_admin"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0}).Error)
	uid := uint(1)
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret.read", UserID: &uid, Description: "read a secret",
		EventTime: time.Now(), ActorType: "user",
	}).Error)

	return NewAuditService(core.NewKeyorixCore(store.NewLocalStorage(db)))
}

func auditCtx() context.Context {
	return authCtx(1, "admin", "audit.read")
}

func TestAuditService_GetAuditLogs(t *testing.T) {
	svc := newAuditService(t)
	resp, err := svc.GetAuditLogs(auditCtx(), &pb.GetAuditLogsRequest{})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(resp.GetLogs()), 1)
	assert.GreaterOrEqual(t, resp.GetTotal(), uint32(1))

	log := resp.GetLogs()[0]
	assert.Equal(t, "secret.read", log.GetEventType())
	assert.Equal(t, "alice", log.GetActor())
}

func TestAuditService_GetAuditLogs_Unauthenticated(t *testing.T) {
	svc := newAuditService(t)
	_, err := svc.GetAuditLogs(context.Background(), &pb.GetAuditLogsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuditService_VerifyAuditChain(t *testing.T) {
	svc := newAuditService(t)
	resp, err := svc.VerifyAuditChain(auditCtx(), &emptypb.Empty{})
	require.NoError(t, err)
	// The seeded events are legacy (no hash chain), so the chained suffix is empty
	// and the trail verifies as intact.
	assert.True(t, resp.GetValid())
}

func TestAuditService_VerifyAuditChain_Unauthenticated(t *testing.T) {
	svc := newAuditService(t)
	_, err := svc.VerifyAuditChain(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuditService_GetAuditRetention(t *testing.T) {
	svc := newAuditService(t)
	resp, err := svc.GetAuditRetention(auditCtx(), &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, "unlimited", resp.GetRetentionPolicy())
	assert.GreaterOrEqual(t, resp.GetTotalEvents(), int64(1))
}

func TestAuditService_WriteAuditCheckpoint_RequiresEncryption(t *testing.T) {
	svc := newAuditService(t)
	// The test core has no encryption configured, so the DEK-derived signing key is
	// unavailable and a checkpoint cannot be written — a precondition failure.
	_, err := svc.WriteAuditCheckpoint(auditCtx(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// TestAuditService_WriteAuditCheckpoint_UnsafeErrorIsSanitized_G50 is the G50
// regression test (detection_idea): a raw storage/internal error unrelated to
// the "refusing to checkpoint" precondition must never reach the gRPC client
// verbatim. Before the fix, WriteAuditCheckpoint classified the error as
// safe-to-surface via strings.Contains(err.Error(), "refusing to checkpoint");
// any unrelated internal error whose text happened to contain that phrase would
// have been misclassified as safe. This drops the audit_events table so
// VerifyAuditChain hits a genuine SQL error (nowhere near the sentinel path),
// and asserts the gRPC status message is the generic clientSafe() text, not the
// raw SQL/table detail.
func TestAuditService_WriteAuditCheckpoint_UnsafeErrorIsSanitized_G50(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "alice@example.com"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "super_admin"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetAuditCheckpointKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"), "v1")

	// Drop the table VerifyAuditChain reads from, so it fails with a raw SQL
	// error instead of the "refusing to checkpoint" sentinel path.
	require.NoError(t, db.Exec("DROP TABLE audit_events").Error)

	svc := NewAuditService(c)
	_, err = svc.WriteAuditCheckpoint(auditCtx(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	msg := status.Convert(err).Message()
	assert.NotContains(t, msg, "audit_events", "raw SQL/table detail must not reach the gRPC client")
	assert.NotContains(t, msg, "no such table", "raw SQL error text must not reach the gRPC client")
	assert.Contains(t, msg, "an internal error occurred", "must fall back to the generic clientSafe() message")
}

func TestAuditService_GetAuditLogs_PermissionDenied(t *testing.T) {
	svc := newAuditService(t)
	ctx := authCtx(7, "nobody") // ungranted user → denied
	_, err := svc.GetAuditLogs(ctx, &pb.GetAuditLogsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestAuditService_GetRBACAuditLogs_EmptyButOK(t *testing.T) {
	svc := newAuditService(t)
	resp, err := svc.GetRBACAuditLogs(auditCtx(), &pb.GetRBACAuditLogsRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.GetLogs())
}

func TestAuditService_GetRBACAuditLogs_ReturnsRoleChanges(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// modernc.org/sqlite gives each pooled connection to ":memory:" its own
	// fresh, unmigrated database unless pinned to a single connection --
	// without this, concurrent queries can intermittently hit a connection
	// that never saw AutoMigrate ("no such table") (ADR-048).
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.UserRole{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SoDPolicy{}))
	// auditCtx() is user 1 — grant it super_admin (global) so the audit.read check passes.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "super_admin"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0}).Error)
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	require.NoError(t, c.AssignUserRole(context.Background(), 5, 10, 2, core.Scope{ProjectID: 3}))

	svc := NewAuditService(c)
	resp, err := svc.GetRBACAuditLogs(auditCtx(), &pb.GetRBACAuditLogsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetLogs(), 1)

	log := resp.GetLogs()[0]
	assert.Equal(t, core.EventRoleAssigned, log.GetAction())
	require.NotNil(t, log.ActorUserId)
	assert.Equal(t, uint32(5), log.GetActorUserId())
	require.NotNil(t, log.TargetUserId)
	assert.Equal(t, uint32(10), log.GetTargetUserId())
	require.NotNil(t, log.RoleId)
	assert.Equal(t, uint32(2), log.GetRoleId())
	require.NotNil(t, log.ProjectId)
	assert.Equal(t, uint32(3), log.GetProjectId())
}
