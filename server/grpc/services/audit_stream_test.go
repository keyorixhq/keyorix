package services

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// fakeAuditStream implements pb.AuditService_StreamAuditLogsServer, capturing
// sent events. The embedded grpc.ServerStream is nil — only Context()/Send() are
// exercised by StreamAuditLogs.
type fakeAuditStream struct {
	grpc.ServerStream
	ctx  context.Context
	mu   sync.Mutex
	sent []*pb.AuditLog
}

func (f *fakeAuditStream) Context() context.Context { return f.ctx }
func (f *fakeAuditStream) Send(m *pb.AuditLog) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
	return nil
}
func (f *fakeAuditStream) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}
func (f *fakeAuditStream) first() *pb.AuditLog {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent[0]
}

func newStreamCore(t *testing.T) (*AuditGRPCService, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// Pin to one connection: a shared :memory: db so the stream goroutine and the
	// test see the same schema (each new pool connection is a fresh :memory: db).
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin"}).Error)
	// User 1 = super_admin (global) so the audit.read check passes (stream tests
	// authenticate as user 1); the denied test uses an ungranted user id.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "super_admin"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 0}).Error)
	return NewAuditService(core.NewKeyorixCore(store.NewLocalStorage(db))), db
}

func TestAuditService_StreamAuditLogs_PermissionDenied(t *testing.T) {
	svc, _ := newStreamCore(t)
	stream := &fakeAuditStream{ctx: authCtx(7, "nobody")} // ungranted user → denied
	err := svc.StreamAuditLogs(&pb.StreamAuditLogsRequest{}, stream)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestAuditService_StreamAuditLogs_ResumesFromCursor(t *testing.T) {
	svc, db := newStreamCore(t)

	// Two pre-existing events. A client that last saw id e1 reconnects with
	// after_id=e1 and must receive the backlog (e2) without any new write.
	uid := uint(1)
	e1 := &models.AuditEvent{EventType: "role.assigned", UserID: &uid, EventTime: time.Now()}
	require.NoError(t, db.Create(e1).Error)
	e2 := &models.AuditEvent{EventType: "role.removed", UserID: &uid, EventTime: time.Now()}
	require.NoError(t, db.Create(e2).Error)

	ctx, cancel := context.WithCancel(authCtx(1, "admin", "audit.read"))
	defer cancel()
	stream := &fakeAuditStream{ctx: ctx}

	after := uint32(e1.ID)
	done := make(chan error, 1)
	go func() {
		done <- svc.StreamAuditLogs(&pb.StreamAuditLogsRequest{AfterId: &after}, stream)
	}()

	// The backlog after e1 (i.e. e2) is replayed immediately, before any new event.
	require.Eventually(t, func() bool { return stream.count() >= 1 }, time.Second, 10*time.Millisecond)
	assert.Equal(t, "role.removed", stream.first().GetEventType())

	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("stream did not return after cancel")
	}
}

func TestAuditService_StreamAuditLogs_TailsNewEvents(t *testing.T) {
	// These events are inserted directly into the DB (bypassing the emitAudit funnel
	// that normally fires the push signal), so delivery here rides the fallback
	// safety-net drain — shorten it for the test. The push (signal) path itself is
	// unit-tested in package core (TestEmitAudit_SignalsSubscribers + broker tests);
	// both paths run the same drain() send/cursor logic exercised below.
	old := auditStreamFallbackInterval
	auditStreamFallbackInterval = 15 * time.Millisecond
	defer func() { auditStreamFallbackInterval = old }()

	svc, db := newStreamCore(t)

	// A pre-existing event: it's the head, so it should NOT be streamed.
	uid := uint(1)
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "role.assigned", UserID: &uid, EventTime: time.Now(),
	}).Error)

	ctx, cancel := context.WithCancel(authCtx(1, "admin", "audit.read"))
	defer cancel()
	stream := &fakeAuditStream{ctx: ctx}

	done := make(chan error, 1)
	go func() { done <- svc.StreamAuditLogs(&pb.StreamAuditLogsRequest{}, stream) }()

	// Let the stream start and capture the head cursor, then create a new event.
	time.Sleep(60 * time.Millisecond)
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "role.removed", UserID: &uid, EventTime: time.Now(),
	}).Error)

	// The new event should arrive on the stream.
	require.Eventually(t, func() bool { return stream.count() >= 1 }, time.Second, 10*time.Millisecond)
	assert.Equal(t, "role.removed", stream.first().GetEventType())

	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("stream did not return after cancel")
	}
}
