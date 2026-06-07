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
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin"}).Error)
	return NewAuditService(core.NewKeyorixCore(store.NewLocalStorage(db))), db
}

func TestAuditService_StreamAuditLogs_PermissionDenied(t *testing.T) {
	svc, _ := newStreamCore(t)
	stream := &fakeAuditStream{ctx: authCtx(1, "nobody")} // no audit.read
	err := svc.StreamAuditLogs(&pb.StreamAuditLogsRequest{}, stream)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestAuditService_StreamAuditLogs_TailsNewEvents(t *testing.T) {
	// Fast poll for the test.
	old := auditStreamPollInterval
	auditStreamPollInterval = 15 * time.Millisecond
	defer func() { auditStreamPollInterval = old }()

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
