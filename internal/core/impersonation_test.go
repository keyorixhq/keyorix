package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
)

func newImpersonationCore(store *MockStorage) *KeyorixCore {
	fixed := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: store, now: func() time.Time { return fixed }}
}

func TestStartImpersonation_Success(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()

	store.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: "admin"}, nil)
	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, Username: "alice"}, nil)
	store.On("CreateSession", ctx, mock.MatchedBy(func(s *models.Session) bool {
		return s.UserID == 2 && s.ImpersonatedBy != nil && *s.ImpersonatedBy == 1 &&
			s.ImpersonationStartedAt != nil
	})).Return(&models.Session{ID: 99, UserID: 2, SessionToken: "tok"}, nil)
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == EventImpersonationStart && e.Impersonation &&
			e.ImpersonatedBy != nil && *e.ImpersonatedBy == 1 &&
			e.ActingAs != nil && *e.ActingAs == 2
	})).Return(nil)

	session, target, err := c.StartImpersonation(ctx, 1, 2, "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session.SessionToken != "tok" || target.Username != "alice" {
		t.Errorf("unexpected result: session=%v target=%v", session, target)
	}
	store.AssertExpectations(t)
}

func TestStartImpersonation_RejectsSelf(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	if _, _, err := c.StartImpersonation(context.Background(), 5, 5, ""); err == nil {
		t.Fatal("expected an error impersonating yourself")
	}
}

func TestEndImpersonation_LogsDurationAndActionCount(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()

	started := c.now().Add(-2 * time.Minute)
	admin := uint(1)
	store.On("GetSession", ctx, "tok").Return(&models.Session{
		ID: 99, UserID: 2, ImpersonatedBy: &admin, ImpersonationStartedAt: &started,
	}, nil)
	store.On("CountImpersonatedActions", uint(2), uint(1), started).Return(int64(3), nil)
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == EventImpersonationEnd && e.Impersonation &&
			strings.Contains(e.Diff, `"action_count":3`) &&
			strings.Contains(e.Diff, `"duration_seconds":120`)
	})).Return(nil)
	store.On("DeleteSession", ctx, uint(99)).Return(nil)

	if err := c.EndImpersonation(ctx, "tok"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	store.AssertExpectations(t)
}

func TestEndImpersonation_RejectsNonImpersonationSession(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()
	store.On("GetSession", ctx, "tok").Return(&models.Session{ID: 1, UserID: 2}, nil)

	if err := c.EndImpersonation(ctx, "tok"); err == nil {
		t.Fatal("expected an error for a non-impersonation session")
	}
}
