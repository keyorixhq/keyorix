package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
)

// captureActorType writes one audit event and returns the ActorType stamped on
// the row handed to storage.
func captureActorType(t *testing.T, write func(c *KeyorixCore, ctx context.Context)) string {
	t.Helper()
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	var got string
	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		got = e.ActorType
		return true
	})).Return(nil)
	write(c, context.Background())
	store.AssertExpectations(t)
	return got
}

func TestWriteAuditEvent_DefaultsToUserActorType(t *testing.T) {
	got := captureActorType(t, func(c *KeyorixCore, ctx context.Context) {
		c.writeAuditEventFull(ctx, "secret.read", nil, nil, nil, "", "x")
	})
	if got != ActorTypeUser {
		t.Errorf("ActorType = %q, want %q", got, ActorTypeUser)
	}
}

func TestWriteAuditEvent_StampsMachineActorTypeFromContext(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	var got string
	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		got = e.ActorType
		return true
	})).Return(nil)

	ctx := WithActorType(context.Background(), ActorTypeMachine)
	c.writeAuditEventFull(ctx, "secret.read", nil, nil, nil, "", "x")

	store.AssertExpectations(t)
	if got != ActorTypeMachine {
		t.Errorf("ActorType = %q, want %q", got, ActorTypeMachine)
	}
}

func TestWriteAuditEventFailed_StampsActorTypeFromContext(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	var got string
	store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		got = e.ActorType
		return true
	})).Return(nil)

	ctx := WithActorType(context.Background(), ActorTypeSystem)
	c.writeAuditEventFailed(ctx, "auth.login_failed", nil, "1.2.3.4", "x")

	store.AssertExpectations(t)
	if got != ActorTypeSystem {
		t.Errorf("ActorType = %q, want %q", got, ActorTypeSystem)
	}
}

func TestActorTypeFromContext_DefaultAndTagged(t *testing.T) {
	if at := actorTypeFromContext(context.Background()); at != ActorTypeUser {
		t.Errorf("untagged context actor type = %q, want %q", at, ActorTypeUser)
	}
	// An empty tag is treated as no tag (default user).
	if ctx := WithActorType(context.Background(), ""); actorTypeFromContext(ctx) != ActorTypeUser {
		t.Errorf("empty tag should default to %q", ActorTypeUser)
	}
	ctx := WithActorType(context.Background(), ActorTypeMachine)
	if at := actorTypeFromContext(ctx); at != ActorTypeMachine {
		t.Errorf("tagged context actor type = %q, want %q", at, ActorTypeMachine)
	}
}

// DetachedAuditContext must carry the actor-type tag (and impersonation) past
// request cancellation into the detached audit goroutine.
func TestDetachedAuditContext_PreservesActorTypeAndImpersonation(t *testing.T) {
	parent := WithActorType(WithImpersonation(context.Background(), 7), ActorTypeMachine)
	detached := DetachedAuditContext(parent)

	if at := actorTypeFromContext(detached); at != ActorTypeMachine {
		t.Errorf("detached actor type = %q, want %q", at, ActorTypeMachine)
	}
	if adminID, ok := impersonatorFromContext(detached); !ok || adminID != 7 {
		t.Errorf("detached impersonator = (%d,%v), want (7,true)", adminID, ok)
	}
}
