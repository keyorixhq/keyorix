package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestKeyorixCore_LogShareCreated(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	core := &KeyorixCore{
		storage: mockStorage,
		now: func() time.Time {
			return mockTime
		},
	}
	ctx := context.Background()

	// Test data
	auditCtx := &ShareAuditContext{
		ActorID:     1,
		SecretID:    1,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "read",
	}

	// Mock expectations
	mockStorage.On("LogAuditEvent", ctx, mock.MatchedBy(func(event *models.AuditEvent) bool {
		return event.EventType == string(ShareAuditEventCreated) &&
			event.SecretNodeID != nil &&
			*event.SecretNodeID == 1
	})).Return(nil)

	// Execute
	core.LogShareCreated(ctx, auditCtx)

	// Assert
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_LogShareUpdated(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	core := &KeyorixCore{
		storage: mockStorage,
		now: func() time.Time {
			return mockTime
		},
	}
	ctx := context.Background()

	// Test data
	auditCtx := &ShareAuditContext{
		ActorID:       1,
		SecretID:      1,
		RecipientID:   2,
		IsGroup:       false,
		Permission:    "write",
		OldPermission: "read",
	}

	// Mock expectations
	mockStorage.On("LogAuditEvent", ctx, mock.MatchedBy(func(event *models.AuditEvent) bool {
		return event.EventType == string(ShareAuditEventUpdated) &&
			event.SecretNodeID != nil &&
			*event.SecretNodeID == 1
	})).Return(nil)

	// Execute
	core.LogShareUpdated(ctx, auditCtx)

	// Assert
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_LogShareRevoked(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	core := &KeyorixCore{
		storage: mockStorage,
		now: func() time.Time {
			return mockTime
		},
	}
	ctx := context.Background()

	// Test data
	auditCtx := &ShareAuditContext{
		ActorID:     1,
		SecretID:    1,
		RecipientID: 2,
		IsGroup:     false,
	}

	// Mock expectations
	mockStorage.On("LogAuditEvent", ctx, mock.MatchedBy(func(event *models.AuditEvent) bool {
		return event.EventType == string(ShareAuditEventRevoked) &&
			event.SecretNodeID != nil &&
			*event.SecretNodeID == 1
	})).Return(nil)

	// Execute
	core.LogShareRevoked(ctx, auditCtx)

	// Assert
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_LogSharedSecretAccessed(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	core := &KeyorixCore{
		storage: mockStorage,
		now: func() time.Time {
			return mockTime
		},
	}
	ctx := context.Background()

	// Test data
	auditCtx := &ShareAuditContext{
		ActorID:    1,
		SecretID:   1,
		Permission: "read",
	}

	// Mock expectations
	mockStorage.On("LogAuditEvent", ctx, mock.MatchedBy(func(event *models.AuditEvent) bool {
		return event.EventType == string(ShareAuditEventAccessed) &&
			event.SecretNodeID != nil &&
			*event.SecretNodeID == 1
	})).Return(nil)

	// Execute
	core.LogSharedSecretAccessed(ctx, auditCtx)

	// Assert
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_LogGroupShareCreated(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	core := &KeyorixCore{
		storage: mockStorage,
		now: func() time.Time {
			return mockTime
		},
	}
	ctx := context.Background()

	// Test data
	auditCtx := &ShareAuditContext{
		ActorID:     1,
		SecretID:    1,
		RecipientID: 2,
		IsGroup:     true,
		Permission:  "read",
	}

	// Mock expectations
	mockStorage.On("LogAuditEvent", ctx, mock.MatchedBy(func(event *models.AuditEvent) bool {
		return event.EventType == string(ShareAuditEventGroupCreated) &&
			event.SecretNodeID != nil &&
			*event.SecretNodeID == 1
	})).Return(nil)

	// Execute
	core.LogGroupShareCreated(ctx, auditCtx)

	// Assert
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_LogGroupShareUpdated(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	core := &KeyorixCore{
		storage: mockStorage,
		now: func() time.Time {
			return mockTime
		},
	}
	ctx := context.Background()

	// Test data
	auditCtx := &ShareAuditContext{
		ActorID:       1,
		SecretID:      1,
		RecipientID:   2,
		IsGroup:       true,
		Permission:    "write",
		OldPermission: "read",
	}

	// Mock expectations
	mockStorage.On("LogAuditEvent", ctx, mock.MatchedBy(func(event *models.AuditEvent) bool {
		return event.EventType == string(ShareAuditEventGroupUpdated) &&
			event.SecretNodeID != nil &&
			*event.SecretNodeID == 1
	})).Return(nil)

	// Execute
	core.LogGroupShareUpdated(ctx, auditCtx)

	// Assert
	mockStorage.AssertExpectations(t)
}

func TestKeyorixCore_LogGroupShareRevoked(t *testing.T) {
	// Setup
	mockStorage := new(MockStorage)
	mockTime := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	core := &KeyorixCore{
		storage: mockStorage,
		now: func() time.Time {
			return mockTime
		},
	}
	ctx := context.Background()

	// Test data
	auditCtx := &ShareAuditContext{
		ActorID:     1,
		SecretID:    1,
		RecipientID: 2,
		IsGroup:     true,
	}

	// Mock expectations
	mockStorage.On("LogAuditEvent", ctx, mock.MatchedBy(func(event *models.AuditEvent) bool {
		return event.EventType == string(ShareAuditEventGroupRevoked) &&
			event.SecretNodeID != nil &&
			*event.SecretNodeID == 1
	})).Return(nil)

	// Execute
	core.LogGroupShareRevoked(ctx, auditCtx)

	// Assert
	mockStorage.AssertExpectations(t)
}

// TestShareAudit_StampsImpersonationContext locks in #284: every sharing-related
// audit writer must route through the shared writeAuditEvent choke point so an
// action taken during an impersonation session is stamped with
// ImpersonatedBy/ActingAs/Impersonation=true — mirroring how secret CRUD and RBAC
// writers (audit.go) already behave. Exploit trace from the finding: an admin (id
// 99) impersonates target user T (id 2) and shares a secret as T; the resulting
// audit row must NOT be indistinguishable from T's own genuine action.
func TestShareAudit_StampsImpersonationContext(t *testing.T) {
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}
	ctx := WithImpersonation(context.Background(), 99) // admin 99 impersonating target 2

	writers := map[string]func(){
		string(ShareAuditEventCreated):      func() { core.LogShareCreated(ctx, &ShareAuditContext{ActorID: 2, SecretID: 1, RecipientID: 3, Permission: "read"}) },
		string(ShareAuditEventUpdated):      func() { core.LogShareUpdated(ctx, &ShareAuditContext{ActorID: 2, SecretID: 1, RecipientID: 3, Permission: "write", OldPermission: "read"}) },
		string(ShareAuditEventRevoked):      func() { core.LogShareRevoked(ctx, &ShareAuditContext{ActorID: 2, SecretID: 1, RecipientID: 3}) },
		string(ShareAuditEventAccessed):     func() { core.LogSharedSecretAccessed(ctx, &ShareAuditContext{ActorID: 2, SecretID: 1, Permission: "read"}) },
		string(ShareAuditEventGroupCreated): func() { core.LogGroupShareCreated(ctx, &ShareAuditContext{ActorID: 2, SecretID: 1, RecipientID: 4, IsGroup: true, Permission: "read"}) },
		string(ShareAuditEventGroupUpdated): func() {
			core.LogGroupShareUpdated(ctx, &ShareAuditContext{ActorID: 2, SecretID: 1, RecipientID: 4, IsGroup: true, Permission: "write", OldPermission: "read"})
		},
		string(ShareAuditEventGroupRevoked): func() { core.LogGroupShareRevoked(ctx, &ShareAuditContext{ActorID: 2, SecretID: 1, RecipientID: 4, IsGroup: true}) },
		string(ShareAuditEventSelfRemoved):  func() { core.LogSelfRemovalFromShare(ctx, &ShareAuditContext{ActorID: 2, SecretID: 1, RecipientID: 2}) },
	}

	for eventType, write := range writers {
		t.Run(eventType, func(t *testing.T) {
			mockStorage.ExpectedCalls = nil
			mockStorage.Calls = nil
			var captured *models.AuditEvent
			mockStorage.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
				captured = e
				return e.EventType == eventType
			})).Return(nil)

			write()

			require.NotNil(t, captured, "expected an audit event to be written")
			assert.True(t, captured.Impersonation, "Impersonation must be true")
			require.NotNil(t, captured.ImpersonatedBy, "ImpersonatedBy must be stamped")
			assert.Equal(t, uint(99), *captured.ImpersonatedBy)
			require.NotNil(t, captured.ActingAs, "ActingAs must be stamped")
			assert.Equal(t, uint(2), *captured.ActingAs)
			assert.Equal(t, ActorTypeUser, captured.ActorType)
		})
	}
}

// TestShareAudit_NoImpersonationOutsideSession confirms a non-impersonation
// context leaves Impersonation/ImpersonatedBy/ActingAs unset, so the fix does not
// spuriously tag ordinary sharing actions.
func TestShareAudit_NoImpersonationOutsideSession(t *testing.T) {
	mockStorage := new(MockStorage)
	core := &KeyorixCore{
		storage: mockStorage,
		now:     time.Now,
	}
	ctx := context.Background()

	var captured *models.AuditEvent
	mockStorage.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		captured = e
		return true
	})).Return(nil)

	core.LogShareCreated(ctx, &ShareAuditContext{ActorID: 2, SecretID: 1, RecipientID: 3, Permission: "read"})

	require.NotNil(t, captured)
	assert.False(t, captured.Impersonation)
	assert.Nil(t, captured.ImpersonatedBy)
	assert.Nil(t, captured.ActingAs)
}

func TestShareAuditContext_Validation(t *testing.T) {
	tests := []struct {
		name    string
		ctx     *ShareAuditContext
		wantErr bool
	}{
		{
			name: "valid user share context",
			ctx: &ShareAuditContext{
				ActorID:     1,
				SecretID:    1,
				RecipientID: 2,
				IsGroup:     false,
				Permission:  "read",
			},
			wantErr: false,
		},
		{
			name: "valid group share context",
			ctx: &ShareAuditContext{
				ActorID:     1,
				SecretID:    1,
				RecipientID: 2,
				IsGroup:     true,
				Permission:  "write",
			},
			wantErr: false,
		},
		{
			name: "context with update information",
			ctx: &ShareAuditContext{
				ActorID:       1,
				SecretID:      1,
				RecipientID:   2,
				IsGroup:       false,
				Permission:    "write",
				OldPermission: "read",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation - ensure required fields are present
			if tt.ctx.ActorID == 0 {
				assert.True(t, tt.wantErr, "ActorID should be required")
			}
			if tt.ctx.SecretID == 0 {
				assert.True(t, tt.wantErr, "SecretID should be required")
			}
		})
	}
}
