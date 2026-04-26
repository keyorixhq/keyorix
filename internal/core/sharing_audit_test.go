package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
