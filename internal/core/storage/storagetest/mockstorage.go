package storagetest

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
)

// MockStorage is a complete mock implementation of the Storage interface for testing
type MockStorage struct {
	mock.Mock

	// GetDynamicSecretConfigFunc/TransitionDynamicSecretConfigDisabledFunc, when
	// set, override the fixed-stub return values GetDynamicSecretConfig/
	// TransitionDynamicSecretConfigDisabled otherwise give (see those methods'
	// doc comments for why they use this settable-func escape hatch instead of
	// the usual testify .On()/m.Called() pattern). nil by default; a test that
	// specifically needs to control the return value (e.g. simulating a lost
	// dynamic-secret-config CAS race deterministically) sets the field directly.
	GetDynamicSecretConfigFunc                func(ctx context.Context, id uint) (*models.DynamicSecretConfig, error)
	TransitionDynamicSecretConfigDisabledFunc func(ctx context.Context, c *models.DynamicSecretConfig, fromDisabled bool) (bool, error)
}

// Permission Management

// Project / Environment

// Secret Management

func (m *MockStorage) mockNameMap(method string, ctx context.Context, ids []uint) (map[uint]string, error) {
	args := m.MethodCalled(method, ctx, ids)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uint]string), args.Error(1)
}

// mockHasExpectation reports whether a test stubbed method. The audit-description
// name lookups (audit_refs.go) are best-effort reads on code paths that predate them,
// so for an unstubbed method the lookup-only getters below answer "not found" instead
// of failing the mock's unexpected-call panic; a test that stubs the method still gets
// exactly what it stubbed.
func (m *MockStorage) mockHasExpectation(method string) bool {
	for _, c := range m.ExpectedCalls {
		if c.Method == method {
			return true
		}
	}
	return false
}

var errMockLookupNotStubbed = fmt.Errorf("mock: lookup not stubbed")

// Secret Sharing Management

// User Management

// Role Management

// RBAC Operations

// Audit Logging

// Session Management

// Personal Access Token Management

// Setup Token Management (ADR-028)

// Health and Maintenance

// Permission queries

// Group-Role assignments

// Rotation Policy Management

// NEW STORAGE METHODS — do NOT append here.
//
// This file is frozen so that parallel feature branches never conflict on it.
// When your PR adds new Storage interface methods to mock, create a NEW file:
//
//	internal/core/mock_storage_<feature>_test.go
//
// Declare the methods there (same package "core", no struct redeclaration).
// Go allows a struct's method set to span multiple files in the same package,
// so the compiler enforces interface completeness across all of them.
