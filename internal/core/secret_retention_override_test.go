package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── SetSecretRetentionOverride ────────────────────────────────────────────────

// TestSetSecretRetentionOverride_HappyPath verifies that a valid override (>= 7
// days) is forwarded to storage and that an audit event is emitted.
func TestSetSecretRetentionOverride_HappyPath(t *testing.T) {
	m := &MockStorage{}
	c := NewKeyorixCore(m)

	m.On("SetRetentionOverride", mock.Anything, uint(42), 30).Return(nil)
	// Audit event sink — emitAudit calls LogAuditEvent on storage.
	m.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	err := c.SetSecretRetentionOverride(context.Background(), 1, 42, 30)
	require.NoError(t, err)
	m.AssertCalled(t, "SetRetentionOverride", mock.Anything, uint(42), 30)
}

// TestSetSecretRetentionOverride_ClearOverride verifies that days=0 is allowed
// (clears the override) and is forwarded to storage.
func TestSetSecretRetentionOverride_ClearOverride(t *testing.T) {
	m := &MockStorage{}
	c := NewKeyorixCore(m)

	m.On("SetRetentionOverride", mock.Anything, uint(7), 0).Return(nil)
	m.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	err := c.SetSecretRetentionOverride(context.Background(), 1, 7, 0)
	require.NoError(t, err)
	m.AssertCalled(t, "SetRetentionOverride", mock.Anything, uint(7), 0)
}

// TestSetSecretRetentionOverride_BelowMinimum verifies that days=6 (below the
// 7-day floor) is rejected with ErrInvalidRetentionDays without touching storage.
func TestSetSecretRetentionOverride_BelowMinimum(t *testing.T) {
	m := &MockStorage{}
	c := NewKeyorixCore(m)

	err := c.SetSecretRetentionOverride(context.Background(), 1, 99, 6)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRetentionDays), "expected ErrInvalidRetentionDays, got: %v", err)
	m.AssertNotCalled(t, "SetRetentionOverride", mock.Anything, mock.Anything, mock.Anything)
}

// TestSetSecretRetentionOverride_Negative verifies that a negative days value
// is rejected with ErrInvalidRetentionDays.
func TestSetSecretRetentionOverride_Negative(t *testing.T) {
	m := &MockStorage{}
	c := NewKeyorixCore(m)

	err := c.SetSecretRetentionOverride(context.Background(), 1, 5, -1)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRetentionDays), "expected ErrInvalidRetentionDays, got: %v", err)
	m.AssertNotCalled(t, "SetRetentionOverride", mock.Anything, mock.Anything, mock.Anything)
}

// TestSetSecretRetentionOverride_StorageError verifies that a storage error is
// propagated to the caller (and no audit event is emitted on failure).
func TestSetSecretRetentionOverride_StorageError(t *testing.T) {
	m := &MockStorage{}
	c := NewKeyorixCore(m)

	storageErr := errors.New("db unavailable")
	m.On("SetRetentionOverride", mock.Anything, uint(10), 90).Return(storageErr)

	err := c.SetSecretRetentionOverride(context.Background(), 1, 10, 90)
	require.Error(t, err)
	assert.ErrorIs(t, err, storageErr)
	// No audit event should be emitted when storage fails.
	m.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
}

// TestSetSecretRetentionOverride_ExactMinimum verifies that exactly 7 days is
// accepted (boundary condition).
func TestSetSecretRetentionOverride_ExactMinimum(t *testing.T) {
	m := &MockStorage{}
	c := NewKeyorixCore(m)

	m.On("SetRetentionOverride", mock.Anything, uint(1), 7).Return(nil)
	m.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	err := c.SetSecretRetentionOverride(context.Background(), 1, 1, 7)
	require.NoError(t, err)
	m.AssertCalled(t, "SetRetentionOverride", mock.Anything, uint(1), 7)
}

// ── GetEffectiveRetentionDays ─────────────────────────────────────────────────

// TestGetEffectiveRetentionDays_OverrideSet verifies that a non-zero
// RetentionOverrideDays on the secret takes precedence over the global value.
func TestGetEffectiveRetentionDays_OverrideSet(t *testing.T) {
	secret := &models.SecretNode{RetentionOverrideDays: 365}
	result := GetEffectiveRetentionDays(secret, 90)
	assert.Equal(t, 365, result)
}

// TestGetEffectiveRetentionDays_OverrideZero verifies that when
// RetentionOverrideDays is 0 the global policy value is returned.
func TestGetEffectiveRetentionDays_OverrideZero(t *testing.T) {
	secret := &models.SecretNode{RetentionOverrideDays: 0}
	result := GetEffectiveRetentionDays(secret, 90)
	assert.Equal(t, 90, result)
}

// TestGetEffectiveRetentionDays_OverrideEqualsGlobal verifies that a secret
// whose override equals the global policy correctly returns the override value
// (same effective result, but driven by the override branch).
func TestGetEffectiveRetentionDays_OverrideEqualsGlobal(t *testing.T) {
	secret := &models.SecretNode{RetentionOverrideDays: 90}
	result := GetEffectiveRetentionDays(secret, 90)
	assert.Equal(t, 90, result)
}
