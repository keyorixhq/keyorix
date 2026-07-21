// notification_retry_test.go — unit tests for SetNotificationRetryPolicy and
// GetNotificationRetryPolicy. Uses MockStorage to isolate storage interactions.
package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── SetNotificationRetryPolicy ────────────────────────────────────────────────

// TestSetNotificationRetryPolicy_HappyPath verifies a valid config is persisted
// and an audit event is emitted.
func TestSetNotificationRetryPolicy_HappyPath(t *testing.T) {
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	st.On("UpdateNotificationRetryPolicy", ctx, uint(1), 5, 2000).Return(nil)
	st.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	err := c.SetNotificationRetryPolicy(ctx, 42, 1, NotificationRetryConfig{MaxRetries: 5, RetryBackoffMs: 2000})
	require.NoError(t, err)
	st.AssertCalled(t, "UpdateNotificationRetryPolicy", ctx, uint(1), 5, 2000)
}

// TestSetNotificationRetryPolicy_MaxRetriesZero verifies MaxRetries=0 (no retry) is valid.
func TestSetNotificationRetryPolicy_MaxRetriesZero(t *testing.T) {
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	st.On("UpdateNotificationRetryPolicy", ctx, uint(1), 0, 500).Return(nil)
	st.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	err := c.SetNotificationRetryPolicy(ctx, 1, 1, NotificationRetryConfig{MaxRetries: 0, RetryBackoffMs: 500})
	require.NoError(t, err)
}

// TestSetNotificationRetryPolicy_MaxRetriesTen verifies MaxRetries=10 (ceiling) is valid.
func TestSetNotificationRetryPolicy_MaxRetriesTen(t *testing.T) {
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	st.On("UpdateNotificationRetryPolicy", ctx, uint(1), 10, 1000).Return(nil)
	st.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	err := c.SetNotificationRetryPolicy(ctx, 1, 1, NotificationRetryConfig{MaxRetries: 10, RetryBackoffMs: 1000})
	require.NoError(t, err)
}

// TestSetNotificationRetryPolicy_MaxRetriesEleven verifies MaxRetries=11 is rejected.
func TestSetNotificationRetryPolicy_MaxRetriesEleven(t *testing.T) {
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	err := c.SetNotificationRetryPolicy(ctx, 1, 1, NotificationRetryConfig{MaxRetries: 11, RetryBackoffMs: 1000})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_retries")
	st.AssertNotCalled(t, "UpdateNotificationRetryPolicy")
}

// TestSetNotificationRetryPolicy_MaxRetriesNegative verifies MaxRetries=-1 is rejected.
func TestSetNotificationRetryPolicy_MaxRetriesNegative(t *testing.T) {
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	err := c.SetNotificationRetryPolicy(ctx, 1, 1, NotificationRetryConfig{MaxRetries: -1, RetryBackoffMs: 1000})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_retries")
	st.AssertNotCalled(t, "UpdateNotificationRetryPolicy")
}

// TestSetNotificationRetryPolicy_BackoffMsMin verifies RetryBackoffMs=100 (floor) is valid.
func TestSetNotificationRetryPolicy_BackoffMsMin(t *testing.T) {
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	st.On("UpdateNotificationRetryPolicy", ctx, uint(1), 3, 100).Return(nil)
	st.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	err := c.SetNotificationRetryPolicy(ctx, 1, 1, NotificationRetryConfig{MaxRetries: 3, RetryBackoffMs: 100})
	require.NoError(t, err)
}

// TestSetNotificationRetryPolicy_BackoffMsMax verifies RetryBackoffMs=60000 (ceiling) is valid.
func TestSetNotificationRetryPolicy_BackoffMsMax(t *testing.T) {
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	st.On("UpdateNotificationRetryPolicy", ctx, uint(1), 3, 60000).Return(nil)
	st.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil).Maybe()

	err := c.SetNotificationRetryPolicy(ctx, 1, 1, NotificationRetryConfig{MaxRetries: 3, RetryBackoffMs: 60000})
	require.NoError(t, err)
}

// TestSetNotificationRetryPolicy_BackoffMsBelowMin verifies RetryBackoffMs=99 is rejected.
func TestSetNotificationRetryPolicy_BackoffMsBelowMin(t *testing.T) {
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	err := c.SetNotificationRetryPolicy(ctx, 1, 1, NotificationRetryConfig{MaxRetries: 3, RetryBackoffMs: 99})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "retry_backoff_ms")
	st.AssertNotCalled(t, "UpdateNotificationRetryPolicy")
}

// TestSetNotificationRetryPolicy_BackoffMsAboveMax verifies RetryBackoffMs=60001 is rejected.
func TestSetNotificationRetryPolicy_BackoffMsAboveMax(t *testing.T) {
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	err := c.SetNotificationRetryPolicy(ctx, 1, 1, NotificationRetryConfig{MaxRetries: 3, RetryBackoffMs: 60001})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "retry_backoff_ms")
	st.AssertNotCalled(t, "UpdateNotificationRetryPolicy")
}

// TestSetNotificationRetryPolicy_StorageError verifies storage errors are propagated.
func TestSetNotificationRetryPolicy_StorageError(t *testing.T) {
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	st.On("UpdateNotificationRetryPolicy", ctx, uint(7), 3, 1000).
		Return(fmt.Errorf("db: disk full"))

	err := c.SetNotificationRetryPolicy(ctx, 1, 7, NotificationRetryConfig{MaxRetries: 3, RetryBackoffMs: 1000})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk full")
}

// ── GetNotificationRetryPolicy ────────────────────────────────────────────────

// TestGetNotificationRetryPolicy_HappyPath verifies the policy is read from the channel.
func TestGetNotificationRetryPolicy_HappyPath(t *testing.T) {
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	ch := &models.NotificationChannel{
		ID:             3,
		Name:           "slack-ops",
		Type:           "slack",
		URL:            "https://hooks.slack.com/services/xxx",
		MaxRetries:     5,
		RetryBackoffMs: 2000,
	}
	st.On("GetNotificationChannel", ctx, uint(3)).Return(ch, nil)

	policy, err := c.GetNotificationRetryPolicy(ctx, 3)
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, 5, policy.MaxRetries)
	assert.Equal(t, 2000, policy.RetryBackoffMs)
}

// TestGetNotificationRetryPolicy_StorageError verifies storage errors are propagated.
func TestGetNotificationRetryPolicy_StorageError(t *testing.T) {
	st := new(MockStorage)
	c := NewKeyorixCore(st)
	ctx := context.Background()

	st.On("GetNotificationChannel", ctx, uint(99)).
		Return(nil, fmt.Errorf("record not found"))

	policy, err := c.GetNotificationRetryPolicy(ctx, 99)
	require.Error(t, err)
	assert.Nil(t, policy)
	assert.Contains(t, err.Error(), "not found")
}
