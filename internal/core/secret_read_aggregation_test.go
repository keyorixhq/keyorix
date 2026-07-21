package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── helper ────────────────────────────────────────────────────────────────────

func newAggCore(t *testing.T) (*KeyorixCore, *MockStorage) {
	t.Helper()
	ms := &MockStorage{}
	return NewKeyorixCore(ms), ms
}

// ── happy path ────────────────────────────────────────────────────────────────

func TestGetSecretReadSummary_HappyPath(t *testing.T) {
	c, ms := newAggCore(t)
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	until := now

	entries := []storage.SecretReadEntry{
		{ActorID: "1", ActorUsername: "alice", ReadCount: 10, LastReadAt: now.Add(-1 * time.Hour)},
		{ActorID: "2", ActorUsername: "bob", ReadCount: 5, LastReadAt: now.Add(-2 * time.Hour)},
		{ActorID: "3", ActorUsername: "carol", ReadCount: 3, LastReadAt: now.Add(-3 * time.Hour)},
	}
	ms.On("GetSecretReadCounts", mock.Anything, uint(42), mock.AnythingOfType("time.Time"), mock.AnythingOfType("time.Time"), 10).
		Return(entries, nil)

	summary, err := c.GetSecretReadSummary(context.Background(), SecretReadSummaryRequest{
		SecretID: 42,
		Since:    since,
		Until:    until,
	})
	require.NoError(t, err)
	assert.Equal(t, uint(42), summary.SecretID)
	assert.Equal(t, int64(18), summary.TotalReads) // 10+5+3
	assert.Len(t, summary.Entries, 3)
	assert.Equal(t, "alice", summary.Entries[0].ActorUsername)
	ms.AssertExpectations(t)
}

// ── defaults ──────────────────────────────────────────────────────────────────

func TestGetSecretReadSummary_SinceDefaultIs30Days(t *testing.T) {
	c, ms := newAggCore(t)

	ms.On("GetSecretReadCounts", mock.Anything, uint(1), mock.MatchedBy(func(since time.Time) bool {
		// since should be approximately 30 days ago
		expected := c.now().Add(-30 * 24 * time.Hour)
		diff := since.Sub(expected)
		if diff < 0 {
			diff = -diff
		}
		return diff < 2*time.Second
	}), mock.AnythingOfType("time.Time"), 10).
		Return([]storage.SecretReadEntry{}, nil)

	summary, err := c.GetSecretReadSummary(context.Background(), SecretReadSummaryRequest{
		SecretID: 1,
		// Since and Until are zero → defaults
	})
	require.NoError(t, err)
	assert.Equal(t, int64(0), summary.TotalReads)
	ms.AssertExpectations(t)
}

func TestGetSecretReadSummary_UntilDefaultIsNow(t *testing.T) {
	c, ms := newAggCore(t)

	ms.On("GetSecretReadCounts", mock.Anything, uint(1), mock.AnythingOfType("time.Time"), mock.MatchedBy(func(until time.Time) bool {
		diff := c.now().Sub(until)
		if diff < 0 {
			diff = -diff
		}
		return diff < 2*time.Second
	}), 10).
		Return([]storage.SecretReadEntry{}, nil)

	_, err := c.GetSecretReadSummary(context.Background(), SecretReadSummaryRequest{SecretID: 1})
	require.NoError(t, err)
	ms.AssertExpectations(t)
}

func TestGetSecretReadSummary_LimitZeroDefaultsTo10(t *testing.T) {
	c, ms := newAggCore(t)

	ms.On("GetSecretReadCounts", mock.Anything, uint(1), mock.AnythingOfType("time.Time"), mock.AnythingOfType("time.Time"), 10).
		Return([]storage.SecretReadEntry{}, nil)

	_, err := c.GetSecretReadSummary(context.Background(), SecretReadSummaryRequest{SecretID: 1})
	require.NoError(t, err)
	ms.AssertExpectations(t)
}

func TestGetSecretReadSummary_LimitCappedAt50(t *testing.T) {
	c, ms := newAggCore(t)

	ms.On("GetSecretReadCounts", mock.Anything, uint(1), mock.AnythingOfType("time.Time"), mock.AnythingOfType("time.Time"), 50).
		Return([]storage.SecretReadEntry{}, nil)

	_, err := c.GetSecretReadSummary(context.Background(), SecretReadSummaryRequest{
		SecretID: 1,
		Limit:    60, // over max → capped at 50
	})
	require.NoError(t, err)
	ms.AssertExpectations(t)
}

// ── validation ────────────────────────────────────────────────────────────────

func TestGetSecretReadSummary_SinceEqualUntilReturnsError(t *testing.T) {
	c, _ := newAggCore(t)

	ts := time.Now()
	_, err := c.GetSecretReadSummary(context.Background(), SecretReadSummaryRequest{
		SecretID: 1,
		Since:    ts,
		Until:    ts, // equal → invalid
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidInput))
}

func TestGetSecretReadSummary_SinceAfterUntilReturnsError(t *testing.T) {
	c, _ := newAggCore(t)

	ts := time.Now()
	_, err := c.GetSecretReadSummary(context.Background(), SecretReadSummaryRequest{
		SecretID: 1,
		Since:    ts.Add(time.Hour),
		Until:    ts,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidInput))
}

// ── storage error propagation ─────────────────────────────────────────────────

func TestGetSecretReadSummary_StorageErrorPropagated(t *testing.T) {
	c, ms := newAggCore(t)

	storageErr := errors.New("db is on fire")
	ms.On("GetSecretReadCounts", mock.Anything, uint(1), mock.AnythingOfType("time.Time"), mock.AnythingOfType("time.Time"), 10).
		Return(nil, storageErr)

	_, err := c.GetSecretReadSummary(context.Background(), SecretReadSummaryRequest{SecretID: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db is on fire")
}

// ── nil entries from storage → empty slice ────────────────────────────────────

func TestGetSecretReadSummary_NilEntriesBecomesEmpty(t *testing.T) {
	c, ms := newAggCore(t)

	ms.On("GetSecretReadCounts", mock.Anything, uint(1), mock.AnythingOfType("time.Time"), mock.AnythingOfType("time.Time"), 10).
		Return([]storage.SecretReadEntry(nil), nil)

	summary, err := c.GetSecretReadSummary(context.Background(), SecretReadSummaryRequest{SecretID: 1})
	require.NoError(t, err)
	assert.NotNil(t, summary.Entries)
	assert.Len(t, summary.Entries, 0)
	assert.Equal(t, int64(0), summary.TotalReads)
}
