package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func factorByKey(s *SecretRiskScore, key string) SecretRiskFactor {
	for _, f := range s.Factors {
		if f.Key == key {
			return f
		}
	}
	return SecretRiskFactor{}
}

func TestComputeSecretRiskScore_HighRisk(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	expired := now.AddDate(0, 0, -3)
	store := new(MockStorage)

	// Expired, never rotated + 400 days old, shared with a 20-member group → high on every axis.
	store.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{
		ID: 1, Name: "stripe-key", OwnerID: 9, Expiration: &expired, CreatedAt: now.AddDate(0, 0, -400),
	}, nil)
	store.On("ListSecretAccessLogs", mock.Anything, uint(1), mock.Anything).Return([]models.SecretAccessLog{}, nil)
	store.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{{IsGroup: true, RecipientID: 5}}, nil)
	members := make([]*models.User, 20)
	for i := range members {
		members[i] = &models.User{ID: uint(100 + i)}
	}
	store.On("ListGroupMembers", mock.Anything, uint(5)).Return(members, nil)

	c := NewKeyorixCore(store)
	c.now = func() time.Time { return now }

	got, err := c.ComputeSecretRiskScore(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, RiskBandHigh, got.Band)
	require.Equal(t, 100, factorByKey(got, "expiry").Score, "expired")
	require.Equal(t, 100, factorByKey(got, "rotation").Score, "never rotated + 400d")
	require.Equal(t, 80, factorByKey(got, "usage").Score, "no reads")
	require.Equal(t, 90, factorByKey(got, "exposure").Score, "21 principals")
	require.GreaterOrEqual(t, got.Score, 90)
}

func TestComputeSecretRiskScore_LowRisk(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	future := now.AddDate(0, 0, 200)
	rotated := now.AddDate(0, 0, -5)
	store := new(MockStorage)

	// Future expiry, freshly rotated, actively read, owner-only → low on every axis.
	store.On("GetSecret", mock.Anything, uint(2)).Return(&models.SecretNode{
		ID: 2, Name: "jwt-key", OwnerID: 9, Expiration: &future, LastRotatedAt: &rotated, CreatedAt: now.AddDate(0, 0, -10),
	}, nil)
	reads := make([]models.SecretAccessLog, 12)
	for i := range reads {
		reads[i] = models.SecretAccessLog{Action: "read"}
	}
	// An update action must not count toward usage.
	reads = append(reads, models.SecretAccessLog{Action: "update"})
	store.On("ListSecretAccessLogs", mock.Anything, uint(2), mock.Anything).Return(reads, nil)
	store.On("ListSharesBySecret", mock.Anything, uint(2)).Return([]*models.ShareRecord{}, nil)

	c := NewKeyorixCore(store)
	c.now = func() time.Time { return now }

	got, err := c.ComputeSecretRiskScore(context.Background(), 2)
	require.NoError(t, err)
	require.Equal(t, RiskBandLow, got.Band)
	require.Equal(t, 10, factorByKey(got, "expiry").Score)
	require.Equal(t, 10, factorByKey(got, "rotation").Score)
	require.Equal(t, 10, factorByKey(got, "usage").Score, "12 reads, update excluded")
	require.Equal(t, 10, factorByKey(got, "exposure").Score, "owner only")
	require.False(t, got.Degraded)
}

// TestComputeSecretRiskScore_DegradedOnListSharesError proves that a failing
// ListSharesBySecret call no longer silently deflates the exposure factor to an
// owner-only count — it now flips Degraded and forces exposure to the worst-case
// score, so a secret that is actually widely shared can't be incorrectly
// deprioritized for rotation because its exposure looked artificially low (#407).
func TestComputeSecretRiskScore_DegradedOnListSharesError(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	future := now.AddDate(0, 0, 200)
	rotated := now.AddDate(0, 0, -5)
	store := new(MockStorage)

	store.On("GetSecret", mock.Anything, uint(3)).Return(&models.SecretNode{
		ID: 3, Name: "widely-shared-key", OwnerID: 9, Expiration: &future, LastRotatedAt: &rotated, CreatedAt: now.AddDate(0, 0, -10),
	}, nil)
	store.On("ListSecretAccessLogs", mock.Anything, uint(3), mock.Anything).Return([]models.SecretAccessLog{}, nil)
	store.On("ListSharesBySecret", mock.Anything, uint(3)).Return(nil, errors.New("simulated shares query failure"))

	c := NewKeyorixCore(store)
	c.now = func() time.Time { return now }

	got, err := c.ComputeSecretRiskScore(context.Background(), 3)
	require.NoError(t, err)
	assert.True(t, got.Degraded, "a failed ListSharesBySecret call must flip Degraded")
	require.NotEmpty(t, got.DegradedReasons)
	assert.Contains(t, got.DegradedReasons[0], "exposure:shares")
	assert.Equal(t, 90, factorByKey(got, "exposure").Score, "an incomplete exposure count must fail toward the worst-case score, not an owner-only low score")
}

// TestComputeSecretRiskScore_DegradedOnListGroupMembersError proves that a failing
// ListGroupMembers call no longer silently skips that group's members from the
// exposure count — it now flips Degraded and forces exposure to the worst-case
// score (#407).
func TestComputeSecretRiskScore_DegradedOnListGroupMembersError(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	future := now.AddDate(0, 0, 200)
	rotated := now.AddDate(0, 0, -5)
	store := new(MockStorage)

	store.On("GetSecret", mock.Anything, uint(4)).Return(&models.SecretNode{
		ID: 4, Name: "group-shared-key", OwnerID: 9, Expiration: &future, LastRotatedAt: &rotated, CreatedAt: now.AddDate(0, 0, -10),
	}, nil)
	store.On("ListSecretAccessLogs", mock.Anything, uint(4), mock.Anything).Return([]models.SecretAccessLog{}, nil)
	store.On("ListSharesBySecret", mock.Anything, uint(4)).Return([]*models.ShareRecord{{IsGroup: true, RecipientID: 7}}, nil)
	store.On("ListGroupMembers", mock.Anything, uint(7)).Return(nil, errors.New("simulated: ListGroupMembers unimplemented on this backend"))

	c := NewKeyorixCore(store)
	c.now = func() time.Time { return now }

	got, err := c.ComputeSecretRiskScore(context.Background(), 4)
	require.NoError(t, err)
	assert.True(t, got.Degraded, "a failed ListGroupMembers call must flip Degraded")
	require.NotEmpty(t, got.DegradedReasons)
	assert.Contains(t, got.DegradedReasons[0], "exposure:group_members:group=7")
	assert.Equal(t, 90, factorByKey(got, "exposure").Score, "an incomplete exposure count must fail toward the worst-case score")
}
