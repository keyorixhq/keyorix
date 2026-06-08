package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
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
}
