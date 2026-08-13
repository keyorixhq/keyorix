package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestClassifyMachineIdentity(t *testing.T) {
	ctx := context.Background()

	t.Run("sets the label and audits", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		store.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, ProjectID: 2, Name: "ci"}, nil)
		var saved *models.MachineIdentity
		store.On("TransitionMachineIdentityState", mock.Anything, mock.MatchedBy(func(m *models.MachineIdentity) bool {
			saved = m
			return true
		}), "").Return(true, nil)
		store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
			return e.EventType == "machine_identity.classified"
		})).Return(nil)

		m, err := c.ClassifyMachineIdentity(ctx, 2, 1, ClassificationRestricted, 9)
		require.NoError(t, err)
		assert.Equal(t, "restricted", m.Classification)
		assert.Equal(t, "restricted", saved.Classification)
	})

	t.Run("loses the race against a concurrent transition", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		store.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, ProjectID: 2, Name: "ci", State: MachineActive}, nil)
		store.On("TransitionMachineIdentityState", mock.Anything, mock.Anything, MachineActive).Return(false, nil)

		_, err := c.ClassifyMachineIdentity(ctx, 2, 1, ClassificationRestricted, 9)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrMachineStateConflict)
		store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
	})

	t.Run("invalid level rejected", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		_, err := c.ClassifyMachineIdentity(ctx, 2, 1, "secret", 9)
		require.Error(t, err)
		store.AssertNotCalled(t, "GetMachineIdentity", mock.Anything, mock.Anything)
	})

	t.Run("cross-project machine is not reachable", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		store.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, ProjectID: 2}, nil)
		_, err := c.ClassifyMachineIdentity(ctx, 999, 1, ClassificationInternal, 9) // wrong project
		require.Error(t, err)
		store.AssertNotCalled(t, "TransitionMachineIdentityState", mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestClassifyMachineToken(t *testing.T) {
	ctx := context.Background()

	t.Run("sets the label on a credential of the machine", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		store.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, ProjectID: 2}, nil)
		store.On("GetMachineIdentityCredentialByID", mock.Anything, uint(5)).Return(&models.MachineIdentityCredential{ID: 5, MachineIdentityID: 1}, nil)
		store.On("UpdateMachineIdentityCredential", mock.Anything, mock.MatchedBy(func(cr *models.MachineIdentityCredential) bool {
			return cr.Classification == "confidential"
		})).Return(nil)
		store.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
			return e.EventType == "machine_identity.token_classified"
		})).Return(nil)

		cred, err := c.ClassifyMachineToken(ctx, 2, 1, 5, ClassificationConfidential, 9)
		require.NoError(t, err)
		assert.Equal(t, "confidential", cred.Classification)
	})

	t.Run("credential of another machine is not reachable", func(t *testing.T) {
		store := new(MockStorage)
		c := newMachineCore(store)
		store.On("GetMachineIdentity", mock.Anything, uint(1)).Return(&models.MachineIdentity{ID: 1, ProjectID: 2}, nil)
		store.On("GetMachineIdentityCredentialByID", mock.Anything, uint(5)).Return(&models.MachineIdentityCredential{ID: 5, MachineIdentityID: 99}, nil)
		_, err := c.ClassifyMachineToken(ctx, 2, 1, 5, ClassificationPublic, 9)
		require.Error(t, err)
		store.AssertNotCalled(t, "UpdateMachineIdentityCredential", mock.Anything, mock.Anything)
	})
}

func TestClassificationPosture_CoversMachineEntities(t *testing.T) {
	store := new(MockStorage)
	c := newMachineCore(store)
	// Static secrets + dynamic configs are not the focus here; let their counts be 0/err.
	store.On("ListSecrets", mock.Anything, mock.Anything).Return(nil, int64(0), assertErr())
	store.On("CountDynamicSecretConfigsByClassification", mock.Anything).Return(map[string]int(nil), assertErr())
	store.On("CountMachineIdentitiesByClassification", mock.Anything).Return(map[string]int{"restricted": 2, "": 1}, nil)
	store.On("CountMachineIdentityCredentialsByClassification", mock.Anything).Return(map[string]int{"confidential": 3}, nil)

	p := c.classificationPosture(context.Background(), &CompliancePosture{})
	assert.Equal(t, 3, p.MachineIdentities.Total)
	assert.Equal(t, 2, p.MachineIdentities.Restricted)
	assert.Equal(t, 1, p.MachineIdentities.Unclassified)
	assert.Equal(t, 3, p.MachineCredentials.Total)
	assert.Equal(t, 3, p.MachineCredentials.Confidential)
}

func assertErr() error { return context.Canceled }
