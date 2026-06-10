package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestDetectProjectDrift_Classification(t *testing.T) {
	const projectID = uint(1)
	store := new(MockStorage)

	store.On("ListEnvironmentsByProject", mock.Anything, projectID).Return([]*models.Environment{
		{ID: 10, ProjectID: projectID, Name: "dev"},
		{ID: 20, ProjectID: projectID, Name: "staging"},
		{ID: 30, ProjectID: projectID, Name: "prod"},
	}, nil)

	// CONSISTENT: present in all three, identical settings.
	// MISSING:    present in dev+staging, absent in prod.
	// META:       present in all three, but type differs in prod.
	store.On("ListProjectSecretsForDrift", mock.Anything, projectID).Return([]storage.DriftSecretRow{
		{EnvironmentID: 10, Name: "CONSISTENT", Type: "password"},
		{EnvironmentID: 20, Name: "CONSISTENT", Type: "password"},
		{EnvironmentID: 30, Name: "CONSISTENT", Type: "password"},

		{EnvironmentID: 10, Name: "MISSING", Type: "api_key"},
		{EnvironmentID: 20, Name: "MISSING", Type: "api_key"},

		{EnvironmentID: 10, Name: "META", Type: "password"},
		{EnvironmentID: 20, Name: "META", Type: "password"},
		{EnvironmentID: 30, Name: "META", Type: "api_key"},
	}, nil)

	c := NewKeyorixCore(store)
	rep, err := c.DetectProjectDrift(context.Background(), projectID)
	require.NoError(t, err)

	require.Equal(t, 3, rep.Summary.EnvironmentCount)
	require.Equal(t, 3, rep.Summary.TotalKeys)
	require.Equal(t, 1, rep.Summary.ConsistentKeys)
	require.Equal(t, 1, rep.Summary.MissingInSome)
	require.Equal(t, 1, rep.Summary.MetadataDrift)

	// Only the two non-consistent keys are listed, name-sorted (META < MISSING).
	require.Len(t, rep.DriftedKeys, 2)

	meta := rep.DriftedKeys[0]
	require.Equal(t, "META", meta.Name)
	require.Equal(t, DriftStatusMetadataOnly, meta.Status)
	require.Empty(t, meta.MissingFrom)
	require.Equal(t, []string{"type"}, meta.DriftFields)

	missing := rep.DriftedKeys[1]
	require.Equal(t, "MISSING", missing.Name)
	require.Equal(t, DriftStatusMissingSome, missing.Status)
	require.Equal(t, []uint{10, 20}, missing.PresentIn)
	require.Equal(t, []uint{30}, missing.MissingFrom)
}

func TestDetectProjectDrift_SingleEnvironmentNoDrift(t *testing.T) {
	const projectID = uint(2)
	store := new(MockStorage)
	store.On("ListEnvironmentsByProject", mock.Anything, projectID).Return([]*models.Environment{
		{ID: 10, ProjectID: projectID, Name: "dev"},
	}, nil)
	store.On("ListProjectSecretsForDrift", mock.Anything, projectID).Return([]storage.DriftSecretRow{
		{EnvironmentID: 10, Name: "A", Type: "password"},
		{EnvironmentID: 10, Name: "B", Type: "password"},
	}, nil)

	c := NewKeyorixCore(store)
	rep, err := c.DetectProjectDrift(context.Background(), projectID)
	require.NoError(t, err)
	require.Equal(t, 2, rep.Summary.TotalKeys)
	require.Equal(t, 2, rep.Summary.ConsistentKeys, "with one environment every key is trivially consistent")
	require.Empty(t, rep.DriftedKeys)
}

func TestDetectProjectDrift_ExpirationAndMaxReadsDrift(t *testing.T) {
	const projectID = uint(3)
	store := new(MockStorage)
	store.On("ListEnvironmentsByProject", mock.Anything, projectID).Return([]*models.Environment{
		{ID: 10, ProjectID: projectID, Name: "dev"},
		{ID: 20, ProjectID: projectID, Name: "prod"},
	}, nil)
	store.On("ListProjectSecretsForDrift", mock.Anything, projectID).Return([]storage.DriftSecretRow{
		// Same type, but prod adds expiration + max_reads → metadata drift on both.
		{EnvironmentID: 10, Name: "TOKEN", Type: "api_key", HasExpiration: false, HasMaxReads: false},
		{EnvironmentID: 20, Name: "TOKEN", Type: "api_key", HasExpiration: true, HasMaxReads: true},
	}, nil)

	c := NewKeyorixCore(store)
	rep, err := c.DetectProjectDrift(context.Background(), projectID)
	require.NoError(t, err)
	require.Len(t, rep.DriftedKeys, 1)
	require.Equal(t, DriftStatusMetadataOnly, rep.DriftedKeys[0].Status)
	require.Equal(t, []string{"expiration", "max_reads"}, rep.DriftedKeys[0].DriftFields)
}
