// remote_secret_schedule_test.go — coverage for the three intentional
// remoteUnsupported stubs in remote_secret_schedule.go.
//
// GetSecretAccessSchedule, SetSecretAccessSchedule, and
// DeleteSecretAccessSchedule are all intentional server-side-only operations
// (the schedule enforcement check runs at the HTTP-handler layer; schedule
// management routes are proxied via secret_schedule.go handlers). Each stub
// must return ErrRemoteUnsupported so calling code can branch cleanly.
package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteStorage_GetSecretAccessSchedule_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("https://unused.example"))
	require.NoError(t, err)

	got, err := rs.GetSecretAccessSchedule(context.Background(), 1)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.True(t, errors.Is(err, store.ErrRemoteUnsupported),
		"GetSecretAccessSchedule must wrap ErrRemoteUnsupported, got %v", err)
}

func TestRemoteStorage_SetSecretAccessSchedule_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("https://unused.example"))
	require.NoError(t, err)

	sched := &models.SecretAccessSchedule{
		SecretNodeID: 1,
		AllowedDays:  "*",
		StartHour:    0,
		EndHour:      24,
		Timezone:     "UTC",
	}
	err = rs.SetSecretAccessSchedule(context.Background(), sched)
	require.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrRemoteUnsupported),
		"SetSecretAccessSchedule must wrap ErrRemoteUnsupported, got %v", err)
}

func TestRemoteStorage_DeleteSecretAccessSchedule_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("https://unused.example"))
	require.NoError(t, err)

	err = rs.DeleteSecretAccessSchedule(context.Background(), 1)
	require.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrRemoteUnsupported),
		"DeleteSecretAccessSchedule must wrap ErrRemoteUnsupported, got %v", err)
}
