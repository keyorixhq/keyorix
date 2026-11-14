package core

// VALIDATION-TYPED-NOV-1 item 3: the i18n "ErrorValidation" refusals of the secret-version
// reads and of the environment clone match a sentinel with their text unchanged. A failed
// read of a named environment is a storage read fault when it is not a positive "no such
// environment": it is never worded "Validation error: ...".

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestValidationTyped_VersionsAndEnvCloneRefusals(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c := NewKeyorixCore(new(MockStorage)) // every case refuses before any storage call
	ctx := context.Background()
	cases := []struct {
		name string
		call func() error
	}{
		{"versions/list without secret id", func() error { _, err := c.GetSecretVersions(ctx, 0); return err }},
		{"versions/list without user id", func() error { _, err := c.GetSecretVersionsWithPermissionCheck(ctx, 1, 0); return err }},
		{"versions/get without secret id", func() error { _, err := c.GetSecretVersion(ctx, 0, 1); return err }},
		{"versions/get version 0", func() error { _, err := c.GetSecretVersion(ctx, 1, 0); return err }},
		{"versions/get without user id", func() error { _, err := c.GetSecretVersionWithPermissionCheck(ctx, 1, 0, 1); return err }},
		{"versions/latest without secret id", func() error { _, err := c.GetLatestSecretVersion(ctx, 0); return err }},
		{"versions/latest without user id", func() error { _, err := c.GetLatestSecretVersionWithPermissionCheck(ctx, 1, 0); return err }},
		{"versions/value without user id", func() error { _, err := c.GetSecretValueWithPermissionCheck(ctx, 1, 0); return err }},
		{"versions/value by version without secret id", func() error { _, err := c.GetSecretValueByVersion(ctx, 0, 1); return err }},
		{"versions/value by version 0", func() error { _, err := c.GetSecretValueByVersion(ctx, 1, 0); return err }},
		{"versions/value by version without user id", func() error { _, err := c.GetSecretValueByVersionWithPermissionCheck(ctx, 1, 0, 1); return err }},
		{"env_clone/no ids", func() error { _, err := c.CloneEnvironment(ctx, 0, 1, 2, "u", 1); return err }},
		{"env_clone/same environment", func() error { _, err := c.CloneEnvironment(ctx, 1, 2, 2, "u", 1); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrValidation)
			assert.True(t, strings.HasPrefix(err.Error(), i18n.T("ErrorValidation", nil)), "the text is unchanged: %q", err.Error())
			assert.False(t, IsStorageReadUnavailable(err))
		})
	}
}

func TestValidationTyped_EnvCloneReadsOfTheNamedEnvironments(t *testing.T) {
	_, base := errFamily7SecretWorld(t)
	ctx := context.Background()
	p1, err := base.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	p2, err := base.CreateProject(ctx, &models.Project{Name: "p2"})
	require.NoError(t, err)
	e1, err := base.CreateEnvironment(ctx, &models.Environment{Name: "e1", ProjectID: p1.ID})
	require.NoError(t, err)
	e2, err := base.CreateEnvironment(ctx, &models.Environment{Name: "e2", ProjectID: p1.ID})
	require.NoError(t, err)
	other, err := base.CreateEnvironment(ctx, &models.Environment{Name: "other", ProjectID: p2.ID})
	require.NoError(t, err)
	c := &KeyorixCore{storage: base, now: time.Now}

	t.Run("a missing environment is a typed not-found refusal with its text", func(t *testing.T) {
		for _, which := range []struct {
			name     string
			src, dst uint
		}{{"source", 9999, e2.ID}, {"destination", e1.ID, 9999}} {
			_, err := c.CloneEnvironment(ctx, p1.ID, which.src, which.dst, "u", 1)
			require.Error(t, err, which.name)
			assert.ErrorIs(t, err, storage.ErrEnvironmentNotFound, which.name)
			assert.True(t, strings.HasPrefix(err.Error(), i18n.T("ErrorValidation", nil)), "%s: %q", which.name, err.Error())
			assert.Contains(t, err.Error(), which.name+" environment")
			assert.Contains(t, err.Error(), "not found")
			assert.False(t, IsStorageReadUnavailable(err), which.name)
		}
	})

	t.Run("environments of another project are a validation refusal", func(t *testing.T) {
		_, err := c.CloneEnvironment(ctx, p1.ID, e1.ID, other.ID, "u", 1)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrValidation)
		assert.Contains(t, err.Error(), "must belong to the given project")
	})

	t.Run("a read fault is a storage fault, not a refused input", func(t *testing.T) {
		for i, want := range []string{"source", "destination"} {
			fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
				Method: "GetEnvironment", NthCall: i + 1, Kind: faultstorage.KindError, Err: errors.New("pq: injected environment fault"),
			})
			fc := &KeyorixCore{storage: fs, now: time.Now}
			_, err := fc.CloneEnvironment(ctx, p1.ID, e1.ID, e2.ID, "u", 1)
			require.True(t, fs.Fired(), want)
			require.Error(t, err, want)
			assert.True(t, IsStorageReadUnavailable(err), "%s: the retry class: %v", want, err)
			assert.NotErrorIs(t, err, ErrValidation, want)
			assert.False(t, strings.HasPrefix(err.Error(), i18n.T("ErrorValidation", nil)), "%s: %q reads as a validation refusal", want, err.Error())
			assert.NotContains(t, err.Error(), "injected", "the driver text stays in the log")
		}
	})
}
