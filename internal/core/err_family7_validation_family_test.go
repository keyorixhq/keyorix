package core

// CORE-ERR-FAMILY-7 item 4: the i18n "ErrorValidation" refusals of the groups, secrets,
// catalog, pat and sharing families match a sentinel now, with their text unchanged:
// catalog, pat and sharing (they have no family sentinel) ErrValidation, the secrets
// family ErrSecretInvalidInput, the secret ACL its own ErrInvalidSecretACLRequest.
// Two sites wrapped a storage READ FAULT in the validation text; they are storage faults
// now (ErrStorageReadUnavailable), never a refused input.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestErrFamily7_ValidationRefusalsMatchTheirFamily(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c := NewKeyorixCore(new(MockStorage)) // every case refuses before any storage call
	ctx := context.Background()
	cases := []struct {
		name     string
		call     func() error
		sentinel error
	}{
		{"catalog/project name", func() error { return validateProjectName("") }, ErrValidation},
		{"catalog/identifier", func() error { return validateIdentifier("bad$name") }, ErrValidation},
		{"pat/user", func() error {
			_, err := c.CreateOwnPAT(ctx, 0, "t", nil, nil, 0, 0, nil)
			return err
		}, ErrValidation},
		{"sharing/share", func() error { _, err := c.ShareSecret(ctx, &ShareSecretRequest{}); return err }, ErrValidation},
		{"sharing/update", func() error { _, err := c.UpdateSharePermission(ctx, &UpdateShareRequest{}); return err }, ErrValidation},
		{"sharing/group share", func() error { _, err := c.ShareSecretWithGroup(ctx, &GroupShareSecretRequest{}); return err }, ErrValidation},
		{"secrets/update", func() error { _, err := c.UpdateSecret(ctx, &UpdateSecretRequest{}); return err }, ErrSecretInvalidInput},
		{"secrets/move", func() error { _, err := c.MoveSecret(ctx, 0, 0, nil); return err }, ErrSecretInvalidInput},
		{"secrets/template", func() error {
			_, err := c.CreateSecretTemplate(ctx, &CreateSecretTemplateRequest{Name: "t", DescriptionPattern: strings.Repeat("x", maxSecretDescriptionLen+1)})
			return err
		}, ErrSecretInvalidInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.sentinel)
			assert.True(t, strings.HasPrefix(err.Error(), i18n.T("ErrorValidation", nil)), "the text is unchanged: %q", err.Error())
			assert.False(t, IsStorageReadUnavailable(err))
		})
	}
}

func errFamily7SecretWorld(t *testing.T) (*gorm.DB, *store.LocalStorage) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{}, &models.SecretAccessLog{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.Group{}, &models.UserGroup{}, &models.UserRole{}, &models.SecretAccessSchedule{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
	return db, store.NewLocalStorage(db)
}

// CopySecret's read of the target environment: any fault there must be a storage fault,
// not "Validation error: <driver text>". Every GetEnvironment call of the copy is
// faulted in turn and none may yield a validation refusal; the first (the target read)
// must be ErrStorageReadUnavailable. The later ones (CreateSecret's own environment
// read) return an untyped storage error that handlers mask as 500; not in scope here.
func TestErrFamily7_CopySecretEnvironmentReadFaultIsNotValidation(t *testing.T) {
	db, base := errFamily7SecretWorld(t)
	c := &KeyorixCore{storage: base, now: time.Now}
	ctx := context.Background()
	p1, err := base.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	staging, err := base.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p1.ID})
	require.NoError(t, err)
	prod, err := base.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p1.ID})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: p1.ID}).Error)
	src, err := c.CreateSecret(ctx, &CreateSecretRequest{
		Name: "db-url", Value: []byte("postgres://secret"), ProjectID: p1.ID, EnvironmentID: staging.ID,
		Type: "connection-string", CreatedBy: "owner", OwnerID: 1,
	})
	require.NoError(t, err)

	fs := faultstorage.NewFaultyStorage(base, nil)
	fc := &KeyorixCore{storage: fs, now: time.Now}
	_, err = fc.CopySecret(ctx, src.ID, prod.ID, "dry-run", "owner", 1, "", "")
	require.NoError(t, err)
	n := 0
	for _, call := range fs.Calls() {
		if call.Method == "GetEnvironment" {
			n++
		}
	}
	require.Positive(t, n, "the copy must read the target environment")
	for i := 1; i <= n; i++ {
		fs.Arm(&faultstorage.FaultSpec{Method: "GetEnvironment", NthCall: i, Kind: faultstorage.KindError, Err: errors.New("pq: injected target env fault")})
		_, err := fc.CopySecret(ctx, src.ID, prod.ID, "", "owner", 1, "", "")
		require.True(t, fs.Fired())
		fs.Arm(nil)
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrSecretInvalidInput, "call %d: a read fault is not a refused input", i)
		assert.NotErrorIs(t, err, ErrValidation, "call %d", i)
		assert.False(t, strings.HasPrefix(err.Error(), i18n.T("ErrorValidation", nil)), "call %d: %q reads as a validation refusal", i, err.Error())
		if i == 1 { // the target-environment read itself (secret_copy.go)
			assert.True(t, IsStorageReadUnavailable(err), "the target read fault is the retry class: %v", err)
			assert.NotContains(t, err.Error(), "injected", "the driver text stays in the log")
		}
	}
}

// CreateSecret's read of the requested parent folder: a fault is a storage fault, not
// "parent folder N not found".
func TestErrFamily7_CreateSecretParentReadFaultIsUnavailable(t *testing.T) {
	_, base := errFamily7SecretWorld(t)
	ctx := context.Background()
	p1, err := base.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	env, err := base.CreateEnvironment(ctx, &models.Environment{Name: "dev", ProjectID: p1.ID})
	require.NoError(t, err)
	fs := faultstorage.NewFaultyStorage(base, &faultstorage.FaultSpec{
		Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("pq: injected parent fault"),
	})
	fc := &KeyorixCore{storage: fs, now: time.Now}
	parent := uint(42)
	_, err = fc.CreateSecret(ctx, &CreateSecretRequest{
		Name: "child", Value: []byte("v"), ProjectID: p1.ID, EnvironmentID: env.ID, ParentID: &parent,
		Type: "generic", CreatedBy: "owner", OwnerID: 1,
	})
	require.True(t, fs.Fired(), "the parent read must be reached")
	require.Error(t, err)
	assert.True(t, IsStorageReadUnavailable(err), "a parent read fault is the retry class: %v", err)
	assert.NotContains(t, err.Error(), "not found")
	assert.Contains(t, StorageReadFaultDetail(err), "injected parent fault")
}
