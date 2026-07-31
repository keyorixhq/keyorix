package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newSecretTemplateTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretTemplate{}))
	return NewLocalStorage(db)
}

func TestCreateAndListSecretTemplates(t *testing.T) {
	ctx := context.Background()
	ls := newSecretTemplateTestStore(t)

	t1 := &models.SecretTemplate{Name: "api-keys", DefaultClassification: "internal", DefaultTags: "api,prod"}
	t2 := &models.SecretTemplate{Name: "db-creds", DefaultClassification: "confidential"}

	require.NoError(t, ls.CreateSecretTemplate(ctx, t1))
	require.NoError(t, ls.CreateSecretTemplate(ctx, t2))
	assert.NotZero(t, t1.ID)
	assert.NotZero(t, t2.ID)

	list, err := ls.ListSecretTemplates(ctx)
	require.NoError(t, err)
	require.Len(t, list, 2)
	// Ordered by name: api-keys < db-creds
	assert.Equal(t, "api-keys", list[0].Name)
	assert.Equal(t, "db-creds", list[1].Name)
}

func TestGetSecretTemplate_Found(t *testing.T) {
	ctx := context.Background()
	ls := newSecretTemplateTestStore(t)

	tmpl := &models.SecretTemplate{Name: "my-tpl", RotationHintDays: 30}
	require.NoError(t, ls.CreateSecretTemplate(ctx, tmpl))

	got, err := ls.GetSecretTemplate(ctx, tmpl.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "my-tpl", got.Name)
	assert.Equal(t, 30, got.RotationHintDays)
}

func TestGetSecretTemplate_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newSecretTemplateTestStore(t)

	_, err := ls.GetSecretTemplate(ctx, 9999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetSecretTemplate_DBError(t *testing.T) {
	ctx := context.Background()
	// No AutoMigrate — provoke a real "no such table" error.
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	ls := NewLocalStorage(db)

	_, err = ls.GetSecretTemplate(ctx, 1)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not found")
}

func TestGetSecretTemplateByName_Found(t *testing.T) {
	ctx := context.Background()
	ls := newSecretTemplateTestStore(t)

	tmpl := &models.SecretTemplate{Name: "find-me", Description: "search by name"}
	require.NoError(t, ls.CreateSecretTemplate(ctx, tmpl))

	got, err := ls.GetSecretTemplateByName(ctx, "find-me")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "find-me", got.Name)
	assert.Equal(t, "search by name", got.Description)
}

func TestGetSecretTemplateByName_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newSecretTemplateTestStore(t)

	_, err := ls.GetSecretTemplateByName(ctx, "does-not-exist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetSecretTemplateByName_DBError(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	ls := NewLocalStorage(db)

	_, err = ls.GetSecretTemplateByName(ctx, "any")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not found")
}

func TestUpdateSecretTemplate(t *testing.T) {
	ctx := context.Background()
	ls := newSecretTemplateTestStore(t)

	tmpl := &models.SecretTemplate{Name: "orig-name", DefaultClassification: "public"}
	require.NoError(t, ls.CreateSecretTemplate(ctx, tmpl))

	tmpl.Name = "updated-name"
	tmpl.DefaultClassification = "restricted"
	tmpl.DefaultTags = "ops"
	require.NoError(t, ls.UpdateSecretTemplate(ctx, tmpl))

	got, err := ls.GetSecretTemplate(ctx, tmpl.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated-name", got.Name)
	assert.Equal(t, "restricted", got.DefaultClassification)
	assert.Equal(t, "ops", got.DefaultTags)
}

func TestDeleteSecretTemplate(t *testing.T) {
	ctx := context.Background()
	ls := newSecretTemplateTestStore(t)

	tmpl := &models.SecretTemplate{Name: "to-delete"}
	require.NoError(t, ls.CreateSecretTemplate(ctx, tmpl))
	require.NotZero(t, tmpl.ID)

	require.NoError(t, ls.DeleteSecretTemplate(ctx, tmpl.ID))

	list, err := ls.ListSecretTemplates(ctx)
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestCreateSecretTemplate_DuplicateName(t *testing.T) {
	ctx := context.Background()
	ls := newSecretTemplateTestStore(t)

	tmpl := &models.SecretTemplate{Name: "dup"}
	require.NoError(t, ls.CreateSecretTemplate(ctx, tmpl))

	dup := &models.SecretTemplate{Name: "dup"}
	err := ls.CreateSecretTemplate(ctx, dup)
	require.Error(t, err, "inserting a duplicate name should fail the unique constraint")
}

func TestListSecretTemplates_Empty(t *testing.T) {
	ctx := context.Background()
	ls := newSecretTemplateTestStore(t)

	list, err := ls.ListSecretTemplates(ctx)
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestListSecretTemplates_DBError(t *testing.T) {
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	ls := NewLocalStorage(db)

	_, err = ls.ListSecretTemplates(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list secret templates")
}
