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

// newCoreWithMock returns a minimal KeyorixCore backed by a fresh MockStorage.
func newCoreWithMock() (*KeyorixCore, *MockStorage) {
	m := &MockStorage{}
	c := &KeyorixCore{storage: m, now: time.Now}
	return c, m
}

// ---------- CreateSecretTemplate ----------

func TestCreateSecretTemplate_Success(t *testing.T) {
	c, m := newCoreWithMock()
	// CreatedAt/UpdatedAt are set inside CreateSecretTemplate, so use MatchedBy.
	m.On("CreateSecretTemplate", context.Background(), mock.MatchedBy(func(t *models.SecretTemplate) bool {
		return t.Name == "db-prod"
	})).Return(nil)

	req := &CreateSecretTemplateRequest{
		Name:                  "db-prod",
		Description:           "Production DB secrets",
		DefaultClassification: "confidential",
		DefaultTags:           "db,prod",
		DescriptionPattern:    "DB password for {{env}}",
		RotationHintDays:      90,
		CreatedBy:             1,
	}
	tmpl, err := c.CreateSecretTemplate(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "db-prod", tmpl.Name)
	assert.Equal(t, "confidential", tmpl.DefaultClassification)
	assert.Equal(t, uint(1), tmpl.CreatedBy)
}

func TestCreateSecretTemplate_EmptyName(t *testing.T) {
	c, _ := newCoreWithMock()
	_, err := c.CreateSecretTemplate(context.Background(), &CreateSecretTemplateRequest{Name: "  "})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestCreateSecretTemplate_InvalidClassification(t *testing.T) {
	c, _ := newCoreWithMock()
	_, err := c.CreateSecretTemplate(context.Background(), &CreateSecretTemplateRequest{
		Name:                  "tpl",
		DefaultClassification: "topsecret",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid classification")
}

func TestCreateSecretTemplate_StorageError(t *testing.T) {
	c, m := newCoreWithMock()
	m.On("CreateSecretTemplate", context.Background(), mock.MatchedBy(func(t *models.SecretTemplate) bool { return true })).
		Return(errors.New("db error"))
	_, err := c.CreateSecretTemplate(context.Background(), &CreateSecretTemplateRequest{Name: "tpl"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db error")
}

// ---------- GetSecretTemplate ----------

func TestGetSecretTemplate_Found(t *testing.T) {
	c, m := newCoreWithMock()
	want := &models.SecretTemplate{ID: 7, Name: "api-keys"}
	m.On("GetSecretTemplate", context.Background(), uint(7)).Return(want, nil)

	got, err := c.GetSecretTemplate(context.Background(), 7)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestGetSecretTemplate_NotFound(t *testing.T) {
	c, m := newCoreWithMock()
	m.On("GetSecretTemplate", context.Background(), uint(99)).Return(nil, errors.New("secret template not found"))

	_, err := c.GetSecretTemplate(context.Background(), 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------- GetSecretTemplateByName ----------

func TestGetSecretTemplateByName_Found(t *testing.T) {
	c, m := newCoreWithMock()
	want := &models.SecretTemplate{ID: 3, Name: "db-prod"}
	m.On("GetSecretTemplateByName", context.Background(), "db-prod").Return(want, nil)

	got, err := c.GetSecretTemplateByName(context.Background(), "db-prod")
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestGetSecretTemplateByName_NotFound(t *testing.T) {
	c, m := newCoreWithMock()
	m.On("GetSecretTemplateByName", context.Background(), "missing").Return(nil, errors.New("secret template not found"))

	_, err := c.GetSecretTemplateByName(context.Background(), "missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------- ListSecretTemplates ----------

func TestListSecretTemplates_Empty(t *testing.T) {
	c, m := newCoreWithMock()
	m.On("ListSecretTemplates", context.Background()).Return([]*models.SecretTemplate{}, nil)

	list, err := c.ListSecretTemplates(context.Background())
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestListSecretTemplates_Multiple(t *testing.T) {
	c, m := newCoreWithMock()
	want := []*models.SecretTemplate{{ID: 1, Name: "a"}, {ID: 2, Name: "b"}}
	m.On("ListSecretTemplates", context.Background()).Return(want, nil)

	list, err := c.ListSecretTemplates(context.Background())
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestListSecretTemplates_StorageError(t *testing.T) {
	c, m := newCoreWithMock()
	m.On("ListSecretTemplates", context.Background()).Return(nil, errors.New("storage down"))

	_, err := c.ListSecretTemplates(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage down")
}

// ---------- UpdateSecretTemplate ----------

func TestUpdateSecretTemplate_Success(t *testing.T) {
	c, m := newCoreWithMock()
	existing := &models.SecretTemplate{ID: 5, Name: "old-name"}
	m.On("GetSecretTemplate", context.Background(), uint(5)).Return(existing, nil)
	m.On("UpdateSecretTemplate", context.Background(), mock.MatchedBy(func(t *models.SecretTemplate) bool { return true })).Return(nil)

	updated, err := c.UpdateSecretTemplate(context.Background(), 5, &UpdateSecretTemplateRequest{
		Name:                  "new-name",
		DefaultClassification: "internal",
	})
	require.NoError(t, err)
	assert.Equal(t, "new-name", updated.Name)
	assert.Equal(t, "internal", updated.DefaultClassification)
}

func TestUpdateSecretTemplate_NotFound(t *testing.T) {
	c, m := newCoreWithMock()
	m.On("GetSecretTemplate", context.Background(), uint(99)).Return(nil, errors.New("secret template not found"))

	_, err := c.UpdateSecretTemplate(context.Background(), 99, &UpdateSecretTemplateRequest{Name: "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestUpdateSecretTemplate_EmptyName(t *testing.T) {
	c, m := newCoreWithMock()
	existing := &models.SecretTemplate{ID: 5, Name: "old"}
	m.On("GetSecretTemplate", context.Background(), uint(5)).Return(existing, nil)

	_, err := c.UpdateSecretTemplate(context.Background(), 5, &UpdateSecretTemplateRequest{Name: "  "})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestUpdateSecretTemplate_InvalidClassification(t *testing.T) {
	c, m := newCoreWithMock()
	existing := &models.SecretTemplate{ID: 5, Name: "tpl"}
	m.On("GetSecretTemplate", context.Background(), uint(5)).Return(existing, nil)

	_, err := c.UpdateSecretTemplate(context.Background(), 5, &UpdateSecretTemplateRequest{
		Name:                  "tpl",
		DefaultClassification: "ultra-secret",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid classification")
}

func TestUpdateSecretTemplate_StorageError(t *testing.T) {
	c, m := newCoreWithMock()
	existing := &models.SecretTemplate{ID: 5, Name: "tpl"}
	m.On("GetSecretTemplate", context.Background(), uint(5)).Return(existing, nil)
	m.On("UpdateSecretTemplate", context.Background(), mock.MatchedBy(func(t *models.SecretTemplate) bool { return true })).Return(errors.New("write error"))

	_, err := c.UpdateSecretTemplate(context.Background(), 5, &UpdateSecretTemplateRequest{Name: "tpl"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write error")
}

// ---------- DeleteSecretTemplate ----------

func TestDeleteSecretTemplate_Success(t *testing.T) {
	c, m := newCoreWithMock()
	existing := &models.SecretTemplate{ID: 3}
	m.On("GetSecretTemplate", context.Background(), uint(3)).Return(existing, nil)
	m.On("DeleteSecretTemplate", context.Background(), uint(3)).Return(nil)

	err := c.DeleteSecretTemplate(context.Background(), 3)
	require.NoError(t, err)
}

func TestDeleteSecretTemplate_NotFound(t *testing.T) {
	c, m := newCoreWithMock()
	m.On("GetSecretTemplate", context.Background(), uint(99)).Return(nil, errors.New("secret template not found"))

	err := c.DeleteSecretTemplate(context.Background(), 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDeleteSecretTemplate_StorageError(t *testing.T) {
	c, m := newCoreWithMock()
	existing := &models.SecretTemplate{ID: 3}
	m.On("GetSecretTemplate", context.Background(), uint(3)).Return(existing, nil)
	m.On("DeleteSecretTemplate", context.Background(), uint(3)).Return(errors.New("delete failed"))

	err := c.DeleteSecretTemplate(context.Background(), 3)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete failed")
}

// ---------- ApplyTemplate ----------

func TestApplyTemplate_EmptyRequest_GetsTemplateValues(t *testing.T) {
	c, m := newCoreWithMock()
	tmpl := &models.SecretTemplate{
		ID:                    1,
		DefaultClassification: "internal",
		DefaultTags:           "db, prod, legacy",
		DescriptionPattern:    "DB password hint",
	}
	m.On("GetSecretTemplate", context.Background(), uint(1)).Return(tmpl, nil)

	result, err := c.ApplyTemplate(context.Background(), 1, "", "", nil)
	require.NoError(t, err)
	assert.Equal(t, "internal", result.Classification)
	assert.Equal(t, "DB password hint", result.Description)
	assert.Equal(t, []string{"db", "prod", "legacy"}, result.Tags)
}

func TestApplyTemplate_NonEmptyPreserved(t *testing.T) {
	c, m := newCoreWithMock()
	tmpl := &models.SecretTemplate{
		ID:                    2,
		DefaultClassification: "internal",
		DefaultTags:           "db",
		DescriptionPattern:    "hint",
	}
	m.On("GetSecretTemplate", context.Background(), uint(2)).Return(tmpl, nil)

	result, err := c.ApplyTemplate(context.Background(), 2, "confidential", "my desc", []string{"custom"})
	require.NoError(t, err)
	// caller-supplied values are preserved
	assert.Equal(t, "confidential", result.Classification)
	assert.Equal(t, "my desc", result.Description)
	assert.Equal(t, []string{"custom"}, result.Tags)
}

func TestApplyTemplate_UnknownTemplate_Error(t *testing.T) {
	c, m := newCoreWithMock()
	m.On("GetSecretTemplate", context.Background(), uint(999)).Return(nil, errors.New("secret template not found"))

	_, err := c.ApplyTemplate(context.Background(), 999, "", "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestApplyTemplate_EmptyDefaultTags_NoTagsSet(t *testing.T) {
	c, m := newCoreWithMock()
	tmpl := &models.SecretTemplate{ID: 3, DefaultClassification: "public"}
	m.On("GetSecretTemplate", context.Background(), uint(3)).Return(tmpl, nil)

	result, err := c.ApplyTemplate(context.Background(), 3, "", "", nil)
	require.NoError(t, err)
	assert.Nil(t, result.Tags)
}

// ---------- validateTemplateClassification ----------

func TestValidateTemplateClassification(t *testing.T) {
	for _, valid := range []string{"", "public", "internal", "confidential", "restricted"} {
		assert.NoError(t, validateTemplateClassification(valid), "should accept %q", valid)
	}
	assert.Error(t, validateTemplateClassification("topsecret"))
}

