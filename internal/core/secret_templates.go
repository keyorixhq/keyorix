// secret_templates.go — reusable metadata presets for secret creation.
//
// A SecretTemplate pre-fills classification, tags, and description hints
// when creating new secrets. Operators define templates once; developers
// apply them at create time. Template fields act as defaults — they are
// merged into the create request only for fields the caller left empty.
package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CreateSecretTemplateRequest carries the fields for a new secret template.
type CreateSecretTemplateRequest struct {
	Name                  string `json:"name"`
	Description           string `json:"description"`
	DefaultClassification string `json:"default_classification"`
	DefaultTags           string `json:"default_tags"`
	DescriptionPattern    string `json:"description_pattern"`
	RotationHintDays      int    `json:"rotation_hint_days"`
	CreatedBy             uint   `json:"created_by"`
}

// UpdateSecretTemplateRequest carries the fields for updating an existing template.
type UpdateSecretTemplateRequest struct {
	Name                  string `json:"name"`
	Description           string `json:"description"`
	DefaultClassification string `json:"default_classification"`
	DefaultTags           string `json:"default_tags"`
	DescriptionPattern    string `json:"description_pattern"`
	RotationHintDays      int    `json:"rotation_hint_days"`
}

// validClassificationLabels is the accepted set of classification labels.
var validClassificationLabels = map[string]bool{
	"":             true,
	"public":       true,
	"internal":     true,
	"confidential": true,
	"restricted":   true,
}

func validateTemplateClassification(label string) error {
	if !validClassificationLabels[label] {
		return fmt.Errorf("invalid classification %q: must be one of public, internal, confidential, restricted, or empty", label)
	}
	return nil
}

// CreateSecretTemplate creates a new secret template.
func (c *KeyorixCore) CreateSecretTemplate(ctx context.Context, req *CreateSecretTemplateRequest) (*models.SecretTemplate, error) {
	if strings.TrimSpace(req.Name) == "" {
		return nil, fmt.Errorf("template name is required")
	}
	if err := validateTemplateClassification(req.DefaultClassification); err != nil {
		return nil, err
	}

	tmpl := &models.SecretTemplate{
		Name:                  req.Name,
		Description:           req.Description,
		DefaultClassification: req.DefaultClassification,
		DefaultTags:           req.DefaultTags,
		DescriptionPattern:    req.DescriptionPattern,
		RotationHintDays:      req.RotationHintDays,
		CreatedBy:             req.CreatedBy,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	if err := c.storage.CreateSecretTemplate(ctx, tmpl); err != nil {
		return nil, fmt.Errorf("failed to create secret template: %w", err)
	}
	return tmpl, nil
}

// GetSecretTemplate returns a template by ID, or an error if not found.
func (c *KeyorixCore) GetSecretTemplate(ctx context.Context, id uint) (*models.SecretTemplate, error) {
	tmpl, err := c.storage.GetSecretTemplate(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret template: %w", err)
	}
	return tmpl, nil
}

// GetSecretTemplateByName returns a template by name, or an error if not found.
func (c *KeyorixCore) GetSecretTemplateByName(ctx context.Context, name string) (*models.SecretTemplate, error) {
	tmpl, err := c.storage.GetSecretTemplateByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret template by name: %w", err)
	}
	return tmpl, nil
}

// ListSecretTemplates returns all secret templates.
func (c *KeyorixCore) ListSecretTemplates(ctx context.Context) ([]*models.SecretTemplate, error) {
	templates, err := c.storage.ListSecretTemplates(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list secret templates: %w", err)
	}
	return templates, nil
}

// UpdateSecretTemplate updates an existing secret template.
func (c *KeyorixCore) UpdateSecretTemplate(ctx context.Context, id uint, req *UpdateSecretTemplateRequest) (*models.SecretTemplate, error) {
	tmpl, err := c.storage.GetSecretTemplate(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret template: %w", err)
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, fmt.Errorf("template name is required")
	}
	if err := validateTemplateClassification(req.DefaultClassification); err != nil {
		return nil, err
	}

	tmpl.Name = req.Name
	tmpl.Description = req.Description
	tmpl.DefaultClassification = req.DefaultClassification
	tmpl.DefaultTags = req.DefaultTags
	tmpl.DescriptionPattern = req.DescriptionPattern
	tmpl.RotationHintDays = req.RotationHintDays
	tmpl.UpdatedAt = time.Now()

	if err := c.storage.UpdateSecretTemplate(ctx, tmpl); err != nil {
		return nil, fmt.Errorf("failed to update secret template: %w", err)
	}
	return tmpl, nil
}

// DeleteSecretTemplate deletes a secret template by ID.
func (c *KeyorixCore) DeleteSecretTemplate(ctx context.Context, id uint) error {
	if _, err := c.storage.GetSecretTemplate(ctx, id); err != nil {
		return fmt.Errorf("failed to get secret template: %w", err)
	}
	if err := c.storage.DeleteSecretTemplate(ctx, id); err != nil {
		return fmt.Errorf("failed to delete secret template: %w", err)
	}
	return nil
}

// ApplyTemplateResult holds the result of applying a template to a create request.
type ApplyTemplateResult struct {
	Classification string   `json:"classification"`
	Tags           []string `json:"tags"`
	Description    string   `json:"description"`
}

// ApplyTemplate merges template defaults into a partial create request.
// Fields already set in the request are preserved; template values only fill
// in empty/zero fields (template is a default, not an override).
func (c *KeyorixCore) ApplyTemplate(ctx context.Context, templateID uint, classification, description string, tags []string) (*ApplyTemplateResult, error) {
	tmpl, err := c.storage.GetSecretTemplate(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret template: %w", err)
	}

	result := &ApplyTemplateResult{
		Classification: classification,
		Tags:           tags,
		Description:    description,
	}

	if result.Classification == "" && tmpl.DefaultClassification != "" {
		result.Classification = tmpl.DefaultClassification
	}
	if result.Description == "" && tmpl.DescriptionPattern != "" {
		result.Description = tmpl.DescriptionPattern
	}
	if len(result.Tags) == 0 && tmpl.DefaultTags != "" {
		parts := strings.Split(tmpl.DefaultTags, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				result.Tags = append(result.Tags, p)
			}
		}
	}

	return result, nil
}
