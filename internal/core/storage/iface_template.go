package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TemplateStore is the Storage slice for secret templates.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type TemplateStore interface {
	// Secret Template Management — reusable metadata presets for secret creation.
	// Templates pre-fill classification, tags, and description hints at create time.
	CreateSecretTemplate(ctx context.Context, t *models.SecretTemplate) error
	GetSecretTemplate(ctx context.Context, id uint) (*models.SecretTemplate, error)
	GetSecretTemplateByName(ctx context.Context, name string) (*models.SecretTemplate, error)
	ListSecretTemplates(ctx context.Context) ([]*models.SecretTemplate, error)
	// UpdateSecretTemplateFields persists ONLY the six editable columns named by
	// f (plus updated_at) of an EXISTING template row. matched=false means the
	// template is gone.
	//
	// This REPLACES the former UpdateSecretTemplate, a bare GORM Save (#2700).
	// SecretTemplate is HARD-deleted (no DeletedAt), so Save's 0-rows fallback
	// re-INSERTED a template a concurrent delete had removed, with its old id.
	// Integrity only — a template mints nothing by itself — and low severity,
	// stated as such.
	UpdateSecretTemplateFields(ctx context.Context, id uint, f SecretTemplateFieldUpdate, updatedAt time.Time) (matched bool, err error)
	DeleteSecretTemplate(ctx context.Context, id uint) error
}
