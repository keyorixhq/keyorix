package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// KeyorixCore represents the core business logic layer.
// It orchestrates all business operations while remaining transport-agnostic.
// Methods are organised into domain files:
//   - secrets.go       — Secret CRUD + rotation
//   - versions.go      — Secret version management + value retrieval
//   - permissions.go   — Permission enforcement and checking
//   - users.go         — User and group management
//   - rbac.go          — Role and permission assignment
//   - auth.go          — Session lifecycle + system initialisation
//   - dashboard.go     — Dashboard stats and activity feed
//   - catalog.go       — Namespace / zone / environment passthrough
type KeyorixCore struct {
	storage    storage.Storage
	encryption *encryption.SecretEncryption
	now        func() time.Time // For testability
}

// NewKeyorixCore creates a new instance of the core business logic.
func NewKeyorixCore(storage storage.Storage) *KeyorixCore {
	return &KeyorixCore{
		storage:    storage,
		encryption: nil,
		now:        time.Now,
	}
}

// NewKeyorixCoreWithEncryption creates a new instance with encryption support.
func NewKeyorixCoreWithEncryption(storage storage.Storage, enc *encryption.SecretEncryption) *KeyorixCore {
	return &KeyorixCore{
		storage:    storage,
		encryption: enc,
		now:        time.Now,
	}
}

// Storage returns the underlying storage interface (used by ancillary services such as AnomalyDetector).
func (c *KeyorixCore) Storage() storage.Storage {
	return c.storage
}

// ListActiveSecrets returns all secrets for anomaly detection. Returns empty slice on error.
func (c *KeyorixCore) ListActiveSecrets(ctx context.Context) []models.SecretNode {
	secrets, _, err := c.ListSecrets(ctx, nil)
	if err != nil || secrets == nil {
		return nil
	}
	result := make([]models.SecretNode, 0, len(secrets))
	for _, s := range secrets {
		if s != nil {
			result = append(result, *s)
		}
	}
	return result
}

// HealthCheck checks the health of the core service and its dependencies.
func (c *KeyorixCore) HealthCheck(ctx context.Context) error {
	if c.storage == nil {
		return fmt.Errorf("storage not initialized")
	}
	return c.storage.HealthCheck(ctx)
}
