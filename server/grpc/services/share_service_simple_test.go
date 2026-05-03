package services

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestShareServiceCreation(t *testing.T) {
	// Initialize i18n for tests
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	err := i18n.Initialize(cfg)
	require.NoError(t, err)

	// Create an in-memory database for testing
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Create storage
	storage := store.NewLocalStorage(db)

	// Create core service
	coreService := core.NewKeyorixCore(storage)

	// Create share service
	service, err := NewShareService(coreService)
	require.NoError(t, err)
	assert.NotNil(t, service)
}

func TestShareServiceBasicValidation(t *testing.T) {
	// Test that NewShareService accepts nil input (no validation currently)
	service, err := NewShareService(nil)
	assert.NoError(t, err)
	assert.NotNil(t, service)

	// The service will have a nil coreService, which would cause issues in actual use
	// but the constructor doesn't validate this
}
