package common

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/delivery"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// InitializeCoreService creates a core service instance using the storage factory
// This function should be used by all CLI commands instead of directly creating storage
func InitializeCoreService() (*core.KeyorixCore, error) {
	// Load configuration
	cfg, err := config.Load("")
	if err != nil {
		// If no config file exists, use default local storage
		cfg = &config.Config{
			Locale: config.LocaleConfig{
				Language:         "en",
				FallbackLanguage: "en",
			},
			Storage: config.StorageConfig{
				Type: "local",
				Database: config.DatabaseConfig{
					Path: "./secrets.db",
				},
			},
		}
	}

	// Initialize i18n system
	if err := i18n.Initialize(cfg); err != nil {
		return nil, fmt.Errorf("failed to initialize i18n: %w", err)
	}

	// Create storage using factory
	factory := storage.NewStorageFactory()
	storageImpl, err := factory.CreateStorage(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	// Create core service and wire credential delivery (ADR-028) so a CLI admin can
	// provision / resend setup links. Best-effort: a delivery misconfig (e.g.
	// mode=smtp with no host) must not break unrelated CLI commands, so on a New
	// error we leave delivery unset — core then falls back to out-of-band (returns
	// the link), which is exactly what a CLI admin wants anyway.
	svc := core.NewKeyorixCore(storageImpl)
	svc.SetSetupTokenTTL(cfg.CredentialDelivery.GetSetupTokenTTL())
	cd := cfg.CredentialDelivery
	if deliverer, derr := delivery.New(delivery.Config{
		Mode:    cd.Mode,
		BaseURL: cd.BaseURL,
		SMTP: delivery.SMTPSettings{
			Host:     cd.SMTP.Host,
			Port:     cd.SMTP.Port,
			Username: cd.SMTP.Username,
			Password: cd.SMTP.GetPassword(),
			From:     cd.SMTP.From,
			TLS:      cd.SMTP.TLS,
		},
	}); derr == nil {
		svc.SetCredentialDelivery(deliverer, cd.BaseURL)
	} else {
		svc.SetCredentialDelivery(nil, cd.BaseURL)
	}
	return svc, nil
}
