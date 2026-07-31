package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	exampleUsername = "example-user"
)

func main() { // NOSONAR -- go:S3776 cognitive complexity 23; standalone example program
	fmt.Println("🔐 Keyorix Secret CRUD Example")
	fmt.Println("===============================")

	cfg, err := config.Load("keyorix.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err := gorm.Open(sqlite.Open(cfg.Storage.Database.Path), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	if err := db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	storage := store.NewLocalStorage(db)
	service := core.NewKeyorixCore(storage)
	ctx := context.Background()

	projectID := uint(1)
	environmentID := uint(1)

	// Example 1: Create a secret
	fmt.Println("\n📝 Example 1: Create Secret")
	createReq := &core.CreateSecretRequest{
		Name:          "example-api-key",
		Value:         []byte("sk-1234567890abcdef"),
		Type:          "api-key",
		ProjectID:     projectID,
		EnvironmentID: environmentID,
		CreatedBy:     exampleUsername,
	}

	secret, err := service.CreateSecret(ctx, createReq)
	if err != nil {
		log.Printf("Failed to create secret (might already exist): %v", err)
		filter := &coreStorage.SecretFilter{
			ProjectID:     &projectID,
			EnvironmentID: &environmentID,
			Page:          1,
			PageSize:      10,
		}
		secrets, _, err := service.ListSecrets(ctx, filter)
		if err != nil {
			log.Fatalf("Failed to list secrets: %v", err)
		}
		for _, s := range secrets {
			if s.Name == "example-api-key" {
				secret = s
				break
			}
		}
		if secret == nil {
			log.Fatalf("Failed to find or create secret")
		}
	}
	fmt.Printf("✅ Secret created/found: %s (ID: %d)\n", secret.Name, secret.ID)

	// Example 2: Get secret metadata
	fmt.Println("\n📖 Example 2: Get Secret Metadata")
	retrieved, err := service.GetSecret(ctx, secret.ID)
	if err != nil {
		log.Fatalf("Failed to get secret: %v", err)
	}
	fmt.Printf("Secret: %s\n", retrieved.Name)
	fmt.Printf("Type: %s\n", retrieved.Type)
	fmt.Printf("Status: %s\n", retrieved.Status)
	fmt.Printf("Created: %s\n", retrieved.CreatedAt.Format(time.RFC3339))

	// Example 3: Update secret
	fmt.Println("\n🔄 Example 3: Update Secret")
	updateReq := &core.UpdateSecretRequest{
		ID:        secret.ID,
		UpdatedBy: exampleUsername,
	}
	updated, err := service.UpdateSecret(ctx, updateReq)
	if err != nil {
		log.Fatalf("Failed to update secret: %v", err)
	}
	fmt.Printf("✅ Secret updated: %s\n", updated.Name)

	// Example 4: List secrets
	fmt.Println("\n📋 Example 4: List Secrets")
	listFilter := &coreStorage.SecretFilter{
		ProjectID:     &projectID,
		EnvironmentID: &environmentID,
		Page:          1,
		PageSize:      10,
	}
	secrets, total, err := service.ListSecrets(ctx, listFilter)
	if err != nil {
		log.Fatalf("Failed to list secrets: %v", err)
	}
	fmt.Printf("Found %d secrets (total: %d)\n", len(secrets), total)
	for _, s := range secrets {
		fmt.Printf("- %s (ID: %d, Type: %s)\n", s.Name, s.ID, s.Type)
	}

	// Example 5: Create secret with expiration
	fmt.Println("\n⏰ Example 5: Create Secret with Expiration")
	expiration := time.Now().Add(24 * time.Hour)
	maxReads := 5
	tempSecretReq := &core.CreateSecretRequest{
		Name:          "temp-token",
		Value:         []byte("temporary-access-token-12345"),
		Type:          "temp-token",
		ProjectID:     projectID,
		EnvironmentID: environmentID,
		MaxReads:      &maxReads,
		Expiration:    &expiration,
		CreatedBy:     exampleUsername,
	}
	tempSecret, err := service.CreateSecret(ctx, tempSecretReq)
	if err != nil {
		log.Printf("Failed to create temp secret (might already exist): %v", err)
	} else {
		fmt.Printf("✅ Temporary secret created: %s\n", tempSecret.Name)
		if tempSecret.Expiration != nil {
			fmt.Printf("Expires: %s\n", tempSecret.Expiration.Format(time.RFC3339))
		}
		if tempSecret.MaxReads != nil {
			fmt.Printf("Max reads: %d\n", *tempSecret.MaxReads)
		}
	}

	fmt.Println("\n✅ Secret CRUD example completed successfully!")
}
