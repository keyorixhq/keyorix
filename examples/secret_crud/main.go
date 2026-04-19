package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/local"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	fmt.Println("🔐 Keyorix Secret CRUD Example")
	fmt.Println("===============================")

	// Load configuration
	cfg, err := config.Load("keyorix.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Connect to database
	db, err := gorm.Open(sqlite.Open(cfg.Storage.Database.Path), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto-migrate models (ensure tables exist)
	if err := db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// Initialize storage and core service
	storage := local.NewLocalStorage(db)
	service := core.NewKeyorixCore(storage)

	// Example 1: Create a secret
	fmt.Println("\n📝 Example 1: Create Secret")
	createReq := &core.CreateSecretRequest{
		Name:          "example-api-key",
		Value:         []byte("sk-1234567890abcdef"),
		Type:          "api-key",
		NamespaceID:   1,
		ZoneID:        1,
		EnvironmentID: 1,
		CreatedBy:     "example-user",
	}

	ctx := context.Background()
	namespaceID := uint(1)
	zoneID := uint(1)
	environmentID := uint(1)
	
	secret, err := service.CreateSecret(ctx, createReq)
	if err != nil {
		log.Printf("Failed to create secret (might already exist): %v", err)
		// Try to get existing secret by listing and finding it
		filter := &coreStorage.SecretFilter{
			NamespaceID:   &namespaceID,
			ZoneID:        &zoneID,
			EnvironmentID: &environmentID,
			Page:          1,
			PageSize:      10,
		}
		secrets, _, err := service.ListSecrets(ctx, filter)
		if err != nil {
			log.Fatalf("Failed to list secrets: %v", err)
		}
		
		// Find the secret by name
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
		UpdatedBy: "example-user",
	}

	updated, err := service.UpdateSecret(ctx, updateReq)
	if err != nil {
		log.Fatalf("Failed to update secret: %v", err)
	}

	fmt.Printf("✅ Secret updated: %s\n", updated.Name)
	fmt.Printf("Type: %s\n", updated.Type)

	// Example 4: List secrets
	fmt.Println("\n📋 Example 4: List Secrets")
	listFilter := &coreStorage.SecretFilter{
		NamespaceID:   &namespaceID,
		ZoneID:        &zoneID,
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
	expiration := time.Now().Add(24 * time.Hour) // Expires in 24 hours
	maxReads := 5

	tempSecretReq := &core.CreateSecretRequest{
		Name:          "temp-token",
		Value:         []byte("temporary-access-token-12345"),
		Type:          "temp-token",
		NamespaceID:   1,
		ZoneID:        1,
		EnvironmentID: 1,
		MaxReads:      &maxReads,
		Expiration:    &expiration,
		CreatedBy:     "example-user",
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

	// Example 9: CLI Command Examples
	fmt.Println("\n💻 Example 9: CLI Command Examples")
	fmt.Println("==================================")

	cliExamples := []struct {
		description string
		command     string
	}{
		{"Create a secret", "keyorix secret create --name 'db-password' --value 'secret123' --type 'password'"},
		{"Get secret metadata", "keyorix secret get --id " + fmt.Sprintf("%d", secret.ID)},
		{"Get secret value", "keyorix secret get --id " + fmt.Sprintf("%d", secret.ID) + " --show-value"},
		{"List all secrets", "keyorix secret list --namespace 1 --zone 1 --environment 1"},
		{"Search secrets", "keyorix secret search --query 'api' --namespace 1"},
		{"Update secret", "keyorix secret update --id " + fmt.Sprintf("%d", secret.ID) + " --type 'new-type'"},
		{"Get versions", "keyorix secret versions --id " + fmt.Sprintf("%d", secret.ID)},
		{"Interactive create", "keyorix secret create --interactive"},
		{"Create from file", "keyorix secret create --name 'cert' --from-file ./certificate.pem"},
		{"Delete secret", "keyorix secret delete --id " + fmt.Sprintf("%d", secret.ID) + " --force"},
	}

	fmt.Println("Available CLI commands:")
	for _, example := range cliExamples {
		fmt.Printf("%-20s: %s\n", example.description, example.command)
	}

	// Example 10: Best Practices
	fmt.Println("\n🏆 Example 10: Best Practices")
	fmt.Println("=============================")

	bestPractices := []string{
		"Use descriptive secret names with consistent naming conventions",
		"Set appropriate secret types for better organization",
		"Use expiration dates for temporary secrets",
		"Set max reads for one-time use secrets",
		"Regularly rotate long-lived secrets",
		"Use namespaces, zones, and environments for proper isolation",
		"Monitor secret access through audit logs",
		"Use interactive mode for sensitive secret creation",
		"Store large secrets (certificates, keys) from files",
		"Always validate secret retrieval before using values",
	}

	fmt.Println("Secret management best practices:")
	for i, practice := range bestPractices {
		fmt.Printf("%d. %s\n", i+1, practice)
	}

	fmt.Println("\n✅ Secret CRUD example completed successfully!")
	fmt.Println("💡 Try the CLI commands shown above to interact with secrets")
}
