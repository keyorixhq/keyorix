package main

import (
	"context"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// This example demonstrates how to use the new unified architecture
// with the existing internationalization system
func main() {
	// Initialize i18n system
	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}

	if err := i18n.Initialize(cfg); err != nil {
		log.Fatalf("Failed to initialize i18n: %v", err)
	}

	// Initialize database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Create storage layer
	storage := store.NewLocalStorage(db)

	// Create core business logic
	coreService := core.NewKeyorixCore(storage)

	// Example usage
	ctx := context.Background()

	// Create a secret
	createReq := &core.CreateSecretRequest{
		Name:          "example-secret",
		Value:         []byte("super-secret-value"),
		NamespaceID:   1,
		ZoneID:        1,
		EnvironmentID: 1,
		Type:          "password",
		CreatedBy:     "example-user",
	}

	fmt.Println("Creating secret...")
	secret, err := coreService.CreateSecret(ctx, createReq)
	if err != nil {
		// Error messages are now internationalized
		fmt.Printf("Error creating secret: %v\n", err)
		return
	}

	fmt.Printf("Secret created successfully: %s (ID: %d)\n", secret.Name, secret.ID)

	// Try to create a duplicate secret (should fail with i18n error)
	fmt.Println("\nTrying to create duplicate secret...")
	_, err = coreService.CreateSecret(ctx, createReq)
	if err != nil {
		// This will show the internationalized error message
		fmt.Printf("Expected error: %v\n", err)
	}

	// Try to get the secret
	fmt.Println("\nRetrieving secret...")
	retrievedSecret, err := coreService.GetSecret(ctx, secret.ID)
	if err != nil {
		fmt.Printf("Error retrieving secret: %v\n", err)
		return
	}

	fmt.Printf("Secret retrieved: %s\n", retrievedSecret.Name)

	// Try to get a non-existent secret (should fail with i18n error)
	fmt.Println("\nTrying to get non-existent secret...")
	_, err = coreService.GetSecret(ctx, 999)
	if err != nil {
		// This will show the internationalized error message
		fmt.Printf("Expected error: %v\n", err)
	}

	// Demonstrate validation errors with i18n
	fmt.Println("\nTrying to create secret with missing name...")
	invalidReq := &core.CreateSecretRequest{
		Name:          "", // Missing name
		Value:         []byte("value"),
		NamespaceID:   1,
		ZoneID:        1,
		EnvironmentID: 1,
		Type:          "password",
		CreatedBy:     "user",
	}

	_, err = coreService.CreateSecret(ctx, invalidReq)
	if err != nil {
		// This will show the internationalized validation error
		fmt.Printf("Validation error: %v\n", err)
	}

	fmt.Println("\n✅ New architecture example completed successfully!")
	fmt.Println("Key benefits demonstrated:")
	fmt.Println("- Unified Storage interface")
	fmt.Println("- Centralized business logic")
	fmt.Println("- Integrated internationalization")
	fmt.Println("- Clean separation of concerns")
}
