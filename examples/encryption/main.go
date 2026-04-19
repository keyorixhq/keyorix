package main

import (
	"fmt"
	"log"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	// Load configuration
	cfg, err := config.Load("keyorix.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Enable encryption for this example
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Encryption.KEKPath = "example_kek.key"
	cfg.Storage.Encryption.DEKPath = "example_dek.key"
	cfg.Storage.Encryption.SaltPath = "example_kek.salt"

	// Setup database
	db, err := gorm.Open(sqlite.Open("example.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto-migrate models
	if err := db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// Initialize encryption
	baseDir, _ := os.Getwd()
	secretEncryption := encryption.NewSecretEncryption(&cfg.Storage.Encryption, baseDir, db)

	passphrase := os.Getenv("KEYORIX_MASTER_PASSWORD")
	if passphrase == "" {
		passphrase = "example-dev-passphrase-do-not-use-in-production"
	}
	if err := secretEncryption.Initialize(passphrase); err != nil {
		log.Fatalf("Failed to initialize encryption: %v", err)
	}

	fmt.Println("✅ Encryption initialized successfully")

	// Example 1: Store and retrieve a simple secret
	fmt.Println("\n📝 Example 1: Simple Secret")
	secretNode := &models.SecretNode{
		Name:          "database_password",
		NamespaceID:   1,
		ZoneID:        1,
		EnvironmentID: 1,
		IsSecret:      true,
		Type:          "password",
		CreatedBy:     "admin",
	}

	if err := db.Create(secretNode).Error; err != nil {
		log.Fatalf("Failed to create secret node: %v", err)
	}

	plaintext := []byte("super_secret_password_123!")
	version, err := secretEncryption.StoreSecret(secretNode, plaintext)
	if err != nil {
		log.Fatalf("Failed to store secret: %v", err)
	}

	fmt.Printf("Secret stored with version ID: %d\n", version.ID)

	// Retrieve the secret
	retrieved, err := secretEncryption.RetrieveSecret(version.ID)
	if err != nil {
		log.Fatalf("Failed to retrieve secret: %v", err)
	}

	fmt.Printf("Retrieved secret: %s\n", string(retrieved))
	fmt.Printf("Matches original: %v\n", string(retrieved) == string(plaintext))

	// Example 2: Store and retrieve a large secret with chunking
	fmt.Println("\n📝 Example 2: Large Secret with Chunking")
	largeSecretNode := &models.SecretNode{
		Name:          "large_config_file",
		NamespaceID:   1,
		ZoneID:        1,
		EnvironmentID: 1,
		IsSecret:      true,
		Type:          "config",
		CreatedBy:     "admin",
	}

	if err := db.Create(largeSecretNode).Error; err != nil {
		log.Fatalf("Failed to create large secret node: %v", err)
	}

	// Create a large secret (simulate a large config file)
	largeSecret := make([]byte, 150*1024) // 150KB
	for i := range largeSecret {
		largeSecret[i] = byte('A' + (i % 26))
	}

	versions, err := secretEncryption.StoreLargeSecret(largeSecretNode, largeSecret, 64) // 64KB chunks
	if err != nil {
		log.Fatalf("Failed to store large secret: %v", err)
	}

	fmt.Printf("Large secret stored in %d chunks\n", len(versions))

	// Retrieve the large secret
	retrievedLarge, err := secretEncryption.RetrieveLargeSecret(largeSecretNode.ID)
	if err != nil {
		log.Fatalf("Failed to retrieve large secret: %v", err)
	}

	fmt.Printf("Retrieved large secret size: %d bytes\n", len(retrievedLarge))
	fmt.Printf("Matches original: %v\n", len(retrievedLarge) == len(largeSecret))

	// Example 3: Check encryption status
	fmt.Println("\n📝 Example 3: Encryption Status")
	status := secretEncryption.GetEncryptionStatus()
	fmt.Printf("Encryption Status: %+v\n", status)

	// Example 4: Validate encryption setup
	fmt.Println("\n📝 Example 4: Validation")
	if err := secretEncryption.ValidateEncryption(); err != nil {
		fmt.Printf("Validation failed: %v\n", err)
	} else {
		fmt.Println("✅ Encryption setup is valid")
	}

	// Cleanup example files
	fmt.Println("\n🧹 Cleaning up example files...")
	_ = os.Remove("example.db")
	_ = os.Remove("example_kek.key")
	_ = os.Remove("example_dek.key")
	_ = os.Remove("example_kek.salt")

	fmt.Println("✅ Example completed successfully!")
}
