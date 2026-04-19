package main

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/startup"
)

func main() {
	fmt.Println("🚀 Keyorix System Initialization Example")
	fmt.Println("========================================")

	// Example 1: Validate existing setup
	fmt.Println("\n📝 Example 1: Validate Current Setup")
	configPath := "keyorix.yaml"

	// Check if config exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("⚠️  Config file not found: %s\n", configPath)
		fmt.Println("💡 This is expected if you haven't run 'keyorix system init' yet")
		fmt.Println("   Run the following command to initialize:")
		fmt.Println("   keyorix system init")
		return
	}

	// Perform validation
	result, err := startup.ValidateStartup(configPath)
	if err != nil {
		fmt.Printf("❌ Validation failed: %v\n", err)
		if result != nil {
			startup.PrintValidationResult(result)
		}
	} else {
		startup.PrintValidationResult(result)
	}

	// Example 2: Show what files should exist after initialization
	fmt.Println("\n📝 Example 2: Expected File Structure After Init")
	fmt.Println("===============================================")

	expectedFiles := []string{
		"keyorix.yaml",    // Main config file
		"keys/kek.key",     // Key Encryption Key
		"keys/dek.key",     // Data Encryption Key
		"keyorix.db",      // SQLite database
		"keyorix.log",     // Application logs
		"certs/server.crt", // TLS certificate (if TLS enabled)
		"certs/server.key", // TLS private key (if TLS enabled)
	}

	fmt.Println("Files that should exist after running 'keyorix system init':")
	for _, file := range expectedFiles {
		status := "❌"
		if _, err := os.Stat(file); err == nil {
			status = "✅"
		}
		fmt.Printf("   %s %s\n", status, file)
	}

	// Example 3: Show initialization commands
	fmt.Println("\n📝 Example 3: Initialization Commands")
	fmt.Println("====================================")

	commands := []struct {
		command     string
		description string
	}{
		{"keyorix system init", "Initialize all components with default settings"},
		{"keyorix system init --interactive", "Interactive setup wizard"},
		{"keyorix system init --encryption", "Initialize encryption keys only"},
		{"keyorix system init --database", "Initialize database only"},
		{"keyorix system init --config ./my.yaml", "Use custom config file path"},
		{"keyorix system init --force", "Overwrite existing files (dangerous)"},
		{"keyorix system validate", "Validate current system setup"},
		{"keyorix system audit", "Audit file permissions"},
		{"keyorix encryption init", "Initialize encryption separately"},
		{"keyorix encryption status", "Check encryption status"},
	}

	fmt.Println("Available initialization and validation commands:")
	for _, cmd := range commands {
		fmt.Printf("   %-35s # %s\n", cmd.command, cmd.description)
	}

	// Example 4: Show configuration template structure
	fmt.Println("\n📝 Example 4: Configuration Structure")
	fmt.Println("====================================")

	configSections := []struct {
		section     string
		description string
	}{
		{"locale", "Language and localization settings"},
		{"server.http", "HTTP server configuration"},
		{"server.grpc", "gRPC server configuration"},
		{"storage.database", "Database connection settings"},
		{"storage.encryption", "Encryption key paths and settings"},
		{"secrets", "Secret management limits and chunking"},
		{"security", "File permission and security policies"},
		{"soft_delete", "Soft delete and retention settings"},
		{"purge", "Automatic cleanup scheduling"},
	}

	fmt.Println("Configuration sections in keyorix.yaml:")
	for _, section := range configSections {
		fmt.Printf("   %-20s # %s\n", section.section, section.description)
	}

	// Example 5: Security recommendations
	fmt.Println("\n📝 Example 5: Security Recommendations")
	fmt.Println("=====================================")

	recommendations := []string{
		"Always run 'keyorix system validate' before starting the system",
		"Keep encryption keys (KEK/DEK) in a secure location with 0600 permissions",
		"Enable file permission checks in production environments",
		"Use TLS for all network communications in production",
		"Regularly rotate encryption keys using 'keyorix encryption rotate'",
		"Monitor file permissions with 'keyorix system audit'",
		"Backup encryption keys securely before key rotation",
		"Use strong, unique passwords for any interactive setup",
	}

	fmt.Println("Security best practices:")
	for i, rec := range recommendations {
		fmt.Printf("   %d. %s\n", i+1, rec)
	}

	fmt.Println("\n✅ Example completed!")
	fmt.Println("💡 Next steps:")
	fmt.Println("   1. Run 'keyorix system init' to set up your system")
	fmt.Println("   2. Run 'keyorix system validate' to check the setup")
	fmt.Println("   3. Run 'keyorix encryption status' to verify encryption")
	fmt.Println("   4. Start using Keyorix for secure secret management!")
}
