package status

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/spf13/cobra"
)

// StatusCmd represents the status command
var StatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check connection health and status",
	Long:  "Check the health and status of the current storage backend",
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	// Load configuration. Pass "" (not the literal "keyorix.yaml") so this
	// resolves via config.Load's normal KEYORIX_CONFIG_PATH → ./keyorix.yaml
	// fallback chain — the same resolution common.InitializeCoreService() below
	// uses. G80 Wave 0c: the hardcoded literal ignored KEYORIX_CONFIG_PATH
	// entirely, so under a container/env-var-configured deployment this always
	// fell through to "No configuration found, using defaults" and displayed
	// "Storage Type: Local" even when InitializeCoreService() (which does
	// respect KEYORIX_CONFIG_PATH) was actually running against remote storage
	// two lines later — the displayed storage type and the one actually used
	// for the health check could silently disagree.
	cfg, err := config.Load("")
	if err != nil {
		// #1644: a Load error means EITHER "no config file yet" OR "a config file is
		// there and failed to parse" -- reporting the latter as "no configuration
		// found, using defaults" is actively misleading (the file exists and is
		// broken, not absent), so surface the real error instead of guessing wrong.
		if !config.IsNotExist(err) {
			return fmt.Errorf("failed to load existing configuration: %w", err)
		}
		fmt.Printf("⚠️  No configuration found, using defaults\n")
		cfg = &config.Config{
			Storage: config.StorageConfig{
				Type: "local",
				Database: config.DatabaseConfig{
					Path: "./secrets.db",
				},
			},
		}
	}

	fmt.Println("📊 System Status")
	fmt.Println("================")

	// Show storage type
	switch cfg.Storage.Type {
	case "remote":
		fmt.Printf("Storage Type: 🌐 Remote\n")
		if cfg.Storage.Remote != nil {
			fmt.Printf("Server URL:   %s\n", cfg.Storage.Remote.BaseURL)
			fmt.Printf("Timeout:      %ds\n", cfg.Storage.Remote.TimeoutSeconds)
		}
	default:
		fmt.Printf("Storage Type: 💾 Local\n")
		fmt.Printf("Database:     %s\n", cfg.Storage.Database.Path)
	}

	// Test connection
	fmt.Printf("Connection:   ")
	service, err := common.InitializeCoreService()
	if err != nil {
		fmt.Printf("❌ Failed to initialize (%s)\n", err.Error())
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	err = service.HealthCheck(ctx)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Unhealthy (%s)\n", err.Error())
		fmt.Printf("Response Time: %v\n", duration)
	} else {
		fmt.Printf("✅ Healthy\n")
		fmt.Printf("Response Time: %v\n", duration)
	}

	return nil
}
