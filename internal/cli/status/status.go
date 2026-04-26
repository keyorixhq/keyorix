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

// PingCmd represents the ping command
var PingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Test connectivity to remote server",
	Long:  "Test network connectivity and response time to remote server",
	RunE:  runPing,
}

func runStatus(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.Load("keyorix.yaml")
	if err != nil {
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

func runPing(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.Load("keyorix.yaml")
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	if cfg.Storage.Type != "remote" {
		return fmt.Errorf("ping command only works with remote storage")
	}

	if cfg.Storage.Remote == nil {
		return fmt.Errorf("remote storage not configured")
	}

	fmt.Printf("🏓 Pinging %s...\n", cfg.Storage.Remote.BaseURL)

	// Perform multiple pings
	const pingCount = 3
	var totalDuration time.Duration
	successCount := 0

	for i := 0; i < pingCount; i++ {
		service, err := common.InitializeCoreService()
		if err != nil {
			fmt.Printf("Ping %d: ❌ Failed to initialize (%s)\n", i+1, err.Error())
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		err = service.HealthCheck(ctx)
		duration := time.Since(start)
		cancel()

		if err != nil {
			fmt.Printf("Ping %d: ❌ Failed (%s) - %v\n", i+1, err.Error(), duration)
		} else {
			fmt.Printf("Ping %d: ✅ Success - %v\n", i+1, duration)
			totalDuration += duration
			successCount++
		}

		// Wait between pings (except for the last one)
		if i < pingCount-1 {
			time.Sleep(1 * time.Second)
		}
	}

	// Show summary
	fmt.Println("\n📈 Summary")
	fmt.Println("==========")
	fmt.Printf("Pings sent:     %d\n", pingCount)
	fmt.Printf("Successful:     %d\n", successCount)
	fmt.Printf("Failed:         %d\n", pingCount-successCount)

	if successCount > 0 {
		avgDuration := totalDuration / time.Duration(successCount)
		fmt.Printf("Average time:   %v\n", avgDuration)
	}

	if successCount == pingCount {
		fmt.Printf("Status:         ✅ All pings successful\n")
	} else if successCount > 0 {
		fmt.Printf("Status:         ⚠️  Partial connectivity\n")
	} else {
		fmt.Printf("Status:         ❌ No connectivity\n")
	}

	return nil
}
