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
	fmt.Println("📊 System Status")
	fmt.Println("================")

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
	cfg, cfgErr := config.Load("")
	if cfgErr != nil && !config.IsNotExist(cfgErr) {
		// #1644: a Load error means EITHER "no config file yet" OR "a config file is
		// there and failed to parse" -- reporting the latter as "no configuration
		// found, using defaults" is actively misleading (the file exists and is
		// broken, not absent), so surface the real error instead of guessing wrong.
		// Exit 2 (usage/config error): we don't have a valid config to interpret,
		// distinct from a target we resolved but couldn't reach (exit 1).
		return common.ExitUsageError(fmt.Errorf("failed to load existing configuration: %w", cfgErr))
	}

	// keyorix.yaml's storage.type: remote (the server-to-server RemoteStorage
	// relay config) already resolves and health-checks correctly below via
	// InitializeCoreService/HealthCheck -- left untouched when present. But a
	// remote TARGET configured via `keyorix connect` (~/.keyorix/cli.yaml) or
	// KEYORIX_SERVER/KEYORIX_TOKEN env vars is invisible to config.Load /
	// cfg.Storage.Type entirely -- a completely separate mechanism (see
	// common.ResolveRemote's doc) -- so without this check that configuration
	// would silently fall through to the "Local" branch below and read/create
	// a stray local secrets.db despite the operator believing `status` was
	// checking a real server (the exact defect class this review exists to
	// close). Checked only when cfg itself does NOT already say remote, so an
	// existing keyorix.yaml storage.type: remote deployment's behavior is
	// completely unchanged.
	if cfgErr != nil || cfg.Storage.Type != "remote" {
		if rc, ok := common.NewRemoteClient(); ok {
			return runStatusRemote(rc)
		}
	}

	if cfgErr != nil {
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
		return common.ExitUnhealthy(fmt.Errorf("failed to initialize storage: %w", err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	err = service.HealthCheck(ctx)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Unhealthy (%s)\n", err.Error())
		fmt.Printf("Response Time: %v\n", duration)
		return common.ExitUnhealthy(err)
	}
	fmt.Printf("✅ Healthy\n")
	fmt.Printf("Response Time: %v\n", duration)
	return nil
}

// runStatusRemote reports connectivity to the server resolved via
// common.NewRemoteClient (the KEYORIX_SERVER/KEYORIX_TOKEN env vars or
// `keyorix connect`'s ~/.keyorix/cli.yaml -- see runStatus's doc comment for
// why this is checked separately from cfg.Storage.Type) by calling its
// unauthenticated GET /health (server/http/handlers/health.go) -- never
// through common.InitializeCoreService()'s local/embedded storage path, so
// this command cannot silently fall back to a stray local file once this
// kind of remote target is configured.
//
// Exit code contract (2026-09-05, a deliberate breaking change from the prior
// always-exit-0 behavior -- see release notes): 0 healthy, 1 unhealthy or
// unreachable, 2 usage/config error. A failed health check is both printed
// ("❌ Unhealthy") AND returned as a non-zero exit via common.ExitUnhealthy --
// a caller scripting on this command's exit code must be able to detect an
// unreachable target without parsing stdout.
func runStatusRemote(rc *common.RemoteClient) error {
	fmt.Printf("Storage Type: 🌐 Remote\n")
	fmt.Printf("Server URL:   %s\n", rc.Endpoint)

	fmt.Printf("Connection:   ")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err := rc.GetRaw(ctx, "/health")
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Unhealthy (%s)\n", err.Error())
		fmt.Printf("Response Time: %v\n", duration)
		return common.ExitUnhealthy(err)
	}
	fmt.Printf("✅ Healthy\n")
	fmt.Printf("Response Time: %v\n", duration)
	return nil
}

func runPing(cmd *cobra.Command, args []string) error {
	// Load configuration. Same KEYORIX_CONFIG_PATH-respecting fix as runStatus.
	cfg, err := config.Load("")
	if err != nil {
		return common.ExitUsageError(fmt.Errorf("failed to load configuration: %w", err))
	}

	if cfg.Storage.Type != "remote" {
		return common.ExitUsageError(fmt.Errorf("ping command only works with remote storage"))
	}

	if cfg.Storage.Remote == nil {
		return common.ExitUsageError(fmt.Errorf("remote storage not configured"))
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
		return nil
	}
	if successCount > 0 {
		fmt.Printf("Status:         ⚠️  Partial connectivity\n")
		return common.ExitUnhealthy(fmt.Errorf("%d/%d pings failed", pingCount-successCount, pingCount))
	}
	fmt.Printf("Status:         ❌ No connectivity\n")
	return common.ExitUnhealthy(fmt.Errorf("all %d pings failed", pingCount))
}
