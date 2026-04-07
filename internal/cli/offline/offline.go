package offline

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// NetworkStatus represents the current network connectivity status
type NetworkStatus struct {
	IsOnline      bool
	LastChecked   time.Time
	RemoteReachable bool
	Error         error
}

// CheckConnectivity checks if the system has network connectivity
func CheckConnectivity(ctx context.Context) *NetworkStatus {
	status := &NetworkStatus{
		LastChecked: time.Now(),
	}

	// First, check basic internet connectivity
	status.IsOnline = checkInternetConnectivity(ctx)
	
	if !status.IsOnline {
		status.Error = fmt.Errorf("no internet connectivity")
		return status
	}

	// If online, check if remote server is reachable
	status.RemoteReachable = checkRemoteServerReachability(ctx)
	
	return status
}

// checkInternetConnectivity performs a basic internet connectivity check
func checkInternetConnectivity(ctx context.Context) bool {
	// Try to resolve a well-known DNS name
	resolver := &net.Resolver{}
	_, err := resolver.LookupHost(ctx, "google.com")
	return err == nil
}

// checkRemoteServerReachability checks if the configured remote server is reachable
func checkRemoteServerReachability(ctx context.Context) bool {
	cfg, err := config.Load("keyorix.yaml")
	if err != nil || cfg.Storage.Type != "remote" || cfg.Storage.Remote == nil {
		return false
	}

	// Create a simple HTTP client with short timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Try to make a HEAD request to the server
	req, err := http.NewRequestWithContext(ctx, "HEAD", cfg.Storage.Remote.BaseURL, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Consider any response (even errors) as reachable
	return true
}

// IsOfflineMode checks if the CLI should operate in offline mode
func IsOfflineMode() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	status := CheckConnectivity(ctx)
	
	// We're in offline mode if we have no internet or remote server is unreachable
	return !status.IsOnline || !status.RemoteReachable
}

// HandleOfflineMode provides user-friendly messaging for offline scenarios
func HandleOfflineMode() error {
	fmt.Println("⚠️  Offline Mode Detected")
	fmt.Println("========================")
	fmt.Println("The CLI has detected that you're currently offline or the remote server is unreachable.")
	fmt.Println()
	fmt.Println("Available options:")
	fmt.Println("1. Check your internet connection and try again")
	fmt.Println("2. Switch to local mode: keyorix config use-local")
	fmt.Println("3. Wait for connectivity to be restored")
	fmt.Println()
	
	return fmt.Errorf("offline mode - remote server not accessible")
}

// GracefulDegradation attempts to switch to local storage when remote is unavailable
func GracefulDegradation() error {
	fmt.Println("🔄 Attempting graceful degradation to local storage...")
	
	// Load current configuration
	cfg, err := config.Load("keyorix.yaml")
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Switch to local storage temporarily
	cfg.Storage.Type = "local"
	if cfg.Storage.Database.Path == "" {
		cfg.Storage.Database.Path = "./secrets.db"
	}

	// Save the updated configuration
	if err := config.Save("keyorix.yaml", cfg); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	fmt.Println("✅ Temporarily switched to local storage")
	fmt.Println("💡 Use 'keyorix config set-remote' to switch back when connectivity is restored")
	
	return nil
}