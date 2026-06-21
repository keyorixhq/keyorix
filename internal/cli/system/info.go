package system

import (
	"context"
	"fmt"
	"sort"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// systemInfo mirrors the GET /api/v1/system/info response (snake_case DTO), the fields
// this command displays.
type systemInfo struct {
	Version     string          `json:"version"`
	GitCommit   string          `json:"git_commit"`
	GoVersion   string          `json:"go_version"`
	OS          string          `json:"os"`
	Arch        string          `json:"arch"`
	Uptime      string          `json:"uptime"`
	Environment string          `json:"environment"`
	Features    map[string]bool `json:"features"`
	Database    struct {
		Type      string `json:"type"`
		Connected bool   `json:"connected"`
	} `json:"database"`
	Security struct {
		TLSEnabled       bool   `json:"tls_enabled"`
		AuthEnabled      bool   `json:"auth_enabled"`
		EncryptionMethod string `json:"encryption_method"`
		AuditEnabled     bool   `json:"audit_enabled"`
	} `json:"security"`
}

// fetchSystemInfo GETs the server's system info (split out for httptest tests).
func fetchSystemInfo(ctx context.Context, c *common.RemoteClient) (systemInfo, error) {
	var info systemInfo
	if err := c.Get(ctx, "/api/v1/system/info", &info); err != nil {
		return systemInfo{}, err
	}
	return info, nil
}

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show the connected server's build identity and configuration",
	Long: `Display the remote Keyorix server's version, commit, runtime, and feature/security
configuration (GET /system/info). Useful for confirming which build you're talking to.
Requires a connection to a server and system.read.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		info, err := fetchSystemInfo(context.Background(), c)
		if err != nil {
			return err
		}

		fmt.Printf("Version:     %s\n", info.Version)
		fmt.Printf("Commit:      %s\n", info.GitCommit)
		fmt.Printf("Go:          %s\n", info.GoVersion)
		fmt.Printf("Platform:    %s/%s\n", info.OS, info.Arch)
		fmt.Printf("Uptime:      %s\n", info.Uptime)
		fmt.Printf("Environment: %s\n", info.Environment)
		fmt.Printf("Database:    %s (connected=%t)\n", info.Database.Type, info.Database.Connected)
		fmt.Printf("Security:    tls=%t auth=%t audit=%t encryption=%s\n",
			info.Security.TLSEnabled, info.Security.AuthEnabled, info.Security.AuditEnabled, info.Security.EncryptionMethod)

		if len(info.Features) > 0 {
			names := make([]string, 0, len(info.Features))
			for k := range info.Features {
				names = append(names, k)
			}
			sort.Strings(names)
			fmt.Print("Features:    ")
			for i, n := range names {
				if i > 0 {
					fmt.Print(", ")
				}
				fmt.Printf("%s=%t", n, info.Features[n])
			}
			fmt.Println()
		}
		return nil
	},
}
