// Package dynamic provides the `keyorix dynamic-secret` CLI — on-demand database
// credentials (ADR-035) from the terminal: list registered targets, issue a
// short-lived lease, and renew/revoke/list leases. All commands talk to the
// server's REST API (the credentials are minted server-side); the issued
// username/password is shown once, on issue.
package dynamic

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// DynamicSecretCmd is the root `keyorix dynamic-secret` command.
var DynamicSecretCmd = &cobra.Command{
	Use:     "dynamic-secret",
	Aliases: []string{"dynamic-secrets", "dyn"},
	Short:   "Issue and manage on-demand database credentials (dynamic secrets)",
}

var (
	flagProjectID int
	flagEnvID     int
	flagTTL       int
)

func init() {
	listCmd.Flags().IntVar(&flagProjectID, "project-id", 0, "Filter by project ID")
	listCmd.Flags().IntVar(&flagEnvID, "environment-id", 0, "Filter by environment ID")
	issueCmd.Flags().IntVar(&flagTTL, "ttl", 0, "Lease TTL in seconds (0 = the config default)")
	renewCmd.Flags().IntVar(&flagTTL, "ttl", 0, "Renewal TTL in seconds (0 = the config default)")

	DynamicSecretCmd.AddCommand(listCmd, issueCmd, leasesCmd, renewCmd, revokeCmd)
}

func client() (*common.RemoteClient, error) {
	c, ok := common.NewRemoteClient()
	if !ok {
		return nil, fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return c, nil
}

type configView struct {
	ID                uint   `json:"id"`
	Name              string `json:"name"`
	ProjectID         uint   `json:"project_id"`
	EnvironmentID     uint   `json:"environment_id"`
	BackendType       string `json:"backend_type"`
	DefaultTTLSeconds int    `json:"default_ttl_seconds"`
	MaxTTLSeconds     int    `json:"max_ttl_seconds"`
}

type issuedLease struct {
	LeaseID   string `json:"lease_id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	ExpiresAt string `json:"expires_at"`
}

type leaseView struct {
	LeaseID   string `json:"lease_id"`
	RoleName  string `json:"role_name"`
	Status    string `json:"status"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List dynamic-secret target configs",
	RunE: func(_ *cobra.Command, _ []string) error {
		c, err := client()
		if err != nil {
			return err
		}
		path := "/api/v1/dynamic-secrets/configs"
		sep := "?"
		if flagProjectID > 0 {
			path += sep + "project_id=" + strconv.Itoa(flagProjectID)
			sep = "&"
		}
		if flagEnvID > 0 {
			path += sep + "environment_id=" + strconv.Itoa(flagEnvID)
		}
		var configs []configView
		if err := c.Get(context.Background(), path, &configs); err != nil {
			return err
		}
		if len(configs) == 0 {
			fmt.Println("No dynamic-secret configs found.")
			return nil
		}
		fmt.Printf("%-5s %-24s %-10s %-8s %-8s\n", "ID", "NAME", "BACKEND", "TTL", "MAXTTL")
		for _, cfg := range configs {
			fmt.Printf("%-5d %-24s %-10s %-8d %-8d\n", cfg.ID, cfg.Name, cfg.BackendType, cfg.DefaultTTLSeconds, cfg.MaxTTLSeconds)
		}
		return nil
	},
}

var issueCmd = &cobra.Command{
	Use:   "issue <config-id>",
	Short: "Issue a short-lived credential from a config (shown once)",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		c, err := client()
		if err != nil {
			return err
		}
		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid config id: %s", args[0])
		}
		var lease issuedLease
		body := map[string]int{"ttl_seconds": flagTTL}
		if err := c.Post(context.Background(), fmt.Sprintf("/api/v1/dynamic-secrets/configs/%d/issue", id), body, &lease); err != nil {
			return err
		}
		fmt.Println("Credential issued — shown once, auto-revokes at expiry.")
		fmt.Printf("  lease:    %s\n", lease.LeaseID)
		fmt.Printf("  username: %s\n", lease.Username)
		fmt.Printf("  password: %s\n", lease.Password)
		fmt.Printf("  expires:  %s\n", lease.ExpiresAt)
		return nil
	},
}

var leasesCmd = &cobra.Command{
	Use:   "leases <config-id>",
	Short: "List leases issued from a config",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		c, err := client()
		if err != nil {
			return err
		}
		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid config id: %s", args[0])
		}
		var leases []leaseView
		if err := c.Get(context.Background(), fmt.Sprintf("/api/v1/dynamic-secrets/configs/%d/leases", id), &leases); err != nil {
			return err
		}
		if len(leases) == 0 {
			fmt.Println("No leases for this config.")
			return nil
		}
		fmt.Printf("%-34s %-16s %-14s %s\n", "LEASE", "ROLE", "STATUS", "EXPIRES")
		for _, l := range leases {
			fmt.Printf("%-34s %-16s %-14s %s\n", l.LeaseID, l.RoleName, l.Status, l.ExpiresAt)
		}
		return nil
	},
}

var renewCmd = &cobra.Command{
	Use:   "renew <lease-id>",
	Short: "Extend an active lease (up to the config's max TTL)",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		c, err := client()
		if err != nil {
			return err
		}
		var out struct {
			LeaseID   string `json:"lease_id"`
			ExpiresAt string `json:"expires_at"`
		}
		body := map[string]int{"ttl_seconds": flagTTL}
		if err := c.Post(context.Background(), fmt.Sprintf("/api/v1/dynamic-secrets/leases/%s/renew", args[0]), body, &out); err != nil {
			return err
		}
		fmt.Printf("Lease %s renewed — new expiry %s\n", out.LeaseID, out.ExpiresAt)
		return nil
	},
}

var revokeCmd = &cobra.Command{
	Use:   "revoke <lease-id>",
	Short: "Revoke an active lease now",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		c, err := client()
		if err != nil {
			return err
		}
		var out struct {
			LeaseID string `json:"lease_id"`
			Status  string `json:"status"`
		}
		if err := c.Post(context.Background(), fmt.Sprintf("/api/v1/dynamic-secrets/leases/%s/revoke", args[0]), map[string]any{}, &out); err != nil {
			return err
		}
		fmt.Printf("Lease %s %s.\n", out.LeaseID, out.Status)
		return nil
	},
}
