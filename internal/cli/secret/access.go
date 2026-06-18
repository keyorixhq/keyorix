package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	accessID      uint
	accessLogID   uint
	accessLogDays int
)

// accessorRow mirrors the GET /secrets/{id}/access ShareView (camelCase).
type accessorRow struct {
	Username   string `json:"username"`
	Permission string `json:"permission"`
	Source     string `json:"source"`
}

// accessLogRow mirrors a GET /secrets/{id}/access-log entry (PascalCase model JSON).
type accessLogRow struct {
	AccessedBy string `json:"AccessedBy"`
	Action     string `json:"Action"`
	IPAddress  string `json:"IPAddress"`
	AccessTime string `json:"AccessTime"`
}

var accessCmd = &cobra.Command{
	Use:   "access",
	Short: "List who can read a secret (owner + direct + group shares)",
	Long: `Show the effective access list for a secret: every user who can read it, with their
permission and how it was granted. Requires secrets.read at the secret's scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if accessID == 0 {
			return fmt.Errorf("--id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		rows, err := fetchAccessors(context.Background(), c, accessID)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("No accessors.")
			return nil
		}
		fmt.Printf("%-24s %-10s %s\n", "USER", "PERMISSION", "SOURCE")
		for _, r := range rows {
			fmt.Printf("%-24s %-10s %s\n", r.Username, r.Permission, r.Source)
		}
		return nil
	},
}

var accessLogCmd = &cobra.Command{
	Use:   "access-log",
	Short: "Show a secret's recent reads (who/when/from where)",
	Long: `List the recent access-log entries for a secret. Requires secrets.read at the
secret's scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if accessLogID == 0 {
			return fmt.Errorf("--id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		rows, err := fetchAccessLog(context.Background(), c, accessLogID, accessLogDays)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("No reads in the window.")
			return nil
		}
		fmt.Printf("%-24s %-8s %-18s %s\n", "ACCESSED BY", "ACTION", "IP", "TIME")
		for _, r := range rows {
			fmt.Printf("%-24s %-8s %-18s %s\n", r.AccessedBy, r.Action, r.IPAddress, r.AccessTime)
		}
		return nil
	},
}

// fetchAccessors GETs the effective access list (split out for httptest tests).
func fetchAccessors(ctx context.Context, c *common.RemoteClient, id uint) ([]accessorRow, error) {
	var body struct {
		Accessors []accessorRow `json:"accessors"`
	}
	if err := c.Get(ctx, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/access", &body); err != nil {
		return nil, err
	}
	return body.Accessors, nil
}

// fetchAccessLog GETs recent reads. days <= 0 lets the server default (30).
func fetchAccessLog(ctx context.Context, c *common.RemoteClient, id uint, days int) ([]accessLogRow, error) {
	path := "/api/v1/secrets/" + strconv.Itoa(int(id)) + "/access-log"
	if days > 0 {
		path += "?days=" + strconv.Itoa(days)
	}
	var body struct {
		AccessLog []accessLogRow `json:"access_log"`
	}
	if err := c.Get(ctx, path, &body); err != nil {
		return nil, err
	}
	return body.AccessLog, nil
}

func init() {
	accessCmd.Flags().UintVar(&accessID, "id", 0, "Secret ID (required)")
	accessLogCmd.Flags().UintVar(&accessLogID, "id", 0, "Secret ID (required)")
	accessLogCmd.Flags().IntVar(&accessLogDays, "days", 0, "Lookback in days (default server-side: 30)")
	SecretCmd.AddCommand(accessCmd)
	SecretCmd.AddCommand(accessLogCmd)
}
