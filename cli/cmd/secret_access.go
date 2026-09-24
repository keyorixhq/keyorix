// secret_access.go — keyorix secret access / access-log.
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

var secretAccessID int

var secretAccessCmd = &cobra.Command{
	Use:   "access",
	Short: "List who can read a secret (owner + direct + group shares)",
	Long: `Show the effective access list for a secret: every user who can read it,
with their permission and how it was granted. Requires secrets.read.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if secretAccessID == 0 {
			return fmt.Errorf("--id is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		resp, err := client.ListAccessorsWithResponse(context.Background(), secretAccessID)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return fmt.Errorf("list accessors: HTTP %d", resp.StatusCode())
		}
		rows := derefSecretAccessorSlice(resp.JSON200.Data.Accessors)
		if len(rows) == 0 {
			fmt.Println("No accessors.")
			return nil
		}
		fmt.Printf("%-24s %-10s %s\n", "USER", "PERMISSION", "SOURCE")
		for _, r := range rows {
			fmt.Printf("%-24s %-10s %s\n", derefStr(r.Username), derefStr(r.Permission), derefStr(r.Source))
		}
		return nil
	},
}

var (
	secretAccessLogID   int
	secretAccessLogDays int
)

var secretAccessLogCmd = &cobra.Command{
	Use:          "access-log",
	Short:        "Show a secret's recent reads (who/when/from where)",
	Long:         "List the recent access-log entries for a secret. Requires secrets.read.",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if secretAccessLogID == 0 {
			return fmt.Errorf("--id is required")
		}
		client, err := secretAPIClient()
		if err != nil {
			return err
		}
		var params *apiclient.GetSecretAccessLogParams
		if secretAccessLogDays > 0 {
			params = &apiclient.GetSecretAccessLogParams{Days: &secretAccessLogDays}
		}
		resp, err := client.GetSecretAccessLogWithResponse(context.Background(), secretAccessLogID, params)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil || resp.JSON200.Data == nil {
			return fmt.Errorf("get secret access log: HTTP %d", resp.StatusCode())
		}
		rows := derefSecretAccessLogSlice(resp.JSON200.Data.AccessLog)
		if len(rows) == 0 {
			fmt.Println("No reads in the window.")
			return nil
		}
		fmt.Printf("%-24s %-8s %-18s %s\n", "ACCESSED BY", "ACTION", "IP", "TIME")
		for _, r := range rows {
			fmt.Printf("%-24s %-8s %-18s %s\n", derefStr(r.AccessedBy), derefStr(r.Action), derefStr(r.IPAddress), derefStr(r.AccessTime))
		}
		return nil
	},
}

func derefSecretAccessorSlice(s *[]apiclient.SecretAccessor) []apiclient.SecretAccessor {
	if s == nil {
		return nil
	}
	return *s
}

func derefSecretAccessLogSlice(s *[]apiclient.SecretAccessLogEntry) []apiclient.SecretAccessLogEntry {
	if s == nil {
		return nil
	}
	return *s
}

func init() {
	secretAccessCmd.Flags().IntVar(&secretAccessID, "id", 0, "Secret ID (required)")
	secretAccessLogCmd.Flags().IntVar(&secretAccessLogID, "id", 0, "Secret ID (required)")
	secretAccessLogCmd.Flags().IntVar(&secretAccessLogDays, "days", 0, "Lookback in days (default server-side: 30)")
	SecretCmd.AddCommand(secretAccessCmd)
	SecretCmd.AddCommand(secretAccessLogCmd)
}
