// Package risk provides `keyorix risk` — the risk register / exceptions (ISO 27001
// A.5.8 risk treatment): governed, time-bound acceptances of a known control gap.
// Talks to /api/v1/risk-exceptions (list reads system.read; add/revoke system.write).
package risk

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// RiskCmd is the `keyorix risk` command.
var RiskCmd = &cobra.Command{
	Use:   "risk",
	Short: "Risk register — governed, time-bound exceptions to control gaps (A.5.8)",
	Long: `Record and review accepted risk exceptions: a known control gap, accepted by
an owner with a justification, that sunsets at a fixed date. An active exception is
the evidence that a gap is governed (accepted with a deadline) rather than ignored.`,
}

type exceptionView struct {
	ID            uint   `json:"id"`
	Title         string `json:"title"`
	Category      string `json:"category"`
	Reference     string `json:"reference"`
	Justification string `json:"justification"`
	Status        string `json:"status"`
	ExpiresAt     string `json:"expires_at"`
	CreatedBy     uint   `json:"created_by"`
}

var listAll bool

var listCmd = &cobra.Command{
	Use:          "list",
	Short:        "List risk exceptions (active by default; --all includes expired)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		path := "/api/v1/risk-exceptions"
		if listAll {
			path += "?all=true"
		}
		var out struct {
			Exceptions []exceptionView `json:"exceptions"`
		}
		if err := c.Get(context.Background(), path, &out); err != nil {
			return err
		}
		if len(out.Exceptions) == 0 {
			fmt.Println("No risk exceptions.")
			return nil
		}
		for _, e := range out.Exceptions {
			fmt.Printf("[%s] #%d %s (category=%s, ref=%q)\n", e.Status, e.ID, e.Title, e.Category, e.Reference)
			fmt.Printf("        expires %s — %s\n", e.ExpiresAt, e.Justification)
		}
		return nil
	},
}

var (
	addTitle, addCategory, addReference, addJustification, addExpires string
)

var addCmd = &cobra.Command{
	Use:          "add",
	Short:        "Record a risk exception (accept a control gap for a bounded time)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if addTitle == "" || addJustification == "" {
			return fmt.Errorf("--title and --justification are required")
		}
		if addExpires == "" {
			return fmt.Errorf("--expires is required (RFC3339, e.g. 2026-12-31T00:00:00Z)")
		}
		if _, err := time.Parse(time.RFC3339, addExpires); err != nil {
			return fmt.Errorf("--expires must be RFC3339 (e.g. 2026-12-31T00:00:00Z)")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		body := map[string]string{
			"title": addTitle, "category": addCategory, "reference": addReference,
			"justification": addJustification, "expires_at": addExpires,
		}
		var out struct {
			Exception exceptionView `json:"exception"`
		}
		if err := c.Post(context.Background(), "/api/v1/risk-exceptions", body, &out); err != nil {
			return err
		}
		fmt.Printf("Risk exception recorded (id=%d), expiring %s.\n", out.Exception.ID, addExpires)
		return nil
	},
}

var revokeID uint

var revokeCmd = &cobra.Command{
	Use:          "revoke",
	Short:        "Revoke a risk exception before its expiry",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if revokeID == 0 {
			return fmt.Errorf("--id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		if err := c.Delete(context.Background(), fmt.Sprintf("/api/v1/risk-exceptions/%d", revokeID)); err != nil {
			return err
		}
		fmt.Printf("Risk exception %d revoked.\n", revokeID)
		return nil
	},
}

func init() {
	listCmd.Flags().BoolVar(&listAll, "all", false, "Include expired exceptions (history)")
	addCmd.Flags().StringVar(&addTitle, "title", "", "Short name for the accepted risk (required)")
	addCmd.Flags().StringVar(&addCategory, "category", "other", "sod | mfa | rotation | dormant_access | classification | other")
	addCmd.Flags().StringVar(&addReference, "reference", "", "What it applies to (a user, an SoD pair, a secret)")
	addCmd.Flags().StringVar(&addJustification, "justification", "", "Why the risk is accepted (required, recorded for audit)")
	addCmd.Flags().StringVar(&addExpires, "expires", "", "When the exception sunsets (RFC3339, required)")
	revokeCmd.Flags().UintVar(&revokeID, "id", 0, "ID of the exception to revoke (required)")
	RiskCmd.AddCommand(listCmd, addCmd, revokeCmd)
}
