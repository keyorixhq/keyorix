// Package legalhold provides `keyorix legal-hold` — a deployment-wide litigation /
// investigation hold (ISO 27001 A.5.34 / eDiscovery). While active, the background
// purge jobs are blocked from hard-deleting any records. Talks to /api/v1/legal-hold
// (status reads system.read; place/lift system.write).
package legalhold

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// LegalHoldCmd is the `keyorix legal-hold` command.
var LegalHoldCmd = &cobra.Command{
	Use:   "legal-hold",
	Short: "Deployment-wide legal hold — block purges to preserve records (A.5.34)",
	Long: `Place or lift a litigation/investigation hold. While a hold is active, the
retention-purge, JIT-expiry, and login-prune jobs are blocked from hard-deleting
any records, so data subject to legal hold is preserved.`,
}

type holdView struct {
	ID       uint   `json:"id"`
	Reason   string `json:"reason"`
	PlacedBy uint   `json:"placed_by"`
	PlacedAt string `json:"placed_at"`
}

var statusCmd = &cobra.Command{
	Use:          "status",
	Short:        "Show whether a legal hold is active",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var out struct {
			Active bool     `json:"active"`
			Hold   holdView `json:"hold"`
		}
		if err := c.Get(context.Background(), "/api/v1/legal-hold", &out); err != nil {
			return err
		}
		if !out.Active {
			fmt.Println("No legal hold is active. Purge jobs run normally.")
			return nil
		}
		fmt.Printf("LEGAL HOLD ACTIVE (id=%d) since %s — purges are blocked.\n  Reason: %s\n",
			out.Hold.ID, out.Hold.PlacedAt, out.Hold.Reason)
		return nil
	},
}

var placeReason string

var placeCmd = &cobra.Command{
	Use:          "place",
	Short:        "Place a legal hold (block all purges until lifted)",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if placeReason == "" {
			return fmt.Errorf("--reason is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		var out struct {
			Hold holdView `json:"hold"`
		}
		if err := c.Post(context.Background(), "/api/v1/legal-hold", map[string]string{"reason": placeReason}, &out); err != nil {
			return err
		}
		fmt.Printf("Legal hold placed (id=%d). All purge jobs are now blocked until lifted.\n", out.Hold.ID)
		return nil
	},
}

var liftYes bool

var liftCmd = &cobra.Command{
	Use:          "lift",
	Short:        "Lift the active legal hold (resume purges)",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if !liftYes {
			fmt.Print("Lift the active legal hold? This immediately re-arms purge/retention/JIT-expiry\njobs and cannot be undone from here. Type 'yes' to confirm: ")
			var answer string
			_, _ = fmt.Fscanln(cmd.InOrStdin(), &answer)
			if answer != "yes" {
				fmt.Println("Aborted.")
				return nil
			}
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		if err := c.Delete(context.Background(), "/api/v1/legal-hold"); err != nil {
			return err
		}
		fmt.Println("Legal hold lifted. Purge jobs will resume on their next tick.")
		return nil
	},
}

func init() {
	placeCmd.Flags().StringVar(&placeReason, "reason", "", "Why the hold is placed (required, recorded for audit)")
	liftCmd.Flags().BoolVar(&liftYes, "yes", false, "Skip the confirmation prompt")
	LegalHoldCmd.AddCommand(statusCmd, placeCmd, liftCmd)
}
