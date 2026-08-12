package share

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	groupSharesGroupID uint
)

var groupSharesCmd = &cobra.Command{
	Use:   "group-shares",
	Short: "List shares for a group",
	RunE:  runGroupShares,
}

func init() {
	groupSharesCmd.Flags().UintVar(&groupSharesGroupID, "group-id", 0, "Group ID (required)")
	_ = groupSharesCmd.MarkFlagRequired("group-id") // #nosec G104

	// Add to parent command
	ShareCmd.AddCommand(groupSharesCmd)
}

func runGroupShares(cmd *cobra.Command, args []string) error {
	// KNOWN GAP (tracked, not fixed here): unlike every other command in this
	// package, this has no `if rc, ok := common.NewRemoteClient(); ok { ... }`
	// branch — it always reads local embedded storage, silently ignoring a
	// connected server (#G66). Not fixed alongside the rest of #G66 because the
	// only way to serve this from a real server today is to expose
	// core.KeyorixCore.ListGroupShares over HTTP, and that function itself has
	// no caller-scoping of its own (#G10 — "core-layer function performs zero
	// authorization") — any principal could list any group's shares. Adding a
	// remote endpoint for it now would ship a new unauthenticated-scope
	// disclosure surface before #G10's fix lands. Sequence this with #G10.
	//
	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}
	service := core.NewKeyorixCore(st)

	// Call service
	ctx := context.Background()
	shares, err := service.ListGroupShares(ctx, groupSharesGroupID)
	if err != nil {
		return fmt.Errorf("failed to list group shares: %w", err)
	}

	// Print result
	if len(shares) == 0 {
		fmt.Println("No shares found for this group.")
		return nil
	}

	// Create a tabwriter for formatted output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSECRET ID\tOWNER ID\tGROUP ID\tPERMISSION\tCREATED AT") //nolint:errcheck
	for _, share := range shares {
		fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%s\t%s\n", //nolint:errcheck
			share.ID,
			share.SecretID,
			share.OwnerID,
			share.RecipientID,
			share.Permission,
			share.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	_ = w.Flush() // #nosec G104

	return nil
}
