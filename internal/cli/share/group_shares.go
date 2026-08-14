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
	// connected server (#G66). #G10 (below) closed the OTHER half of this: the
	// core function now self-authorizes, so a future remote endpoint can safely
	// expose it without shipping a new unauthenticated-scope disclosure surface.
	// Adding that endpoint (and this command's remote-client branch) is still
	// out of scope here — it's #G66's fix, not #G10's.
	//
	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}
	service := core.NewKeyorixCore(st)

	// #G10: ListGroupShares now requires an authorized actor. Embedded/local mode has no
	// authenticated session — the operator asserts their own Keyorix user ID via
	// KEYORIX_CLI_ACTOR (common.ResolveActorID, #150) for accountability; it must also
	// hold secrets.read (globally or at this group's shares' scope) or the call is denied,
	// same as every other transport.
	ctx := context.Background()
	shares, err := service.ListGroupShares(ctx, core.ActorTypeUser, common.ResolveActorID(), groupSharesGroupID)
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
