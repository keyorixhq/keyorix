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
	listSecretID uint
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List shares for a secret",
	RunE:  runList,
}

func init() {
	listCmd.Flags().UintVar(&listSecretID, "secret-id", 0, "Secret ID (required)")
	_ = listCmd.MarkFlagRequired("secret-id") // #nosec G104
}

func runList(cmd *cobra.Command, args []string) error {
	if rc, ok := common.NewRemoteClient(); ok {
		return runListRemote(rc, listSecretID)
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}
	service := core.NewKeyorixCore(st)

	// Call service
	ctx := context.Background()
	shares, err := service.ListSecretShares(ctx, listSecretID)
	if err != nil {
		return fmt.Errorf("failed to list shares: %w", err)
	}

	// Print result
	if len(shares) == 0 {
		fmt.Println("No shares found for this secret.")
		return nil
	}

	// Create a tabwriter for formatted output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSECRET ID\tOWNER ID\tRECIPIENT ID\tIS GROUP\tPERMISSION\tCREATED AT") //nolint:errcheck
	for _, share := range shares {
		fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%t\t%s\t%s\n", //nolint:errcheck
			share.ID,
			share.SecretID,
			share.OwnerID,
			share.RecipientID,
			share.IsGroup,
			share.Permission,
			share.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	_ = w.Flush() // #nosec G104

	return nil
}
