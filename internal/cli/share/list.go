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

	// cli-connect-007 (info, deliberate — not a bug): ListSecretShares is the
	// non-authorization-checked variant (see its doc comment and
	// ListSecretSharesWithPermissionCheck, both in
	// internal/core/sharing_query.go) — unlike HTTP/gRPC, which gate the caller
	// to the secret's owner, this local CLI path does not. That's intentional:
	// embedded/local mode has no authenticated-user concept (share/remote.go:7-9),
	// so there is no caller identity to check against, and this command can
	// enumerate the share list for any --secret-id. The residual risk is if
	// embedded mode is ever pointed at a genuinely shared/multi-tenant backend
	// (the scenario common.go's InitializeCoreService warning already
	// contemplates for the cli-connect-004/#G67 ResolveActorID fix) — then this
	// becomes an unrestricted enumeration surface. If that deployment shape ever
	// becomes real, route this through common.ResolveActorID() and
	// ListSecretSharesWithPermissionCheck instead, consistent with how
	// group_shares.go's ListGroupShares call was hardened in #G10.
	//
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
	fmt.Fprintln(w, "ID\tSECRET ID\tOWNER ID\tRECIPIENT ID\tIS GROUP\tPERMISSION\tCREATED AT\tEXPIRES AT") //nolint:errcheck
	for _, share := range shares {
		fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%t\t%s\t%s\t%s\n", //nolint:errcheck
			share.ID,
			share.SecretID,
			share.OwnerID,
			share.RecipientID,
			share.IsGroup,
			share.Permission,
			share.CreatedAt.Format("2006-01-02 15:04:05"),
			formatShareExpiry(share.ExpiresAt),
		)
	}
	_ = w.Flush() // #nosec G104

	return nil
}
