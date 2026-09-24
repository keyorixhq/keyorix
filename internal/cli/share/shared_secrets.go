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
	sharedSecretsUserID uint
)

var sharedSecretsCmd = &cobra.Command{
	Use:   "shared-secrets",
	Short: "List secrets shared with a user (defaults to yourself)",
	RunE:  runSharedSecrets,
}

func init() {
	sharedSecretsCmd.Flags().UintVar(&sharedSecretsUserID, "user-id", 0,
		"User ID (defaults to yourself; viewing another user's shared secrets requires an admin permission and rank over that user in remote mode)")
}

func runSharedSecrets(cmd *cobra.Command, args []string) error {
	if rc, ok := common.NewRemoteClient(); ok {
		// GET /api/v1/shared-secrets (--user-id 0, i.e. omitted) for the
		// caller's own shares, or GET /api/v1/users/{id}/shared-secrets for an
		// arbitrary target — the admin-scoped route added alongside this
		// change (CLI-split inventory §6 secondary gap; previously --user-id
		// was silently ignored here).
		return runSharedSecretsRemote(rc, sharedSecretsUserID)
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}
	service := core.NewKeyorixCore(st)

	// cli-connect-007 (info, deliberate — not a bug): unlike the remote branch
	// above (now admin-rank-ceiling-checked via ListSharedSecretsForUser),
	// --user-id is not checked against the invoking operator here at all —
	// ListSharedSecrets (internal/core/sharing_query.go) takes a bare userID
	// with no caller/actor parameter at all, and --user-id 0 (the new default)
	// fails its own validation ("user ID is required") rather than resolving
	// to "myself", since embedded/local mode has no authenticated-user concept
	// (share/remote.go:7-9) to default to. An embedded admin can query any
	// user's shared secrets by ID. The residual risk is if embedded mode is
	// ever pointed at a genuinely shared/multi-tenant backend (the scenario
	// common.go's InitializeCoreService warning already contemplates for the
	// cli-connect-004/#G67 ResolveActorID fix) — then this becomes an
	// unrestricted enumeration surface. If that deployment shape ever becomes
	// real, route this through common.ResolveActorID() and an actor-aware,
	// permission-checked core variant, consistent with how group_shares.go's
	// ListGroupShares call was hardened in #G10.
	//
	// Call service
	ctx := context.Background()
	secrets, err := service.ListSharedSecrets(ctx, sharedSecretsUserID)
	if err != nil {
		return fmt.Errorf("failed to list shared secrets: %w", err)
	}

	// Print result
	if len(secrets) == 0 {
		fmt.Println("No shared secrets found for this user.")
		return nil
	}

	// Create a tabwriter for formatted output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tTYPE\tPROJECT\tENVIRONMENT\tCREATED BY\tCREATED AT") //nolint:errcheck
	for _, secret := range secrets {
		fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%s\t%s\n", //nolint:errcheck
			secret.ID,
			secret.Name,
			secret.Type,
			secret.ProjectID,
			secret.EnvironmentID,
			secret.CreatedBy,
			secret.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	_ = w.Flush() // #nosec G104

	return nil
}
