package request

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	withdrawID      uint
	withdrawUser    string
	withdrawProject string
)

var withdrawCmd = &cobra.Command{
	Use:   "withdraw",
	Short: "Withdraw your own pending access request",
	Long:  "Cancel a pending access request you own, by ID (self-service, ADR-024).",
	RunE:  runWithdraw,
}

func init() {
	withdrawCmd.Flags().UintVar(&withdrawID, "id", 0, "Access request ID (required)")
	withdrawCmd.Flags().StringVar(&withdrawUser, "user", "", "Requester email address (required — must own the request)")
	withdrawCmd.Flags().StringVar(&withdrawProject, "project", "", "Project name (required when a remote server is configured; embedded mode looks this up from the request row directly)")
	_ = withdrawCmd.MarkFlagRequired("id")
	_ = withdrawCmd.MarkFlagRequired("user")
}

func runWithdraw(cmd *cobra.Command, args []string) error {
	if withdrawID == 0 {
		return fmt.Errorf("--id is required")
	}
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		return runWithdrawRemote(ctx, rc)
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	userID, err := resolveUserID(ctx, service, withdrawUser)
	if err != nil {
		return err
	}
	if err := service.WithdrawAccessRequest(ctx, withdrawID, userID); err != nil {
		return fmt.Errorf("failed to withdraw access request: %w", err)
	}
	fmt.Printf("Access request %d withdrawn.\n", withdrawID)
	return nil
}

// runWithdrawRemote withdraws the request via POST
// /api/v1/projects/{id}/access-requests/{requestId}/withdraw -- deliberately
// self-service server-side (see router.go: no permission middleware on this
// route), so any authenticated caller may withdraw a request, but only their
// OWN: WithdrawAccessRequest (internal/core/invitations.go) checks
// req.UserID == the caller's own session identity and returns the same
// generic "not found" for a wrong-owner request as for a nonexistent one
// (#G14, anti-enumeration), which this surfaces as a plain failed-request
// error rather than trying to pre-verify ownership itself: doing that here
// would require reading the request row via the roles.assign-gated list
// endpoint, a permission an ordinary self-service requester withdrawing their
// OWN request has no reason to hold and the real withdraw route does not
// require either -- see fetchAccessRequest's doc comment for the identical
// reasoning applied to review/list.
//
// --project is required here (unlike embedded mode) because the withdraw
// route is project-scoped in its URL and there is no by-ID-alone lookup this
// CLI can use, for the same reason, to discover it without that extra
// permission.
func runWithdrawRemote(ctx context.Context, rc *common.RemoteClient) error {
	if withdrawProject == "" {
		return fmt.Errorf("--project is required when a remote server is configured (POST " +
			".../projects/{id}/access-requests/{requestId}/withdraw is project-scoped in its URL; embedded " +
			"mode can resolve this from the request row directly, remote mode cannot without it)")
	}
	projectID, err := resolveProjectIDByName(ctx, rc, withdrawProject)
	if err != nil {
		return err
	}
	fmt.Printf("Withdrawing access request %d (requester %s) from project %q (id=%d)...\n",
		withdrawID, withdrawUser, withdrawProject, projectID)

	path := fmt.Sprintf("/api/v1/projects/%d/access-requests/%d/withdraw", projectID, withdrawID)
	if err := rc.Post(ctx, path, map[string]interface{}{}, nil); err != nil {
		return fmt.Errorf("failed to withdraw access request: %w", err)
	}
	fmt.Printf("Access request %d withdrawn.\n", withdrawID)
	return nil
}
