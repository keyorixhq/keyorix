package invite

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	revokeID      uint
	revokeBy      string
	revokeProject string
)

var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a pending invitation",
	Long:  "Cancel a pending project invitation by ID (ADR-024).",
	RunE:  runRevoke,
}

func init() {
	revokeCmd.Flags().UintVar(&revokeID, "id", 0, "Invitation ID (required)")
	revokeCmd.Flags().StringVar(&revokeBy, "by", "", "Revoker email address (required, for audit)")
	revokeCmd.Flags().StringVar(&revokeProject, "project", "",
		"Project name (or use KEYORIX_PROJECT / active project) -- required in remote mode; "+
			"embedded mode infers it directly from the invitation row")
	_ = revokeCmd.MarkFlagRequired("id")
	_ = revokeCmd.MarkFlagRequired("by")
}

func runRevoke(cmd *cobra.Command, args []string) error {
	if revokeID == 0 {
		return fmt.Errorf("--id is required")
	}
	ctx := context.Background()

	// Remote mode: revoke through the real hub REST API -- see send.go's
	// runSendRemote doc comment for why --by isn't used here, and
	// resend.go's runResendRemote doc comment for why --project is required
	// here but not in embedded mode.
	if rc, ok := common.NewRemoteClient(); ok {
		return runRevokeRemote(ctx, rc, revokeID, revokeProject)
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	actorID, err := resolveUserID(ctx, service, revokeBy)
	if err != nil {
		return err
	}
	// The core method is project-scoped (cross-project guard); the embedded CLI
	// admin operates on the invitation's own project.
	inv, err := service.Storage().GetProjectInvitation(ctx, revokeID)
	if err != nil {
		return fmt.Errorf("invitation %d not found", revokeID)
	}
	if err := requireInviteAuthority(ctx, service, actorID, inv.ProjectID); err != nil {
		return err
	}
	if err := service.RevokeInvitation(ctx, inv.ProjectID, revokeID, actorID); err != nil {
		return fmt.Errorf("failed to revoke invitation: %w", err)
	}
	fmt.Printf("Invitation %d revoked.\n", revokeID)
	return nil
}

// runRevokeRemote cancels the invitation via DELETE
// /api/v1/projects/{id}/invitations/{invitationId} (server/http/handlers/
// invitations.go's RevokeInvitation, which reports success with no response
// body).
func runRevokeRemote(ctx context.Context, rc *common.RemoteClient, id uint, projectFlag string) error {
	projectName, err := common.ResolveProject(projectFlag)
	if err != nil {
		return err
	}
	projectID, err := resolveProjectIDRemote(ctx, rc, projectName)
	if err != nil {
		return err
	}
	fmt.Printf("Target: %s (project %q, id=%d)\n", rc.Endpoint, projectName, projectID)

	path := fmt.Sprintf("/api/v1/projects/%d/invitations/%d", projectID, id)
	if err := rc.Delete(ctx, path); err != nil {
		return fmt.Errorf("failed to revoke invitation: %w", err)
	}
	fmt.Printf("Invitation %d revoked.\n", id)
	return nil
}
