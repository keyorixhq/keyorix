package invite

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	resendID      uint
	resendBy      string
	resendProject string
)

var resendCmd = &cobra.Command{
	Use:   "resend",
	Short: "Reissue and redeliver an invitation's setup link (ADR-028)",
	Long: "Reissue a pending invitation's accept link, invalidating any prior link, and\n" +
		"deliver it again. In out-of-band mode the link is printed for you to relay.\n" +
		"Throttled per the ADR-028 resend limits.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if resendID == 0 {
			return errors.New("invitation id is required (use --id)")
		}
		if resendBy == "" {
			return errors.New("acting admin email is required (use --by)")
		}
		ctx := context.Background()

		// Remote mode: reissue the link through the real hub REST API -- see
		// send.go's runSendRemote doc comment for why --by isn't used here.
		// Unlike embedded mode below (which reads the invitation row directly
		// to learn its ProjectID), there is no general "look up an
		// invitation's project by ID alone" REST endpoint, so remote mode
		// needs --project (or KEYORIX_PROJECT / the active project) to build
		// the URL.
		if rc, ok := common.NewRemoteClient(); ok {
			return runResendRemote(ctx, rc, resendID, resendProject)
		}

		service, err := common.InitializeCoreService()
		if err != nil {
			return fmt.Errorf("failed to initialize service: %w", err)
		}
		actorID, err := resolveUserID(ctx, service, resendBy)
		if err != nil {
			return err
		}
		// Project-scoped core method (cross-project guard); the embedded CLI admin
		// operates on the invitation's own project.
		inv, err := service.Storage().GetProjectInvitation(ctx, resendID)
		if err != nil {
			return fmt.Errorf("invitation %d not found", resendID)
		}
		if err := requireInviteAuthority(ctx, service, actorID, inv.ProjectID); err != nil {
			return err
		}
		prov, err := service.ResendInvitationLink(ctx, inv.ProjectID, resendID, actorID)
		if err != nil {
			return fmt.Errorf("failed to resend invitation link: %w", err)
		}
		fmt.Printf("Invitation link reissued for invitation %d.\n", resendID)
		common.PrintProvisionResult(prov)
		return nil
	},
}

func init() {
	resendCmd.Flags().UintVar(&resendID, "id", 0, "Invitation ID (required)")
	resendCmd.Flags().StringVar(&resendBy, "by", "", "Acting admin email (required, for audit)")
	resendCmd.Flags().StringVar(&resendProject, "project", "",
		"Project name (or use KEYORIX_PROJECT / active project) -- required in remote mode; "+
			"embedded mode infers it directly from the invitation row")
	_ = resendCmd.MarkFlagRequired("id")
	_ = resendCmd.MarkFlagRequired("by")
}

// runResendRemote reissues the invitation's setup link via POST
// /api/v1/projects/{id}/invitations/{invitationId}/resend, matching
// ResendInvitation's response shape ({"setup_link": ...}) exactly
// (server/http/handlers/invitations.go).
func runResendRemote(ctx context.Context, rc *common.RemoteClient, id uint, projectFlag string) error {
	projectName, err := common.ResolveProject(projectFlag)
	if err != nil {
		return err
	}
	projectID, err := resolveProjectIDRemote(ctx, rc, projectName)
	if err != nil {
		return err
	}
	fmt.Printf("Target: %s (project %q, id=%d)\n", rc.Endpoint, projectName, projectID)

	var resp struct {
		SetupLink *core.ProvisionSetupResult `json:"setup_link"`
	}
	path := fmt.Sprintf("/api/v1/projects/%d/invitations/%d/resend", projectID, id)
	if err := rc.Post(ctx, path, nil, &resp); err != nil {
		return fmt.Errorf("failed to resend invitation link: %w", err)
	}
	fmt.Printf("Invitation link reissued for invitation %d.\n", id)
	common.PrintProvisionResult(resp.SetupLink)
	return nil
}
