package invite

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	sendProject string
	sendEmail   string
	sendRole    string
	sendBy      string
)

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send a project invitation",
	Long:  "Invite an email address to a project with an intended role (admin-driven, ADR-024).",
	RunE:  runSend,
}

func init() {
	sendCmd.Flags().StringVar(&sendProject, "project", "", "Project name (or use KEYORIX_PROJECT / active project)")
	sendCmd.Flags().StringVar(&sendEmail, "email", "", "Invitee email address (required)")
	sendCmd.Flags().StringVar(&sendRole, "role", "", "Intended project role (required)")
	sendCmd.Flags().StringVar(&sendBy, "by", "", "Inviter email address (required, for audit)")
	_ = sendCmd.MarkFlagRequired("email")
	_ = sendCmd.MarkFlagRequired("role")
	_ = sendCmd.MarkFlagRequired("by")
}

func runSend(cmd *cobra.Command, args []string) error {
	if sendEmail == "" || sendRole == "" {
		return errors.New("--email and --role are required")
	}
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	projectName, err := common.ResolveProject(sendProject)
	if err != nil {
		return err
	}
	projectID, err := common.LookupProjectIDByName(ctx, service.Storage(), projectName)
	if err != nil {
		return err
	}
	invitedBy, err := resolveUserID(ctx, service, sendBy)
	if err != nil {
		return err
	}

	inv, prov, err := service.InviteToProjectWithLink(ctx, projectID, sendEmail, sendRole, invitedBy)
	if err != nil {
		if inv == nil {
			return fmt.Errorf("failed to send invitation: %w", err)
		}
		// The invitation exists but the link could not be delivered (e.g. base_url
		// unset). Report it so the operator can fix config and `invite resend`.
		fmt.Printf("Invitation created: id=%d email=%s role=%s project=%s expires=%s\n",
			inv.ID, inv.Email, inv.Role, projectName, fmtTime(inv.ExpiresAt))
		return fmt.Errorf("but the setup link could not be delivered: %w", err)
	}
	fmt.Printf("Invitation sent: id=%d email=%s role=%s project=%s expires=%s\n",
		inv.ID, inv.Email, inv.Role, projectName, fmtTime(inv.ExpiresAt))
	common.PrintProvisionResult(prov)
	return nil
}
