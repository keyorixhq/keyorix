package request

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	reviewID     uint
	reviewAction string
	reviewRole   string
	reviewReason string
	reviewBy     string
)

var reviewCmd = &cobra.Command{
	Use:   "review",
	Short: "Approve or reject a pending access request",
	Long: "Resolve a pending access request (admin-driven, ADR-024).\n" +
		"Approving grants the role at the project scope (--role overrides the suggested role);\n" +
		"rejecting records a --reason.",
	RunE: runReview,
}

func init() {
	reviewCmd.Flags().UintVar(&reviewID, "id", 0, "Access request ID (required)")
	reviewCmd.Flags().StringVar(&reviewAction, "action", "", "approve | reject (required)")
	reviewCmd.Flags().StringVar(&reviewRole, "role", "", "Role to grant on approve (defaults to the suggested role)")
	reviewCmd.Flags().StringVar(&reviewReason, "reason", "", "Reason on reject")
	reviewCmd.Flags().StringVar(&reviewBy, "by", "", "Reviewer email address (required, for audit)")
	_ = reviewCmd.MarkFlagRequired("id")
	_ = reviewCmd.MarkFlagRequired("action")
	_ = reviewCmd.MarkFlagRequired("by")
}

func runReview(cmd *cobra.Command, args []string) error {
	if reviewID == 0 {
		return fmt.Errorf("--id is required")
	}
	if reviewAction != "approve" && reviewAction != "reject" {
		return fmt.Errorf("--action must be approve or reject")
	}
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	approverID, err := resolveUserID(ctx, service, reviewBy)
	if err != nil {
		return err
	}

	switch reviewAction {
	case "approve":
		req, err := service.ApproveAccessRequest(ctx, reviewID, approverID, reviewRole)
		if err != nil {
			return fmt.Errorf("failed to approve access request: %w", err)
		}
		fmt.Printf("Access request %d approved: granted role %q to %s.\n",
			req.ID, req.GrantedRole, userLabel(ctx, service, req.UserID))
	case "reject":
		req, err := service.RejectAccessRequest(ctx, reviewID, approverID, reviewReason)
		if err != nil {
			return fmt.Errorf("failed to reject access request: %w", err)
		}
		fmt.Printf("Access request %d rejected.\n", req.ID)
	}
	return nil
}
