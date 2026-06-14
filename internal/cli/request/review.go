package request

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	reviewID     uint
	reviewAction string
	reviewRole   string
	reviewReason string
	reviewBy     string
	reviewTTL    string
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
	reviewCmd.Flags().StringVar(&reviewTTL, "ttl", "", "Time-bound the granted role on approve (Go duration, e.g. 4h); empty = permanent")
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

	// The approve/reject core methods are project-scoped (cross-project guard);
	// the embedded CLI admin operates on the request's own project.
	existing, err := service.Storage().GetAccessRequest(ctx, reviewID)
	if err != nil {
		return fmt.Errorf("access request %d not found", reviewID)
	}
	projectID := existing.ProjectID

	switch reviewAction {
	case "approve":
		var ttl time.Duration
		if reviewTTL != "" {
			ttl, err = time.ParseDuration(reviewTTL)
			if err != nil || ttl < 0 {
				return fmt.Errorf("--ttl must be a non-negative Go duration (e.g. 4h)")
			}
		}
		req, err := service.ApproveAccessRequestWithExpiry(ctx, projectID, reviewID, approverID, reviewRole, ttl)
		if err != nil {
			return fmt.Errorf("failed to approve access request: %w", err)
		}
		// Under dual control the request may still be pending more approvals.
		if req.State != "approved" {
			fmt.Printf("Approval recorded for access request %d (%d of %d) — more approvals needed before the role is granted.\n",
				req.ID, req.ApprovalsReceived, req.RequiredApprovals)
			return nil
		}
		grantNote := "permanently"
		if ttl > 0 {
			grantNote = fmt.Sprintf("for %s (time-bound)", ttl)
		}
		fmt.Printf("Access request %d approved: granted role %q to %s %s.\n",
			req.ID, req.GrantedRole, userLabel(ctx, service, req.UserID), grantNote)
	case "reject":
		req, err := service.RejectAccessRequest(ctx, projectID, reviewID, approverID, reviewReason)
		if err != nil {
			return fmt.Errorf("failed to reject access request: %w", err)
		}
		fmt.Printf("Access request %d rejected.\n", req.ID)
	}
	return nil
}
