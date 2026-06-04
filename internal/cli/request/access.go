package request

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	accessProject string
	accessUser    string
	accessRole    string
	accessReason  string
)

var accessCmd = &cobra.Command{
	Use:   "access",
	Short: "Request access to a project",
	Long:  "Create a pending access request for a user to a project, optionally suggesting a role (ADR-024).",
	RunE:  runAccess,
}

func init() {
	accessCmd.Flags().StringVar(&accessProject, "project", "", "Project name (or use KEYORIX_PROJECT / active project)")
	accessCmd.Flags().StringVar(&accessUser, "user", "", "Requester email address (required)")
	accessCmd.Flags().StringVar(&accessRole, "role", "", "Suggested project role (optional)")
	accessCmd.Flags().StringVar(&accessReason, "reason", "", "Reason for the request (optional)")
	_ = accessCmd.MarkFlagRequired("user")
}

func runAccess(cmd *cobra.Command, args []string) error {
	if accessUser == "" {
		return fmt.Errorf("--user is required")
	}
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	projectName, err := common.ResolveProject(accessProject)
	if err != nil {
		return err
	}
	projectID, err := common.LookupProjectIDByName(ctx, service.Storage(), projectName)
	if err != nil {
		return err
	}
	userID, err := resolveUserID(ctx, service, accessUser)
	if err != nil {
		return err
	}

	req, err := service.RequestProjectAccess(ctx, projectID, userID, accessRole, accessReason)
	if err != nil {
		return fmt.Errorf("failed to request access: %w", err)
	}
	fmt.Printf("Access requested: id=%d project=%s suggested-role=%s state=%s\n",
		req.ID, projectName, dashIfEmpty(req.SuggestedRole), req.State)
	return nil
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
