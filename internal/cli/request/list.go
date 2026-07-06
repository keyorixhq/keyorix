package request

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var listProject string

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List a project's access requests",
	Long:  "List all access requests for a project, expiring stale pending ones on read (ADR-024).",
	RunE:  runList,
}

func init() {
	listCmd.Flags().StringVar(&listProject, "project", "", "Project name (or use KEYORIX_PROJECT / active project)")
}

func runList(cmd *cobra.Command, args []string) error {
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	projectName, err := common.ResolveProject(listProject)
	if err != nil {
		return err
	}
	projectID, err := common.LookupProjectIDByName(ctx, service.Storage(), projectName)
	if err != nil {
		return err
	}

	requests, err := service.ListAccessRequests(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to list access requests: %w", err)
	}

	if len(requests) == 0 {
		fmt.Println("No access requests found.")
		return nil
	}
	fmt.Printf("%-6s %-24s %-14s %-14s %-11s %-10s %s\n", "ID", "USER", "SUGGESTED", "GRANTED", "STATE", "SECRET", "REASON")
	for _, req := range requests {
		secretCol := "-"
		if req.SecretID != nil {
			secretCol = fmt.Sprintf("#%d", *req.SecretID)
		}
		fmt.Printf("%-6d %-24s %-14s %-14s %-11s %-10s %s\n",
			req.ID, userLabel(ctx, service, req.UserID), dashIfEmpty(req.SuggestedRole),
			dashIfEmpty(req.GrantedRole), req.State, secretCol, dashIfEmpty(req.Reason))
	}
	return nil
}
