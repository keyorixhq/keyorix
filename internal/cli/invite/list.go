package invite

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	listProject   string
	listStaleDays int
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List project invitations",
	Long:  "List a project's invitations. With --stale-days, show only pending invites older than N days.",
	RunE:  runList,
}

func init() {
	listCmd.Flags().StringVar(&listProject, "project", "", "Project name (or use KEYORIX_PROJECT / active project)")
	listCmd.Flags().IntVar(&listStaleDays, "stale-days", 0, "Show only pending invitations older than this many days")
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

	var invitations []*models.ProjectInvitation
	if listStaleDays > 0 {
		invitations, err = service.StaleInvitations(ctx, projectID, time.Duration(listStaleDays)*24*time.Hour)
	} else {
		invitations, err = service.ListProjectInvitations(ctx, projectID)
	}
	if err != nil {
		return fmt.Errorf("failed to list invitations: %w", err)
	}

	if len(invitations) == 0 {
		fmt.Println("No invitations found.")
		return nil
	}
	fmt.Printf("%-6s %-30s %-16s %-10s %s\n", "ID", "EMAIL", "ROLE", "STATE", "EXPIRES")
	for _, inv := range invitations {
		fmt.Printf("%-6d %-30s %-16s %-10s %s\n", inv.ID, inv.Email, inv.Role, inv.State, fmtTime(inv.ExpiresAt))
	}
	return nil
}
