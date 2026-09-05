package invite

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	listProject   string
	listStaleDays int
	listBy        string
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
	listCmd.Flags().StringVar(&listBy, "by", "", "Viewer email address (required, for authorization)")
	_ = listCmd.MarkFlagRequired("by")
}

func runList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	projectName, err := common.ResolveProject(listProject)
	if err != nil {
		return err
	}

	// Remote mode: read the invitation list through the real hub REST API --
	// see send.go's runSendRemote doc comment for why --by isn't used here.
	if rc, ok := common.NewRemoteClient(); ok {
		return runListRemote(ctx, rc, projectName)
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	projectID, err := common.LookupProjectIDByName(ctx, service.Storage(), projectName)
	if err != nil {
		return err
	}

	// #1648: mirrors send/revoke/resend's identical guard (requireInviteAuthority,
	// invite.go) and the structurally identical request/list.go's requireListAuthority
	// -- without it, --by resolving ANY email with zero authority check let an
	// operator read an arbitrary project's pending invitations (invitee email,
	// intended role, state) purely by naming an arbitrary or unprivileged account.
	// ListProjectInvitations itself does not check permissions (the HTTP handler's
	// job is done by router middleware), so this must be verified here, at the CLI
	// entrypoint, before the list is returned.
	viewerID, err := resolveUserID(ctx, service, listBy)
	if err != nil {
		return err
	}
	if err := requireInviteAuthority(ctx, service, viewerID, projectID); err != nil {
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

	printInvitations(invitations)
	return nil
}

// runListRemote fetches the project's invitations via GET
// /api/v1/projects/{id}/invitations, matching ListInvitations' response shape
// ({"invitations": [...]}) exactly (server/http/handlers/invitations.go). The
// server has no dedicated stale-invitations endpoint, so --stale-days is
// applied client-side over the same full list core.StaleInvitations would
// have filtered server-side in embedded mode -- identical predicate (pending +
// older than the cutoff), just evaluated here instead.
func runListRemote(ctx context.Context, rc *common.RemoteClient, projectName string) error {
	projectID, err := resolveProjectIDRemote(ctx, rc, projectName)
	if err != nil {
		return err
	}
	fmt.Printf("Target: %s (project %q, id=%d)\n", rc.Endpoint, projectName, projectID)

	var resp struct {
		Invitations []*models.ProjectInvitation `json:"invitations"`
	}
	path := fmt.Sprintf("/api/v1/projects/%d/invitations", projectID)
	if err := rc.Get(ctx, path, &resp); err != nil {
		return fmt.Errorf("failed to list invitations: %w", err)
	}

	invitations := resp.Invitations
	if listStaleDays > 0 {
		cutoff := time.Now().Add(-time.Duration(listStaleDays) * 24 * time.Hour)
		var stale []*models.ProjectInvitation
		for _, inv := range invitations {
			if inv.State == core.InvitationPending && inv.CreatedAt.Before(cutoff) {
				stale = append(stale, inv)
			}
		}
		invitations = stale
	}
	printInvitations(invitations)
	return nil
}

// printInvitations renders the invitation table shared by both the embedded
// and remote paths.
func printInvitations(invitations []*models.ProjectInvitation) {
	if len(invitations) == 0 {
		fmt.Println("No invitations found.")
		return
	}
	fmt.Printf("%-6s %-30s %-16s %-10s %s\n", "ID", "EMAIL", "ROLE", "STATE", "EXPIRES")
	for _, inv := range invitations {
		fmt.Printf("%-6d %-30s %-16s %-10s %s\n", inv.ID, inv.Email, inv.Role, inv.State, fmtTime(inv.ExpiresAt))
	}
}
