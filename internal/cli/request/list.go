package request

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	listProject string
	listBy      string
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List a project's access requests",
	Long:  "List all access requests for a project, expiring stale pending ones on read (ADR-024).",
	RunE:  runList,
}

func init() {
	listCmd.Flags().StringVar(&listProject, "project", "", "Project name (or use KEYORIX_PROJECT / active project)")
	listCmd.Flags().StringVar(&listBy, "by", "", "Acting admin email address (required, for authorization)")
	_ = listCmd.MarkFlagRequired("by")
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

	viewerID, err := resolveUserID(ctx, service, listBy)
	if err != nil {
		return err
	}
	if err := requireListAuthority(ctx, service, viewerID, projectID); err != nil {
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

// requireListAuthority verifies that actorID — the user resolved from --by —
// actually holds the authority the equivalent HTTP route requires for this
// exact operation: GET .../projects/{id}/access-requests is gated on
// roles.assign scoped to the project (see router.go). The local CLI has no
// session/middleware to enforce this, so --by resolving ANY email — with zero
// authority check — would let an operator read a project's access-request
// list (which surfaces who requested what, and why) purely by naming an
// arbitrary or unprivileged account. ListAccessRequests itself does not check
// permissions (the HTTP handler's job is done by router middleware), so this
// must be verified here, at the CLI entrypoint, before the list is returned.
func requireListAuthority(ctx context.Context, svc *core.KeyorixCore, actorID, projectID uint) error {
	ok, err := svc.Authorize(ctx, actorID, "roles.assign", core.Scope{ProjectID: projectID})
	if err != nil {
		return common.ByAuthorityUnavailableError(err,
			"run GET /api/v1/projects/{id}/access-requests directly against the hub instead, authenticated "+
				"with your own real session (e.g. via 'keyorix connect')")
	}
	if !ok {
		return fmt.Errorf("--by actor does not hold roles.assign at project %d; refusing to list access requests on their behalf", projectID)
	}
	return nil
}
