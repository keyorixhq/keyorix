package request

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
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
	ctx := context.Background()

	projectName, err := common.ResolveProject(accessProject)
	if err != nil {
		return err
	}

	if rc, ok := common.NewRemoteClient(); ok {
		return runAccessRemote(ctx, rc, projectName)
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
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

// runAccessRemote creates the access request via POST
// /api/v1/projects/{id}/access-requests. That route is deliberately
// self-service (see router.go: no permission middleware on the POST) --
// mustGetUser resolves the actor from the caller's OWN authenticated session,
// not from any field in the body, so there is no way to request access on
// behalf of a DIFFERENT user remotely the way embedded mode's --user can.
// Rather than silently misattributing the request (the exact "admin believes
// they acted for X, something else happened" failure this whole fix exists to
// close), this echoes the actual requester the server attributes the new
// request to, taken straight from the row the server just created -- not
// assumed to equal --user.
func runAccessRemote(ctx context.Context, rc *common.RemoteClient, projectName string) error {
	projectID, err := resolveProjectIDByName(ctx, rc, projectName)
	if err != nil {
		return err
	}
	fmt.Printf("Requesting access to project %q (id=%d) for %s...\n", projectName, projectID, accessUser)
	fmt.Println("Note: the remote access-request API is self-service -- the request is always attributed to " +
		"the authenticated caller's own session, not to --user. If you are requesting access on behalf of " +
		"someone else, have them run this command themselves via their own 'keyorix connect' session.")

	body := map[string]interface{}{
		"suggested_role": accessRole,
		"reason":         accessReason,
	}
	var resp struct {
		AccessRequest *models.AccessRequest `json:"access_request"`
	}
	if err := rc.Post(ctx, fmt.Sprintf("/api/v1/projects/%d/access-requests", projectID), body, &resp); err != nil {
		return fmt.Errorf("failed to request access: %w", err)
	}
	req := resp.AccessRequest
	if req == nil {
		return fmt.Errorf("server did not return the created access request")
	}
	fmt.Printf("Access requested: id=%d project=%s requester=user#%d suggested-role=%s state=%s\n",
		req.ID, projectName, req.UserID, dashIfEmpty(req.SuggestedRole), req.State)
	return nil
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
