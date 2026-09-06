package invite

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
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
	ctx := context.Background()

	projectName, err := common.ResolveProject(sendProject)
	if err != nil {
		return err
	}

	// Remote mode: create the invitation through the real hub REST API so it
	// lands in the server's own store (visible to the dashboard, subject to
	// the server's own authorization for the caller's session) instead of a
	// stray local SQLite file that keyorix connect's remote config never
	// touched -- see internal/cli/user/create.go for the template this
	// mirrors. --by is not used on this path: in remote mode the audit-trail
	// actor is whoever KEYORIX_TOKEN authenticates as, not a locally-resolved
	// email -- requireInviteAuthority below exists specifically to substitute
	// for that when there is no real session (embedded mode).
	if rc, ok := common.NewRemoteClient(); ok {
		return runSendRemote(ctx, rc, projectName)
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	projectID, err := common.LookupProjectIDByName(ctx, service.Storage(), projectName)
	if err != nil {
		return err
	}
	invitedBy, err := resolveUserID(ctx, service, sendBy)
	if err != nil {
		return err
	}

	if err := requireInviteAuthority(ctx, service, invitedBy, projectID); err != nil {
		return err
	}

	inv, prov, err := service.InviteToProjectWithLink(ctx, projectID, sendEmail, sendRole, invitedBy, 0) // nosemgrep: trailofbits.go.invalid-usage-of-modified-variable.invalid-usage-of-modified-variable -- inv is nil-checked below before any field is dereferenced; the non-nil branch is the intentional partial-result path (invite created, link delivery failed)
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

// runSendRemote sends the invitation via POST /api/v1/projects/{id}/invitations,
// matching CreateInvitation's request body ({"email","role"}) and response shape
// ({"invitation": ..., "setup_link": ...} on full success, or {"invitation": ...,
// "delivery_error": ...} when the invitation was created but the setup link could
// not be delivered) exactly -- server/http/handlers/invitations.go's
// CreateInvitation, both branches still respond 201/success:true.
func runSendRemote(ctx context.Context, rc *common.RemoteClient, projectName string) error {
	projectID, err := resolveProjectIDRemote(ctx, rc, projectName)
	if err != nil {
		return err
	}
	fmt.Printf("Target: %s (project %q, id=%d)\n", rc.Endpoint, projectName, projectID)

	body := map[string]interface{}{"email": sendEmail, "role": sendRole}
	var resp struct {
		Invitation    *models.ProjectInvitation  `json:"invitation"`
		SetupLink     *core.ProvisionSetupResult `json:"setup_link"`
		DeliveryError string                     `json:"delivery_error"`
	}
	path := fmt.Sprintf("/api/v1/projects/%d/invitations", projectID)
	if err := rc.Post(ctx, path, body, &resp); err != nil {
		return fmt.Errorf("failed to send invitation: %w", err)
	}
	if resp.Invitation == nil {
		return fmt.Errorf("server reported success but returned no invitation for %s", sendEmail)
	}
	inv := resp.Invitation
	if resp.DeliveryError != "" {
		fmt.Printf("Invitation created: id=%d email=%s role=%s project=%s expires=%s\n",
			inv.ID, inv.Email, inv.Role, projectName, fmtTime(inv.ExpiresAt))
		return fmt.Errorf("but the setup link could not be delivered: %s", resp.DeliveryError)
	}
	fmt.Printf("Invitation sent: id=%d email=%s role=%s project=%s expires=%s\n",
		inv.ID, inv.Email, inv.Role, projectName, fmtTime(inv.ExpiresAt))
	common.PrintProvisionResult(resp.SetupLink)
	return nil
}

// requireInviteAuthority verifies that actorID — the user resolved from --by —
// actually holds the authority the equivalent HTTP route requires for this
// exact operation: POST .../projects/{id}/invitations is gated on roles.assign
// scoped to the project (see router.go). The local CLI has no
// session/middleware to enforce this, so --by resolving ANY email — with zero
// authority check — would let an operator attribute an invitation to an
// arbitrary or unprivileged account purely for what appears in the audit
// trail (#264/#491). InviteToProjectWithLink itself does not check
// permissions (the HTTP handler's job is done by router middleware), so this
// must be verified here, at the CLI entrypoint, before the resolved actor is
// credited with the action.
func requireInviteAuthority(ctx context.Context, svc *core.KeyorixCore, actorID, projectID uint) error {
	ok, err := svc.Authorize(ctx, actorID, "roles.assign", core.Scope{ProjectID: projectID})
	if err != nil {
		return common.ByAuthorityUnavailableError(err,
			"run the equivalent invitation request directly against the hub instead -- POST "+
				"/api/v1/projects/{id}/invitations (send), POST .../invitations/{id}/resend, or DELETE "+
				".../invitations/{id} (revoke) -- authenticated with your own real session (e.g. via "+
				"'keyorix connect'), since the hub, not this shared credential, decides who may act")
	}
	if !ok {
		return fmt.Errorf("--by actor does not hold roles.assign at project %d; refusing to attribute this invitation to them", projectID)
	}
	return nil
}
