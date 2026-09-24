package request

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	secretAccessSecretID uint
	secretAccessRef      string
	secretAccessUser     string
	secretAccessReason   string
)

var secretAccessCmd = &cobra.Command{
	Use:   "secret-access",
	Short: "Request approval to read one restricted secret's value",
	Long: "Create a pending, secret-scoped access request: approval to read ONE specific\n" +
		"secret's value, distinct from `request access`'s broader project/role request.\n" +
		"Only relevant when classification.restricted_requires_approval is enabled and\n" +
		"the target secret's classification is \"restricted\" — the gate this satisfies.",
	RunE: runSecretAccess,
}

func init() {
	secretAccessCmd.Flags().UintVar(&secretAccessSecretID, "secret-id", 0, "Secret ID (or use --ref)")
	secretAccessCmd.Flags().StringVar(&secretAccessRef, "ref", "", "Secret reference \"project/environment/name\" (or use --secret-id)")
	secretAccessCmd.Flags().StringVar(&secretAccessUser, "user", "", "Requester email address (embedded mode only, required there; ignored when a remote server is configured -- the server attributes the request to the caller's own authenticated identity)")
	secretAccessCmd.Flags().StringVar(&secretAccessReason, "reason", "", "Reason for the request (required when a remote server is configured; optional in embedded mode)")
}

func runSecretAccess(cmd *cobra.Command, args []string) error {
	if secretAccessSecretID == 0 && secretAccessRef == "" {
		return fmt.Errorf("--secret-id or --ref is required")
	}
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		return runSecretAccessRemote(ctx, rc)
	}

	if secretAccessUser == "" {
		return fmt.Errorf("--user is required")
	}
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	secretID := secretAccessSecretID
	if secretID == 0 {
		secret, err := service.ResolveSecretRef(ctx, secretAccessRef)
		if err != nil {
			return fmt.Errorf("resolve ref %q: %w", secretAccessRef, err)
		}
		secretID = secret.ID
	}

	userID, err := resolveUserID(ctx, service, secretAccessUser)
	if err != nil {
		return err
	}

	req, err := service.RequestSecretAccess(ctx, secretID, userID, secretAccessReason)
	if err != nil {
		return fmt.Errorf("failed to request secret access: %w", err)
	}
	fmt.Printf("Secret access requested: id=%d secret=%d state=%s\n", req.ID, secretID, req.State)
	return nil
}

// runSecretAccessRemote creates the request via POST
// /api/v1/secret-access-requests, gated server-side only on the caller
// already being able to see the secret (GetSecretWithPermissionCheck, inside
// the handler -- CreateSecretAccessRequest's own doc comment). --user is
// ignored: there is no server capability to attribute a self-service request
// to anyone other than the caller's own authenticated identity (mirrors
// runReviewRemote's identical --by handling).
func runSecretAccessRemote(ctx context.Context, rc *common.RemoteClient) error {
	if secretAccessReason == "" {
		return fmt.Errorf("--reason is required when a remote server is configured")
	}
	if secretAccessUser != "" {
		fmt.Println("Note: --user is ignored when a remote server is configured; the request is attributed to your own authenticated identity.")
	}
	secretID, err := resolveSecretIDRemote(ctx, rc, secretAccessSecretID, secretAccessRef)
	if err != nil {
		return err
	}
	body := map[string]interface{}{"secret_id": secretID, "reason": secretAccessReason}
	var resp struct {
		AccessRequest *models.AccessRequest `json:"access_request"`
	}
	if err := rc.Post(ctx, "/api/v1/secret-access-requests", body, &resp); err != nil {
		return fmt.Errorf("failed to request secret access: %w", err)
	}
	if resp.AccessRequest == nil {
		return fmt.Errorf("secret access requested, but the server response carried no access_request to confirm it")
	}
	fmt.Printf("Secret access requested: id=%d secret=%d state=%s\n", resp.AccessRequest.ID, secretID, resp.AccessRequest.State)
	return nil
}
