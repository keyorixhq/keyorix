package request

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
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
	secretAccessCmd.Flags().StringVar(&secretAccessUser, "user", "", "Requester email address (required)")
	secretAccessCmd.Flags().StringVar(&secretAccessReason, "reason", "", "Reason for the request (optional)")
	_ = secretAccessCmd.MarkFlagRequired("user")
}

func runSecretAccess(cmd *cobra.Command, args []string) error {
	if secretAccessUser == "" {
		return fmt.Errorf("--user is required")
	}
	if secretAccessSecretID == 0 && secretAccessRef == "" {
		return fmt.Errorf("--secret-id or --ref is required")
	}
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

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
