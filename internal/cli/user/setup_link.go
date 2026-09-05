// setup_link.go — credential-delivery setup-link commands for the user CLI (ADR-028).
//
// resend-setup-link reissues a user's account_setup link (superseding the prior one)
// and re-delivers it. Like the lifecycle commands, the local CLI has no session, so
// --by supplies the audited acting admin. printProvisionResult is shared with the
// `user create --setup-link` path.
package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	resendSetupLinkUserID uint
	resendSetupLinkBy     string
)

var resendSetupLinkCmd = &cobra.Command{
	Use:   "resend-setup-link",
	Short: "Reissue and redeliver a user's setup link (ADR-028)",
	Long: "Reissue an account's setup link, invalidating any prior link, and deliver it\n" +
		"again. In out-of-band mode the link is printed for you to relay. Throttled per\n" +
		"the ADR-028 resend limits.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if resendSetupLinkUserID == 0 {
			return errors.New("user id is required (use --id)")
		}
		if resendSetupLinkBy == "" {
			return errors.New("acting admin email is required (use --by)")
		}
		if rc, ok := common.NewRemoteClient(); ok {
			return runResendSetupLinkRemote(rc)
		}
		service, err := common.InitializeCoreService()
		if err != nil {
			return fmt.Errorf("failed to initialize service: %w", err)
		}
		ctx := context.Background()
		adminID, err := resolveAdminID(ctx, service, resendSetupLinkBy)
		if err != nil {
			return err
		}
		if err := requireUserAuthority(ctx, service, adminID, permUsersWrite); err != nil {
			return err
		}
		prov, err := service.ResendAccountSetupLink(ctx, resendSetupLinkUserID, adminID)
		if err != nil {
			return fmt.Errorf("failed to resend setup link: %w", err)
		}
		fmt.Printf("Setup link reissued for user %d.\n", resendSetupLinkUserID)
		common.PrintProvisionResult(prov)
		return nil
	},
}

// runResendSetupLinkRemote reissues and redelivers the user's setup link via
// POST /api/v1/users/{id}/resend-setup-link against the connected server
// (server/http/handlers/users_crud.go's ResendSetupLink), so the link is
// issued from -- and tracked/throttled by -- the server's real setup-token
// store instead of a stray local SQLite file.
func runResendSetupLinkRemote(rc *common.RemoteClient) error {
	ctx := context.Background()
	label := remoteUserLabel(ctx, rc, resendSetupLinkUserID)
	fmt.Printf("Reissuing setup link for %s on %s...\n", label, rc.Endpoint)

	var prov core.ProvisionSetupResult
	if err := rc.Post(ctx, fmt.Sprintf("/api/v1/users/%d/resend-setup-link", resendSetupLinkUserID), struct{}{}, &prov); err != nil {
		return fmt.Errorf("failed to resend setup link for %s on %s: %w", label, rc.Endpoint, err)
	}
	fmt.Printf("Setup link reissued for %s on %s.\n", label, rc.Endpoint)
	common.PrintProvisionResult(&prov)
	return nil
}

func init() {
	resendSetupLinkCmd.Flags().UintVar(&resendSetupLinkUserID, "id", 0, "Target user ID (required)")
	resendSetupLinkCmd.Flags().StringVar(&resendSetupLinkBy, "by", "", "Acting admin email (required, for audit)")
	_ = resendSetupLinkCmd.MarkFlagRequired("id")
	_ = resendSetupLinkCmd.MarkFlagRequired("by")
}
