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
		service, err := common.InitializeCoreService()
		if err != nil {
			return fmt.Errorf("failed to initialize service: %w", err)
		}
		ctx := context.Background()
		adminID, err := resolveAdminID(ctx, service, resendSetupLinkBy)
		if err != nil {
			return err
		}
		prov, err := service.ResendAccountSetupLink(ctx, resendSetupLinkUserID, adminID)
		if err != nil {
			return fmt.Errorf("failed to resend setup link: %w", err)
		}
		fmt.Printf("Setup link reissued for user %d.\n", resendSetupLinkUserID)
		printProvisionResult(prov)
		return nil
	},
}

func init() {
	resendSetupLinkCmd.Flags().UintVar(&resendSetupLinkUserID, "id", 0, "Target user ID (required)")
	resendSetupLinkCmd.Flags().StringVar(&resendSetupLinkBy, "by", "", "Acting admin email (required, for audit)")
	_ = resendSetupLinkCmd.MarkFlagRequired("id")
	_ = resendSetupLinkCmd.MarkFlagRequired("by")
}

// printProvisionResult prints how a setup link was delivered. In out-of-band mode it
// prints the link itself for the admin to relay; in SMTP mode it confirms the send.
func printProvisionResult(prov *core.ProvisionSetupResult) {
	if prov == nil {
		return
	}
	if prov.Delivered {
		fmt.Printf("Setup link delivered to %s via %s.\n", prov.Email, prov.Channel)
		return
	}
	fmt.Printf("Setup link (relay this to %s securely — it is single-use and expires):\n  %s\n", prov.Email, prov.LinkForAdmin)
}
