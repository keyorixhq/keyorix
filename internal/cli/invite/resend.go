package invite

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/spf13/cobra"
)

var (
	resendID uint
	resendBy string
)

var resendCmd = &cobra.Command{
	Use:   "resend",
	Short: "Reissue and redeliver an invitation's setup link (ADR-028)",
	Long: "Reissue a pending invitation's accept link, invalidating any prior link, and\n" +
		"deliver it again. In out-of-band mode the link is printed for you to relay.\n" +
		"Throttled per the ADR-028 resend limits.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if resendID == 0 {
			return errors.New("invitation id is required (use --id)")
		}
		if resendBy == "" {
			return errors.New("acting admin email is required (use --by)")
		}
		service, err := common.InitializeCoreService()
		if err != nil {
			return fmt.Errorf("failed to initialize service: %w", err)
		}
		ctx := context.Background()
		actorID, err := resolveUserID(ctx, service, resendBy)
		if err != nil {
			return err
		}
		prov, err := service.ResendInvitationLink(ctx, resendID, actorID)
		if err != nil {
			return fmt.Errorf("failed to resend invitation link: %w", err)
		}
		fmt.Printf("Invitation link reissued for invitation %d.\n", resendID)
		printProvisionResult(prov)
		return nil
	},
}

func init() {
	resendCmd.Flags().UintVar(&resendID, "id", 0, "Invitation ID (required)")
	resendCmd.Flags().StringVar(&resendBy, "by", "", "Acting admin email (required, for audit)")
	_ = resendCmd.MarkFlagRequired("id")
	_ = resendCmd.MarkFlagRequired("by")
}

// printProvisionResult prints how an invitation's setup link was delivered. In
// out-of-band mode it prints the link for the admin to relay; in SMTP mode it
// confirms the send. Shared by `invite send` and `invite resend`.
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
