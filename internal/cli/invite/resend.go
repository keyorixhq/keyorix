package invite

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
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
		common.PrintProvisionResult(prov)
		return nil
	},
}

func init() {
	resendCmd.Flags().UintVar(&resendID, "id", 0, "Invitation ID (required)")
	resendCmd.Flags().StringVar(&resendBy, "by", "", "Acting admin email (required, for audit)")
	_ = resendCmd.MarkFlagRequired("id")
	_ = resendCmd.MarkFlagRequired("by")
}
