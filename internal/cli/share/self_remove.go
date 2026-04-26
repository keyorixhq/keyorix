package share

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/spf13/cobra"
)

// NewSelfRemoveCommand creates a new command for removing self from shared secrets
func NewSelfRemoveCommand(coreService *core.KeyorixCore) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "self-remove <secret-id>",
		Short: i18n.T("CLISelfRemoveShort", nil),
		Long:  i18n.T("CLISelfRemoveLong", nil),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSelfRemove(cmd.Context(), coreService, args[0])
		},
	}

	return cmd
}

func runSelfRemove(ctx context.Context, coreService *core.KeyorixCore, secretIDStr string) error {
	// Parse secret ID
	secretID, err := strconv.ParseUint(secretIDStr, 10, 32)
	if err != nil {
		return fmt.Errorf("%s: %s", i18n.T("ErrorInvalidSecretID", nil), err.Error())
	}

	// Get current user ID (this would need to be implemented based on your auth system)
	// For now, we'll use a placeholder
	userID := getCurrentUserID()
	if userID == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorUserNotAuthenticated", nil))
	}

	// Remove self from share
	err = coreService.RemoveSelfFromShare(ctx, uint(secretID), userID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorSelfRemovalFailed", nil), err)
	}

	fmt.Printf("%s\n", i18n.T("SuccessSelfRemoved", map[string]interface{}{
		"SecretID": secretID,
	}))

	return nil
}

// getCurrentUserID returns the current user's ID
// This is a placeholder - implement based on your authentication system
func getCurrentUserID() uint {
	// TODO: Implement proper user ID retrieval from context/session
	return 1 // Placeholder
}
