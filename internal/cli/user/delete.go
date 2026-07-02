package user

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	deleteUserID uint
	deleteForce  bool
)

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a user",
	RunE:  runDelete,
}

func init() {
	deleteCmd.Flags().UintVar(&deleteUserID, "id", 0, "User ID (required)")
	deleteCmd.Flags().BoolVar(&deleteForce, "force", false, "Skip the confirmation prompt")
}

func runDelete(cmd *cobra.Command, args []string) error {
	if deleteUserID == 0 {
		return errors.New("user id is required (use --id)")
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	// Deleting a user is irreversible, so require an explicit confirmation unless
	// the caller opted out with --force (e.g. for scripted/CI use).
	if !deleteForce {
		label := fmt.Sprintf("user %d", deleteUserID)
		if u, gerr := service.GetUser(ctx, deleteUserID); gerr == nil {
			label = fmt.Sprintf("user %d (%s)", u.ID, u.Email)
		}
		if !confirmYesNo(fmt.Sprintf("Delete %s? This cannot be undone.", label)) {
			fmt.Println("❌ Deletion cancelled")
			return nil
		}
	}

	if err := service.DeleteUser(ctx, deleteUserID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	fmt.Printf("User %d deleted.\n", deleteUserID)
	return nil
}

// confirmYesNo prompts on stdin and reports whether the operator typed "y"/"yes"
// (case-insensitive). Anything else — including a blank line — is treated as "no", so
// an accidental Enter never confirms a destructive action.
func confirmYesNo(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s (yes/no): ", prompt)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "yes" || input == "y"
}
