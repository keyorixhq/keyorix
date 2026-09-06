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
	deleteBy     string
)

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a user",
	RunE:  runDelete,
}

func init() {
	deleteCmd.Flags().UintVar(&deleteUserID, "id", 0, "User ID (required)")
	deleteCmd.Flags().BoolVar(&deleteForce, "force", false, "Skip the confirmation prompt")
	deleteCmd.Flags().StringVar(&deleteBy, "by", "", "Acting admin email (required, for audit)")
	_ = deleteCmd.MarkFlagRequired("id")
	_ = deleteCmd.MarkFlagRequired("by")
}

func runDelete(cmd *cobra.Command, args []string) error {
	if deleteUserID == 0 {
		return errors.New("user id is required (use --id)")
	}
	if deleteBy == "" {
		return errors.New("acting admin email is required (use --by)")
	}

	if rc, ok := common.NewRemoteClient(); ok {
		return runDeleteRemote(rc)
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}
	ctx := context.Background()

	adminID, err := resolveAdminID(ctx, service, deleteBy)
	if err != nil {
		return err
	}
	if err := requireUserAuthority(ctx, service, adminID, permUsersDelete); err != nil {
		return err
	}

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

	if err := service.DeleteUser(ctx, adminID, deleteUserID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	fmt.Printf("User %d deleted.\n", deleteUserID)
	return nil
}

// runDeleteRemote deletes the user via DELETE /api/v1/users/{id} against the
// connected server, so the deletion lands in the server's real store instead
// of a stray local SQLite file. The acting admin is the session identity
// behind the configured bearer token, not --by (which only has meaning for
// the local/embedded audit trail -- see resolveAdminID's doc comment); the
// server's own DeleteUser handler applies its own self-delete/last-admin
// guards against that real identity. A destructive, irreversible action, so
// it still confirms (unless --force) and echoes the exact target and server
// before and after acting -- never a bare "Success."
func runDeleteRemote(rc *common.RemoteClient) error {
	ctx := context.Background()
	label := remoteUserLabel(ctx, rc, deleteUserID)

	if !deleteForce {
		if !confirmYesNo(fmt.Sprintf("Delete %s on %s? This cannot be undone.", label, rc.Endpoint)) {
			fmt.Println("❌ Deletion cancelled")
			return nil
		}
	}

	fmt.Printf("Deleting %s on %s...\n", label, rc.Endpoint)
	if err := rc.Delete(ctx, fmt.Sprintf("/api/v1/users/%d", deleteUserID)); err != nil {
		return fmt.Errorf("failed to delete %s on %s: %w", label, rc.Endpoint, err)
	}
	fmt.Printf("%s deleted on %s.\n", label, rc.Endpoint)
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
