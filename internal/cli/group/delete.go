package group

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	deleteGroupID uint
	deleteForce   bool
)

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a group",
	RunE:  runDelete,
}

func init() {
	deleteCmd.Flags().UintVar(&deleteGroupID, "id", 0, "Group ID (required)")
	deleteCmd.Flags().BoolVar(&deleteForce, "force", false, "Skip the confirmation prompt")
}

func runDelete(cmd *cobra.Command, args []string) error {
	if deleteGroupID == 0 {
		return errors.New("group id is required (use --id)")
	}
	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		return runDeleteRemote(ctx, rc)
	}

	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	// Deleting a group is irreversible, so require an explicit confirmation unless
	// the caller opted out with --force (e.g. for scripted/CI use).
	if !deleteForce {
		label := fmt.Sprintf("group %d", deleteGroupID)
		if g, gerr := service.GetGroup(ctx, deleteGroupID); gerr == nil {
			label = fmt.Sprintf("group %d (%s)", g.ID, g.Name)
		}
		if !confirmYesNo(fmt.Sprintf("Delete %s? This cannot be undone.", label)) {
			fmt.Println("❌ Deletion cancelled")
			return nil
		}
	}

	if err := service.DeleteGroup(ctx, common.ResolveActorID(), deleteGroupID); err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	fmt.Printf("Group %d deleted.\n", deleteGroupID)
	return nil
}

// runDeleteRemote mirrors runDelete's confirm-then-delete flow against the
// real REST API (DELETE /api/v1/groups/{id}) instead of local storage. The
// group's name is fetched first (best-effort -- an unreachable/erroring GET
// just falls back to an id-only label) so the confirmation prompt and the
// final result both name the actual target being deleted, on the actual
// server being deleted from -- not just an opaque numeric ID.
func runDeleteRemote(ctx context.Context, rc *common.RemoteClient) error {
	idPath := "/api/v1/groups/" + strconv.FormatUint(uint64(deleteGroupID), 10)

	label := fmt.Sprintf("group %d", deleteGroupID)
	var g groupAPIResponse
	if gerr := rc.Get(ctx, idPath, &g); gerr == nil {
		label = fmt.Sprintf("group %d (%s)", g.ID, g.Name)
	}

	if !deleteForce {
		if !confirmYesNo(fmt.Sprintf("Delete %s on %s? This cannot be undone.", label, rc.Endpoint)) {
			fmt.Println("❌ Deletion cancelled")
			return nil
		}
	}

	fmt.Printf("Deleting %s on %s...\n", label, rc.Endpoint)
	if err := rc.Delete(ctx, idPath); err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}
	fmt.Printf("Deleted %s.\n", label)
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
