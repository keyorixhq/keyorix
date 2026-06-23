package share

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// selfRemoveCmd lets the signed-in user remove THEMSELVES from a secret that was shared
// with them. The server identifies "self" from the caller's token, so this is remote-only
// — there is no authenticated user in embedded (direct-storage) mode.
var selfRemoveCmd = &cobra.Command{
	Use:          "self-remove <secret-id>",
	Short:        "Remove yourself from a secret shared with you",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		secretID, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid secret ID %q: %w", args[0], err)
		}
		rc, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("self-remove requires a server connection — run: keyorix connect <server>")
		}
		if err := rc.Delete(context.Background(), fmt.Sprintf("/api/v1/secrets/%d/self-share", secretID)); err != nil {
			return fmt.Errorf("remove self from share: %w", err)
		}
		fmt.Printf("Removed yourself from secret %d.\n", secretID)
		return nil
	},
}
