// move.go — keyorix secret move: re-parent a secret or folder.
package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	moveID uint
	moveTo uint
)

var moveCmd = &cobra.Command{
	Use:   "move",
	Short: "Move a secret or folder to a different parent folder",
	Long: `Move a secret or folder to a different parent folder.

Use --to 0 (or omit --to) to move the node to the root (no parent).

Examples:
  keyorix secret move --id 42 --to 7     # move secret 42 into folder 7
  keyorix secret move --id 42 --to 0     # move secret 42 to the root

Requires secrets.write at the secret's scope.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if moveID == 0 {
			return fmt.Errorf("--id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		if err := moveSecret(context.Background(), c, moveID, moveTo); err != nil {
			return err
		}
		dest := "root"
		if moveTo != 0 {
			dest = "folder " + strconv.Itoa(int(moveTo))
		}
		fmt.Printf("Secret %d moved to %s\n", moveID, dest)
		return nil
	},
}

// moveSecret POSTs the move request to the server. Exported (lowercase) for test access.
func moveSecret(ctx context.Context, c *common.RemoteClient, id, parentID uint) error {
	body := map[string]uint{"parent_id": parentID}
	var ignored struct{}
	return c.Post(ctx, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/move", body, &ignored)
}

func init() {
	moveCmd.Flags().UintVar(&moveID, "id", 0, "Secret or folder ID to move (required)")
	moveCmd.Flags().UintVar(&moveTo, "to", 0, "Target parent folder ID (0 = root)")
	SecretCmd.AddCommand(moveCmd)
}
