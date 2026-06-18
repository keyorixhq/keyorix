package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	reassignProject uint
	reassignFrom    uint
	reassignTo      uint
)

var reassignOwnerCmd = &cobra.Command{
	Use:   "reassign-owner",
	Short: "Re-home all of a departed user's secrets to a new owner",
	Long: `Transfer every secret in a project owned by one user to another, in one call —
the bulk completion of offboarding after 'keyorix secret orphaned' surfaces a gone
owner's secrets. Requires secrets.write at the project scope; each secret is authorized
individually (you must be its owner, or the current owner must be gone).`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if reassignProject == 0 || reassignFrom == 0 || reassignTo == 0 {
			return fmt.Errorf("--project, --from and --to are all required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		n, err := reassignOwner(context.Background(), c, reassignProject, reassignFrom, reassignTo)
		if err != nil {
			return err
		}
		fmt.Printf("✅ Reassigned %d secret(s) from user %d to user %d.\n", n, reassignFrom, reassignTo)
		return nil
	},
}

// reassignOwner POSTs the bulk reassignment and returns the count (split out for tests).
func reassignOwner(ctx context.Context, c *common.RemoteClient, projectID, from, to uint) (int, error) {
	path := "/api/v1/projects/" + strconv.Itoa(int(projectID)) + "/secrets/reassign-owner"
	body := map[string]uint{"from_owner_id": from, "to_owner_id": to}
	var out struct {
		Reassigned int `json:"reassigned"`
	}
	if err := c.Post(ctx, path, body, &out); err != nil {
		return 0, err
	}
	return out.Reassigned, nil
}

func init() {
	reassignOwnerCmd.Flags().UintVar(&reassignProject, "project", 0, "Project ID (required)")
	reassignOwnerCmd.Flags().UintVar(&reassignFrom, "from", 0, "Current owner's user ID (required)")
	reassignOwnerCmd.Flags().UintVar(&reassignTo, "to", 0, "New owner's user ID (required)")
	SecretCmd.AddCommand(reassignOwnerCmd)
}
