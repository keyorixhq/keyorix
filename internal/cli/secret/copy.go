package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	copyID      uint
	copyToEnv   uint
	copyNewName string
)

var copyCmd = &cobra.Command{
	Use:   "copy",
	Short: "Copy a secret's value and metadata into another environment",
	Long: `Promote a secret into another environment of the same project (e.g. staging →
production) without re-typing the value. Creates a new, independently-owned secret with
the source's value, type, classification, and description. Requires secrets.read on the
source and secrets.write in the target environment.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if copyID == 0 || copyToEnv == 0 {
			return fmt.Errorf("--id and --to-environment are required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		id, err := copySecret(context.Background(), c, copyID, copyToEnv, copyNewName)
		if err != nil {
			return err
		}
		fmt.Printf("✅ Copied secret %d to environment %d as new secret %d.\n", copyID, copyToEnv, id)
		return nil
	},
}

// copySecret POSTs the copy and returns the new secret's ID (split out for tests).
func copySecret(ctx context.Context, c *common.RemoteClient, id, toEnv uint, name string) (uint, error) {
	body := map[string]interface{}{"environment_id": toEnv}
	if name != "" {
		body["name"] = name
	}
	var out struct {
		ID uint `json:"ID"`
	}
	if err := c.Post(ctx, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/copy", body, &out); err != nil {
		return 0, err
	}
	return out.ID, nil
}

func init() {
	copyCmd.Flags().UintVar(&copyID, "id", 0, "Source secret ID (required)")
	copyCmd.Flags().UintVar(&copyToEnv, "to-environment", 0, "Target environment ID, same project (required)")
	copyCmd.Flags().StringVar(&copyNewName, "name", "", "Name for the copy (default: the source name)")
	SecretCmd.AddCommand(copyCmd)
}
