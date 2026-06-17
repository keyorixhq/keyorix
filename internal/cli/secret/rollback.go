package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	rollbackID      uint
	rollbackVersion int
)

var rollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Restore a secret to the value of a prior version",
	Long: `Restore a secret to an earlier version's value. The old value is re-instated as a
NEW version (history stays append-only, so the rollback itself can be undone).

List the available versions with: keyorix secret versions --id <id>.
Requires secrets.write at the secret's scope.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		if rollbackID == 0 {
			return fmt.Errorf("--id is required")
		}
		if rollbackVersion <= 0 {
			return fmt.Errorf("--version must be a positive version number")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		return runRollbackRemote(c, rollbackID, rollbackVersion)
	},
}

// runRollbackRemote POSTs the rollback request to the server. Split out from the
// command so it can be exercised against an httptest server.
func runRollbackRemote(c *common.RemoteClient, id uint, version int) error {
	body := map[string]interface{}{"version": version}
	var out struct{}
	path := "/api/v1/secrets/" + strconv.Itoa(int(id)) + "/rollback"
	if err := c.Post(context.Background(), path, body, &out); err != nil {
		return err
	}
	fmt.Printf("✓ Secret %d rolled back to the value of version %d (as a new version).\n", id, version)
	return nil
}

func init() {
	rollbackCmd.Flags().UintVar(&rollbackID, "id", 0, "Secret ID (required)")
	rollbackCmd.Flags().IntVar(&rollbackVersion, "version", 0, "Version number to restore (required)")
	SecretCmd.AddCommand(rollbackCmd)
}
