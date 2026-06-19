package secret

import (
	"context"
	"fmt"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

var (
	descID  uint
	descSet string
)

var descriptionCmd = &cobra.Command{
	Use:   "description",
	Short: "Show or set a secret's description",
	Long: `Show a secret's free-text note, or replace it with --set.

Examples:
  keyorix secret description --id 42                         # show the note
  keyorix secret description --id 42 --set "prod DB; dba@"   # set the note
  keyorix secret description --id 42 --set ""                # clear it

Showing requires secrets.read; setting requires secrets.write at the secret's scope.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if descID == 0 {
			return fmt.Errorf("--id is required")
		}
		c, ok := common.NewRemoteClient()
		if !ok {
			return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
		}
		ctx := context.Background()

		if cmd.Flags().Changed("set") {
			if err := setSecretDescription(ctx, c, descID, descSet); err != nil {
				return err
			}
		}
		desc, err := getSecretDescription(ctx, c, descID)
		if err != nil {
			return err
		}
		if desc == "" {
			fmt.Println("(no description)")
			return nil
		}
		fmt.Println(desc)
		return nil
	},
}

// getSecretDescription reads the note from the secret GET (raw model: PascalCase
// Description). Split out for httptest tests.
func getSecretDescription(ctx context.Context, c *common.RemoteClient, id uint) (string, error) {
	var body struct {
		Description string `json:"Description"`
		Desc2       string `json:"description"`
	}
	if err := c.Get(ctx, "/api/v1/secrets/"+strconv.Itoa(int(id)), &body); err != nil {
		return "", err
	}
	if body.Description != "" {
		return body.Description, nil
	}
	return body.Desc2, nil
}

// setSecretDescription PATCHes the secret's description. The endpoint returns the
// updated secret; decode it into a throwaway so the response envelope is consumed.
func setSecretDescription(ctx context.Context, c *common.RemoteClient, id uint, desc string) error {
	var ignored struct{}
	return c.Patch(ctx, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/description",
		map[string]string{"description": desc}, &ignored)
}

func init() {
	descriptionCmd.Flags().UintVar(&descID, "id", 0, "Secret ID (required)")
	descriptionCmd.Flags().StringVar(&descSet, "set", "", "Replace the description with this text (\"\" clears)")
	SecretCmd.AddCommand(descriptionCmd)
}
