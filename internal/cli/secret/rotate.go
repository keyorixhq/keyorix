package secret

import (
	"context"
	"fmt"
	"net/url"
	"syscall"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var rotateCmd = &cobra.Command{
	Use:   "rotate <name>",
	Short: "Rotate a secret by providing a new value",
	Args:  cobra.ExactArgs(1),
	RunE:  runRotate,
}

var rotateValue string
var rotateEnv string

func init() {
	rotateCmd.Flags().StringVarP(&rotateValue, "value", "v", "", "New secret value (omit to be prompted interactively)")
	rotateCmd.Flags().StringVarP(&rotateEnv, "env", "e", "production", "Environment name")
	SecretCmd.AddCommand(rotateCmd)
}

func promptRotateValue() (string, error) {
	fmt.Print("New secret value (hidden): ")
	valueBytes, perr := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if perr != nil {
		return "", fmt.Errorf("failed to read secret value: %w", perr)
	}
	if len(valueBytes) == 0 {
		return "", fmt.Errorf("secret value is required (use --value or enter it at the prompt)")
	}
	return string(valueBytes), nil
}

func runRotate(cmd *cobra.Command, args []string) error {
	name := args[0]

	common.WarnInsecureFlag(cmd, "value", "omit the flag to be prompted instead.")
	if !cmd.Flags().Changed("value") {
		v, err := promptRotateValue()
		if err != nil {
			return err
		}
		rotateValue = v
	}

	// common.NewRemoteClient (not a homegrown *http.Client) so this request gets the
	// same HTTPS-cleartext warning and bounded request timeout as every other CLI
	// remote-mode command — this endpoint transmits the new secret value (#G71).
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}

	ctx := context.Background()

	// Find secret ID by name
	var listResult struct {
		Secrets []struct {
			ID   uint   `json:"ID"`
			Name string `json:"Name"`
		} `json:"secrets"`
	}
	listPath := "/api/v1/secrets?environment=" + url.QueryEscape(rotateEnv)
	if err := rc.Get(ctx, listPath, &listResult); err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	var secretID uint
	for _, s := range listResult.Secrets {
		if s.Name == name {
			secretID = s.ID
			break
		}
	}
	if secretID == 0 {
		return fmt.Errorf("secret '%s' not found in environment '%s'", name, rotateEnv)
	}

	// Rotate
	rotatePath := fmt.Sprintf("/api/v1/secrets/%d/rotate", secretID)
	if err := rc.Post(ctx, rotatePath, map[string]string{"new_value": rotateValue}, nil); err != nil {
		return fmt.Errorf("rotate request failed: %w", err)
	}

	fmt.Printf("✓ Secret '%s' rotated successfully in %s\n", name, rotateEnv)
	return nil
}
