package secret

import (
	"context"
	"fmt"
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
var rotateProjectName string

func init() {
	rotateCmd.Flags().StringVarP(&rotateValue, "value", "v", "", "New secret value (omit to be prompted interactively)")
	rotateCmd.Flags().StringVarP(&rotateEnv, "env", "e", "production", "Environment name")
	rotateCmd.Flags().StringVar(&rotateProjectName, "project", "", "Project name (overrides KEYORIX_PROJECT and active project)")
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

	projectName, err := common.ResolveProject(rotateProjectName)
	if err != nil {
		return err
	}

	// common.NewRemoteClient (not a homegrown *http.Client) so this request gets the
	// same HTTPS-cleartext warning and bounded request timeout as every other CLI
	// remote-mode command — this endpoint transmits the new secret value (#G71).
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}

	ctx := context.Background()

	projectID, err := common.ResolveProjectIDRemote(ctx, rc, projectName)
	if err != nil {
		return err
	}
	environmentID, err := common.ResolveEnvironmentIDRemote(ctx, rc, projectID, rotateEnv)
	if err != nil {
		return err
	}

	secretID, err := findExactSecretID(ctx, rc, projectID, environmentID, rotateEnv, name)
	if err != nil {
		return err
	}

	// Rotate
	rotatePath := fmt.Sprintf("/api/v1/secrets/%d/rotate", secretID)
	if err := rc.Post(ctx, rotatePath, map[string]string{"new_value": rotateValue}, nil); err != nil {
		return fmt.Errorf("rotate request failed: %w", err)
	}

	fmt.Printf("✓ Secret '%s' rotated successfully in %s\n", name, rotateEnv)
	return nil
}

// findExactSecretID resolves name to exactly one secret ID within
// (projectID, environmentID) by listing secrets scoped to both IDs (the
// server's real filters — see server/http/handlers/secrets_list.go) and
// matching the exact (case-sensitive) name. Zero matches is a clear
// "not found" error; more than one is refused rather than silently picking
// the first — a same-named secret should never coexist within one
// project/environment, but this must never guess if it somehow does.
func findExactSecretID(ctx context.Context, rc *common.RemoteClient, projectID, environmentID uint, envName, name string) (uint, error) {
	var listResult struct {
		Secrets []struct {
			ID   uint   `json:"ID"`
			Name string `json:"Name"`
		} `json:"secrets"`
	}
	// page_size=100 is the server's actual maximum (secrets_list.go); a project's
	// environment is expected to hold far fewer secrets than that.
	listPath := fmt.Sprintf("/api/v1/secrets?project_id=%d&environment_id=%d&page_size=100", projectID, environmentID)
	if err := rc.Get(ctx, listPath, &listResult); err != nil {
		return 0, fmt.Errorf("failed to list secrets: %w", err)
	}

	var matches []uint
	for _, s := range listResult.Secrets {
		if s.Name == name {
			matches = append(matches, s.ID)
		}
	}
	switch len(matches) {
	case 0:
		return 0, fmt.Errorf("secret '%s' not found in environment '%s'", name, envName)
	case 1:
		return matches[0], nil
	default:
		return 0, fmt.Errorf("secret '%s' is ambiguous in environment '%s': matches %d secrets (IDs %v) — refusing to guess", name, envName, len(matches), matches)
	}
}
