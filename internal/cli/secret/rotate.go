package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"syscall"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// maxSecretListResponseBytes caps how much of the Keyorix server's secrets-list
// response this command will read into memory before decoding — the response
// can list every secret in an environment, so a generous cap is used (matching
// the same 10MB idiom used elsewhere for Keyorix server response decodes).
// This bounds a malicious or misbehaving server response from exhausting
// client memory via an unbounded json.Decode of resp.Body.
const maxSecretListResponseBytes = 10 << 20 // 10MB

// rotateHTTPClient is used instead of http.DefaultClient so a 3xx response from
// the configured server can't bounce the bearer-token-bearing request to an
// internal host (e.g. cloud IMDS) — CWE-918. Matches the CheckRedirect idiom
// used by this codebase's other Keyorix API clients.
var rotateHTTPClient = &http.Client{CheckRedirect: refuseRotateRedirect}

func refuseRotateRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("keyorix: refusing to follow redirect to %q", req.URL)
}

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

	cfg, err := cliconfig.LoadCLIConfig("")
	if err != nil {
		return fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}

	// Find secret ID by name
	listURL := cfg.Client.Endpoint + "/api/v1/secrets?environment=" + rotateEnv
	req, err := http.NewRequest("GET", listURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Client.Auth.GetAPIKey())
	resp, err := rotateHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	var listResult struct {
		Data struct {
			Secrets []struct {
				ID   uint   `json:"ID"`
				Name string `json:"Name"`
			} `json:"secrets"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSecretListResponseBytes)).Decode(&listResult); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	var secretID uint
	for _, s := range listResult.Data.Secrets {
		if s.Name == name {
			secretID = s.ID
			break
		}
	}
	if secretID == 0 {
		return fmt.Errorf("secret '%s' not found in environment '%s'", name, rotateEnv)
	}

	// Rotate
	rotateURL := fmt.Sprintf("%s/api/v1/secrets/%d/rotate", cfg.Client.Endpoint, secretID)
	body, _ := json.Marshal(map[string]string{"new_value": rotateValue})
	req2, err := http.NewRequest("POST", rotateURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req2.Header.Set("Authorization", "Bearer "+cfg.Client.Auth.GetAPIKey())
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := rotateHTTPClient.Do(req2)
	if err != nil {
		return fmt.Errorf("rotate request failed: %w", err)
	}
	defer resp2.Body.Close() //nolint:errcheck

	if resp2.StatusCode != 200 {
		return fmt.Errorf("server returned %d", resp2.StatusCode)
	}

	fmt.Printf("✓ Secret '%s' rotated successfully in %s\n", name, rotateEnv)
	return nil
}
