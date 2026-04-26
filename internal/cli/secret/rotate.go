package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/spf13/cobra"
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
	rotateCmd.Flags().StringVarP(&rotateValue, "value", "v", "", "New secret value (required)")
	rotateCmd.Flags().StringVarP(&rotateEnv, "env", "e", "production", "Environment name")
	rotateCmd.MarkFlagRequired("value")
	SecretCmd.AddCommand(rotateCmd)
}

func runRotate(cmd *cobra.Command, args []string) error {
	name := args[0]

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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var listResult struct {
		Data struct {
			Secrets []struct {
				ID   uint   `json:"ID"`
				Name string `json:"Name"`
			} `json:"secrets"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResult); err != nil {
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
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		return fmt.Errorf("rotate request failed: %w", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		return fmt.Errorf("server returned %d", resp2.StatusCode)
	}

	fmt.Printf("✓ Secret '%s' rotated successfully in %s\n", name, rotateEnv)
	return nil
}
