package secret

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	updateID          uint
	updateType        string
	updateMaxReads    int
	updateExpiration  string
	updateValue       string
	updateFromFile    string
	updateInteractive bool
	updateClearExp    bool
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update an existing secret",
	Long: `Update an existing secret's value or metadata.

Examples:
  keyorix secret update --id 123 --value "new-secret"
  keyorix secret update --id 123 --type "api-key" --expires "2024-12-31T23:59:59Z"
  keyorix secret update --id 123 --from-file ./new-value.txt
  keyorix secret update --id 123 --interactive`,
	RunE: runUpdate,
}

func init() {
	updateCmd.Flags().UintVar(&updateID, "id", 0, "Secret ID (required)")
	updateCmd.Flags().StringVar(&updateType, "type", "", "Update secret type")
	updateCmd.Flags().IntVar(&updateMaxReads, "max-reads", -1, "Update max reads (-1 = no change, 0 = unlimited)")
	updateCmd.Flags().StringVar(&updateExpiration, "expires", "", "Update expiration (RFC3339 format)")
	updateCmd.Flags().StringVar(&updateValue, "value", "", "New secret value")
	updateCmd.Flags().StringVar(&updateFromFile, "from-file", "", "Read new value from file")
	updateCmd.Flags().BoolVar(&updateInteractive, "interactive", false, "Interactive mode")
	updateCmd.Flags().BoolVar(&updateClearExp, "clear-expiration", false, "Remove expiration")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	if updateID == 0 {
		return errors.New("secret ID is required (use --id)")
	}

	common.WarnInsecureFlag(cmd, "value", "use --interactive or --from-file instead.")

	if rc, ok := common.NewRemoteClient(); ok {
		return runUpdateRemote(rc)
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	st, err := common.InitializeStorage()
	if err != nil {
		return err
	}
	service := core.NewKeyorixCore(st)

	// Create context
	ctx := context.Background()

	current, err := service.GetSecret(ctx, updateID)
	if err != nil {
		return fmt.Errorf("failed to get current secret: %w", err)
	}

	fmt.Printf("🔄 Updating Secret: %s (ID: %d)\n", current.Name, current.ID)
	fmt.Printf("Current Type: %s\n", current.Type)
	if current.MaxReads != nil {
		fmt.Printf("Current Max Reads: %d\n", *current.MaxReads)
	}
	if current.Expiration != nil {
		fmt.Printf("Current Expiration: %s\n", current.Expiration.Format(time.RFC3339))
	}
	fmt.Println()

	var req *core.UpdateSecretRequest

	if updateInteractive {
		req, err = interactiveUpdate(current)
		if err != nil {
			return fmt.Errorf("interactive update failed: %w", err)
		}
	} else {
		req, err = buildUpdateRequest()
		if err != nil {
			return fmt.Errorf("failed to build request: %w", err)
		}
	}

	response, err := service.UpdateSecret(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	fmt.Printf("✅ Secret updated successfully!\n")
	fmt.Printf("ID: %d\n", response.ID)
	fmt.Printf("Name: %s\n", response.Name)
	fmt.Printf("Type: %s\n", response.Type)
	fmt.Printf("Updated: %s\n", response.UpdatedAt.Format(time.RFC3339))

	if len(req.Value) > 0 {
		fmt.Printf("🔐 New encrypted version created\n")
	}

	return nil
}

// runUpdateRemote updates the secret through the server (PUT /api/v1/secrets/{id})
// so it operates on the same store the dashboard/API use. Supports value,
// max-reads, and expiration (set or clear); --type is not supported by the
// endpoint (and is ignored in embedded mode too).
func runUpdateRemote(rc *common.RemoteClient) error {
	ctx := context.Background()

	// Fetch current state for the display + interactive defaults. The GET response
	// (without include_value) is the secret node itself, with PascalCase keys that
	// unmarshal straight into models.SecretNode.
	var current models.SecretNode
	if err := rc.Get(ctx, fmt.Sprintf("/api/v1/secrets/%d", updateID), &current); err != nil {
		return fmt.Errorf("failed to get current secret: %w", err)
	}

	fmt.Printf("🔄 Updating Secret: %s (ID: %d)\n", current.Name, current.ID)
	fmt.Printf("Current Type: %s\n", current.Type)
	if current.MaxReads != nil {
		fmt.Printf("Current Max Reads: %d\n", *current.MaxReads)
	}
	if current.Expiration != nil {
		fmt.Printf("Current Expiration: %s\n", current.Expiration.Format(time.RFC3339))
	}
	fmt.Println()

	var req *core.UpdateSecretRequest
	var err error
	if updateInteractive {
		req, err = interactiveUpdate(&current)
	} else {
		req, err = buildUpdateRequest()
	}
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}

	body := map[string]interface{}{}
	if len(req.Value) > 0 {
		body["value"] = string(req.Value)
	}
	if req.MaxReads != nil {
		body["max_reads"] = *req.MaxReads
	}
	if req.ClearExpiration {
		body["clear_expiration"] = true
	} else if req.Expiration != nil {
		body["expiration"] = req.Expiration.Format(time.RFC3339)
	}

	var updated models.SecretNode
	if err := rc.Put(ctx, fmt.Sprintf("/api/v1/secrets/%d", updateID), body, &updated); err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	fmt.Printf("✅ Secret updated successfully!\n")
	fmt.Printf("ID: %d\n", updated.ID)
	fmt.Printf("Name: %s\n", updated.Name)
	fmt.Printf("Type: %s\n", updated.Type)
	if len(req.Value) > 0 {
		fmt.Printf("🔐 New encrypted version created\n")
	}
	return nil
}

func buildUpdateRequest() (*core.UpdateSecretRequest, error) {
	req := &core.UpdateSecretRequest{
		ID:        updateID,
		UpdatedBy: "cli-user",
	}

	if updateFromFile != "" {
		cleanPath := filepath.Clean(updateFromFile)
		if filepath.IsAbs(cleanPath) {
			return nil, fmt.Errorf("absolute paths not allowed: %s", cleanPath)
		}
		info, err := os.Lstat(cleanPath)
		if err != nil {
			return nil, fmt.Errorf("cannot stat file: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlinks not allowed: %s", cleanPath)
		}
		value, err := os.ReadFile(cleanPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", cleanPath, err)
		}
		req.Value = value
	} else if updateValue != "" {
		req.Value = []byte(updateValue)
	}

	// Note: Type updates are not supported in the current core implementation
	if updateType != "" {
		fmt.Printf("Warning: Type updates are not currently supported, ignoring --type flag\n")
	}

	if updateMaxReads >= 0 {
		req.MaxReads = &updateMaxReads
	}

	if updateClearExp {
		req.ClearExpiration = true
	} else if updateExpiration != "" {
		exp, err := time.Parse(time.RFC3339, updateExpiration)
		if err != nil {
			return nil, fmt.Errorf("invalid expiration format (use RFC3339): %w", err)
		}
		req.Expiration = &exp
	}

	return req, nil
}

func interactiveUpdate(current *models.SecretNode) (*core.UpdateSecretRequest, error) {
	reader := bufio.NewReader(os.Stdin)

	ask := func(prompt string, defaultVal string) string {
		if defaultVal != "" {
			fmt.Printf("%s [%s]: ", prompt, defaultVal)
		} else {
			fmt.Printf("%s [no change]: ", prompt)
		}
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		return text
	}

	askBool := func(prompt string) bool {
		for {
			input := ask(prompt+" (y/n)", "n")
			switch strings.ToLower(input) {
			case "y", "yes": //nolint:goconst
				return true
			case "n", "no", "":
				return false
			default:
				fmt.Printf("Please enter 'y' or 'n'\n")
			}
		}
	}

	fmt.Println("🔄 Interactive Secret Update")
	fmt.Println("============================")

	req := &core.UpdateSecretRequest{
		ID:        updateID,
		UpdatedBy: "cli-user",
	}

	if askBool("Update secret value?") {
		fmt.Print("New secret value (hidden): ")
		valueBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil, fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println()
		if len(valueBytes) > 0 {
			req.Value = valueBytes
		}
	}

	newType := ask("Secret type", current.Type)
	if newType != "" && newType != current.Type {
		fmt.Printf("Warning: Type updates are not currently supported, ignoring type change\n")
	}

	currentMaxReads := "unlimited"
	if current.MaxReads != nil {
		currentMaxReads = strconv.Itoa(*current.MaxReads)
	}

	maxReadsStr := ask("Max reads (0 for unlimited)", currentMaxReads)
	if maxReadsStr != "" && maxReadsStr != currentMaxReads {
		maxReads, err := strconv.Atoi(maxReadsStr)
		if err == nil {
			req.MaxReads = &maxReads
		}
	}

	currentExp := "none"
	if current.Expiration != nil {
		currentExp = current.Expiration.Format(time.RFC3339)
	}

	if askBool("Update expiration?") {
		if askBool("Clear expiration?") {
			req.ClearExpiration = true
		} else {
			expirationStr := ask("Expiration (RFC3339 format)", currentExp)
			if expirationStr != "" && expirationStr != currentExp {
				exp, err := time.Parse(time.RFC3339, expirationStr)
				if err != nil {
					fmt.Printf("Warning: Invalid expiration format, ignoring\n")
				} else {
					req.Expiration = &exp
				}
			}
		}
	}

	return req, nil
}
