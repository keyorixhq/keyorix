// fixed imports
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
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	createName          string
	createType          string
	createNamespaceID   uint
	createZoneID        uint
	createEnvironmentID uint
	createMaxReads      int
	createExpiration    string
	createValue         string
	createFromFile      string
	createInteractive   bool
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new secret",
	RunE:  runCreate,
}

func init() {
	createCmd.Flags().StringVar(&createName, "name", "", "Secret name (required)")
	createCmd.Flags().StringVar(&createType, "type", "generic", "Secret type")
	createCmd.Flags().UintVar(&createNamespaceID, "namespace", 1, "Namespace ID")
	createCmd.Flags().UintVar(&createZoneID, "zone", 1, "Zone ID")
	createCmd.Flags().UintVar(&createEnvironmentID, "environment", 1, "Environment ID")
	createCmd.Flags().IntVar(&createMaxReads, "max-reads", 0, "Maximum number of reads (0 = unlimited)")
	createCmd.Flags().StringVar(&createExpiration, "expires", "", "Expiration time (RFC3339 format)")
	createCmd.Flags().StringVar(&createValue, "value", "", "Secret value")
	createCmd.Flags().StringVar(&createFromFile, "from-file", "", "Read secret value from file")
	createCmd.Flags().BoolVar(&createInteractive, "interactive", false, "Interactive mode")
}

func runCreate(cmd *cobra.Command, args []string) error {
	// Initialize core service using storage factory
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	var req *core.CreateSecretRequest
	if createInteractive {
		req, err = interactiveCreate()
	} else {
		req, err = buildCreateRequest()
	}
	if err != nil {
		return err
	}

	ctx := context.Background()
	secret, err := service.CreateSecret(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	fmt.Printf("✅ Secret created successfully!\n")
	fmt.Printf("ID: %d\n", secret.ID)
	fmt.Printf("Name: %s\n", secret.Name)
	fmt.Printf("Type: %s\n", secret.Type)
	fmt.Printf("Namespace: %d\n", secret.NamespaceID)
	fmt.Printf("Zone: %d\n", secret.ZoneID)
	fmt.Printf("Environment: %d\n", secret.EnvironmentID)
	fmt.Printf("Created: %s\n", secret.CreatedAt.Format(time.RFC3339))
	if secret.Expiration != nil {
		fmt.Printf("Expires: %s\n", secret.Expiration.Format(time.RFC3339))
	}

	return nil
}

func buildCreateRequest() (*core.CreateSecretRequest, error) {
	if createName == "" {
		return nil, errors.New("secret name is required (use --name)")
	}

	var value []byte

	if createFromFile != "" {
		// ✅ G304: Check for file path safety
		cleanPath := filepath.Clean(createFromFile)
		if filepath.IsAbs(cleanPath) {
			return nil, fmt.Errorf("absolute paths are not allowed: %s", cleanPath)
		}
		fileInfo, err := os.Lstat(cleanPath)
		if err != nil {
			return nil, fmt.Errorf("cannot stat file: %w", err)
		}
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("symlinks are not allowed: %s", cleanPath)
		}
		value, err = os.ReadFile(cleanPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", cleanPath, err)
		}
	} else if createValue != "" {
		value = []byte(createValue)
	} else {
		return nil, errors.New("secret value is required (use --value or --from-file)")
	}

	req := &core.CreateSecretRequest{
		Name:          createName,
		Value:         value,
		Type:          createType,
		NamespaceID:   createNamespaceID,
		ZoneID:        createZoneID,
		EnvironmentID: createEnvironmentID,
		CreatedBy:     "cli-user",
	}

	if createMaxReads > 0 {
		req.MaxReads = &createMaxReads
	}

	if createExpiration != "" {
		exp, err := time.Parse(time.RFC3339, createExpiration)
		if err != nil {
			return nil, fmt.Errorf("invalid expiration format: %w", err)
		}
		req.Expiration = &exp
	}

	return req, nil
}

func interactiveCreate() (*core.CreateSecretRequest, error) {
	reader := bufio.NewReader(os.Stdin)

	ask := func(prompt string, defaultVal string) string {
		if defaultVal != "" {
			fmt.Printf("%s [%s]: ", prompt, defaultVal)
		} else {
			fmt.Printf("%s: ", prompt)
		}
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "" && defaultVal != "" {
			return defaultVal
		}
		return text
	}

	askUint := func(prompt string, defaultVal uint) uint {
		for {
			input := ask(prompt, fmt.Sprint(defaultVal))
			val, err := strconv.ParseUint(input, 10, 64)
			if err != nil || val > uint64(^uint(0)) {
				fmt.Println("Invalid number, please enter a valid positive integer.")
				continue
			}
			return uint(val)
		}
	}

	fmt.Println("🔐 Interactive Secret Creation")
	fmt.Println("==============================")

	name := ask("Secret name", "")
	if name == "" {
		return nil, errors.New("secret name is required")
	}

	secretType := ask("Secret type", "generic")
	namespaceID := askUint("Namespace ID", 1)
	zoneID := askUint("Zone ID", 1)
	environmentID := askUint("Environment ID", 1)

	fmt.Print("Secret value (hidden): ")
	valueBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, fmt.Errorf("failed to read secret value: %w", err)
	}
	fmt.Println()
	if len(valueBytes) == 0 {
		return nil, errors.New("secret value is required")
	}

	req := &core.CreateSecretRequest{
		Name:          name,
		Type:          secretType,
		NamespaceID:   namespaceID,
		ZoneID:        zoneID,
		EnvironmentID: environmentID,
		Value:         valueBytes,
		CreatedBy:     "cli-user",
	}

	maxReadsStr := ask("Max reads (0 for unlimited)", "0")
	if maxReadsStr != "0" {
		if m, err := strconv.Atoi(maxReadsStr); err == nil && m > 0 {
			req.MaxReads = &m
		}
	}

	expirationStr := ask("Expiration (RFC3339 format, leave empty for none)", "")
	if expirationStr != "" {
		if exp, err := time.Parse(time.RFC3339, expirationStr); err == nil {
			req.Expiration = &exp
		} else {
			fmt.Println("⚠️ Invalid expiration format. Skipping expiration.")
		}
	}

	return req, nil
}
