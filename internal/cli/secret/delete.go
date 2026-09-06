package secret

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	deleteID    uint
	deleteName  string
	deleteNS    uint
	deleteEnv   uint
	deleteForce bool
)

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a secret",
	Long: `Delete a secret permanently.

Examples:
  keyorix secret delete --id 123
  keyorix secret delete --name "db-password" --project 1 --environment 1
  keyorix secret delete --id 123 --force  # Skip confirmation`,
	RunE: runDelete,
}

func init() {
	deleteCmd.Flags().UintVar(&deleteID, "id", 0, "Secret ID")
	deleteCmd.Flags().StringVar(&deleteName, "name", "", "Secret name")
	deleteCmd.Flags().UintVar(&deleteNS, "project", 1, "Project ID (required with --name)")
	deleteCmd.Flags().UintVar(&deleteEnv, "environment", 1, "Environment ID (required with --name)")
	deleteCmd.Flags().BoolVar(&deleteForce, "force", false, "Skip confirmation prompt")
}

func runDelete(cmd *cobra.Command, args []string) error {
	if deleteID == 0 && deleteName == "" {
		return fmt.Errorf("either --id or --name is required")
	}

	if rc, ok := common.NewRemoteClient(); ok {
		return runDeleteRemote(rc)
	}

	// Obtain storage via the factory so the backend honors cfg.Storage.Type (ADR-049).
	storageImpl, err := common.InitializeStorage()
	if err != nil {
		return err
	}
	service := core.NewKeyorixCore(storageImpl)

	// Create context
	ctx := context.Background()

	var secretID uint
	var secretName string

	// Get secret information
	if deleteID != 0 {
		secret, err := service.GetSecret(ctx, deleteID)
		if err != nil {
			return fmt.Errorf("secret not found: %w", err)
		}
		secretID = secret.ID
		secretName = secret.Name
	} else {
		// Find by name using storage method
		secret, err := storageImpl.GetSecretByName(ctx, deleteName, deleteNS, deleteEnv)
		if err != nil {
			return fmt.Errorf("secret not found: %w", err)
		}

		secretID = secret.ID
		secretName = secret.Name
	}

	// Show what we're about to delete
	fmt.Printf("🗑️  About to delete secret:\n")
	fmt.Printf("ID: %d\n", secretID)
	fmt.Printf("Name: %s\n", secretName)

	// Get versions count by listing versions
	versions, err := storageImpl.GetSecretVersions(ctx, secretID)
	if err != nil {
		return fmt.Errorf("failed to get versions: %w", err)
	}
	fmt.Printf("Versions: %d\n", len(versions))

	// Confirmation
	if !deleteForce {
		fmt.Printf("\n⚠️  This action cannot be undone!\n")
		fmt.Printf("All versions and metadata will be permanently deleted.\n\n")

		if !confirmDeletion(secretName) {
			fmt.Printf("❌ Deletion cancelled\n")
			return nil
		}
	}

	// Delete the secret
	if err := service.DeleteSecret(ctx, secretID); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	fmt.Printf("✅ Secret '%s' (ID: %d) deleted successfully\n", secretName, secretID)
	fmt.Printf("🗑️  %d versions were also deleted\n", len(versions))

	return nil
}

// runDeleteRemote handles `secret delete` in remote mode: resolves the target
// secret via GET /api/v1/secrets/{id} (--id) or a filtered
// GET /api/v1/secrets?project_id=&environment_id=&search= lookup (--name,
// matched exactly client-side -- the list endpoint only offers a fuzzy
// "search" filter, not an exact-name one), fetches its version count for the
// same pre-delete summary the local path prints, then DELETEs it.
func runDeleteRemote(rc *common.RemoteClient) error {
	fmt.Printf("Target: %s\n", rc.Endpoint)
	ctx := context.Background()

	var secretID uint
	var secretName string
	if deleteID != 0 {
		var secret models.SecretNode
		if err := rc.Get(ctx, fmt.Sprintf("/api/v1/secrets/%d", deleteID), &secret); err != nil {
			return fmt.Errorf("secret not found: %w", err)
		}
		secretID, secretName = secret.ID, secret.Name
	} else {
		id, name, err := findRemoteSecretByName(ctx, rc, deleteName, deleteNS, deleteEnv)
		if err != nil {
			return err
		}
		secretID, secretName = id, name
	}

	fmt.Printf("🗑️  About to delete secret:\n")
	fmt.Printf("ID: %d\n", secretID)
	fmt.Printf("Name: %s\n", secretName)

	var versionsBody struct {
		Versions []*models.SecretVersion `json:"versions"`
	}
	if err := rc.Get(ctx, fmt.Sprintf("/api/v1/secrets/%d/versions", secretID), &versionsBody); err != nil {
		return fmt.Errorf("failed to get versions: %w", err)
	}
	fmt.Printf("Versions: %d\n", len(versionsBody.Versions))

	if !deleteForce {
		fmt.Printf("\n⚠️  This action cannot be undone!\n")
		fmt.Printf("All versions and metadata will be permanently deleted.\n\n")
		if !confirmDeletion(secretName) {
			fmt.Printf("❌ Deletion cancelled\n")
			return nil
		}
	}

	if err := rc.Delete(ctx, fmt.Sprintf("/api/v1/secrets/%d", secretID)); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	fmt.Printf("✅ Secret '%s' (ID: %d) deleted successfully\n", secretName, secretID)
	fmt.Printf("🗑️  %d versions were also deleted\n", len(versionsBody.Versions))
	return nil
}

// findRemoteSecretByName resolves a secret name to its ID via the list endpoint's
// fuzzy "search" filter, then requires an EXACT name match among the results --
// GET /api/v1/secrets has no exact-name filter, and treating a fuzzy substring
// hit as a confirmed match could delete the wrong secret.
func findRemoteSecretByName(ctx context.Context, rc *common.RemoteClient, name string, projectID, environmentID uint) (uint, string, error) {
	path := fmt.Sprintf("/api/v1/secrets?project_id=%d&environment_id=%d&search=%s&page_size=100",
		projectID, environmentID, url.QueryEscape(name))
	var body struct {
		Secrets []*models.SecretWithSharingInfo `json:"secrets"`
	}
	if err := rc.Get(ctx, path, &body); err != nil {
		return 0, "", fmt.Errorf("secret not found: %w", err)
	}
	var matches []*models.SecretWithSharingInfo
	for _, s := range body.Secrets {
		if s.Name == name {
			matches = append(matches, s)
		}
	}
	switch len(matches) {
	case 0:
		return 0, "", fmt.Errorf("secret not found: no secret named %q in project %d, environment %d", name, projectID, environmentID)
	case 1:
		return matches[0].ID, matches[0].Name, nil
	default:
		return 0, "", fmt.Errorf("ambiguous: %d secrets named %q in project %d, environment %d -- use --id instead", len(matches), name, projectID, environmentID)
	}
}

func confirmDeletion(secretName string) bool {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("Type the secret name '%s' to confirm deletion: ", secretName)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input != secretName {
		fmt.Printf("❌ Name mismatch. Expected '%s', got '%s'\n", secretName, input)
		return false
	}

	fmt.Printf("Are you absolutely sure? (yes/no): ")
	confirmation, _ := reader.ReadString('\n')
	confirmation = strings.TrimSpace(strings.ToLower(confirmation))

	return confirmation == "yes"
}
