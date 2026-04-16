package secret

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	getID        uint
	getName      string
	getShowValue bool
	getNamespace uint
	getZone      uint
	getEnv       uint
)

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a secret",
	Long: `Retrieve a secret by ID or name.

Examples:
  keyorix secret get --id 123
  keyorix secret get --name "db-password" --namespace 1 --zone 1 --environment 1
  keyorix secret get --id 123 --show-value  # Show decrypted value`,
	RunE: runGet,
}

func init() {
	getCmd.Flags().UintVar(&getID, "id", 0, "Secret ID")
	getCmd.Flags().StringVar(&getName, "name", "", "Secret name")
	getCmd.Flags().UintVar(&getNamespace, "namespace", 1, "Namespace ID (required with --name)")
	getCmd.Flags().UintVar(&getZone, "zone", 1, "Zone ID (required with --name)")
	getCmd.Flags().UintVar(&getEnv, "environment", 1, "Environment ID (required with --name)")
	getCmd.Flags().BoolVar(&getShowValue, "show-value", false, "Show decrypted secret value")
}

func runGet(cmd *cobra.Command, args []string) error {
	if getID == 0 && getName == "" {
		return fmt.Errorf("either --id or --name is required")
	}

	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		return runGetRemote(ctx, rc)
	}
	return runGetEmbedded(ctx)
}

// ── Remote mode ───────────────────────────────────────────────────────────────

func runGetRemote(ctx context.Context, rc *common.RemoteClient) error {
	var secret *models.SecretNode
	var value string

	if getID != 0 {
		if getShowValue {
			path := fmt.Sprintf("/api/v1/secrets/%d?include_value=true", getID)
			var body struct {
				Secret *models.SecretNode `json:"secret"`
				Value  string             `json:"value"`
			}
			if err := rc.Get(ctx, path, &body); err != nil {
				return fmt.Errorf("get secret: %w", err)
			}
			secret = body.Secret
			value = body.Value
		} else {
			secret = &models.SecretNode{}
			if err := rc.Get(ctx, fmt.Sprintf("/api/v1/secrets/%d", getID), secret); err != nil {
				return fmt.Errorf("get secret: %w", err)
			}
		}
	} else {
		// Resolve name → secret via filtered list, then optionally fetch value.
		path := fmt.Sprintf(
			"/api/v1/secrets?namespace_id=%d&zone_id=%d&environment_id=%d&page_size=1000&page=1",
			getNamespace, getZone, getEnv,
		)
		var body struct {
			Secrets []*models.SecretNode `json:"secrets"`
		}
		if err := rc.Get(ctx, path, &body); err != nil {
			return fmt.Errorf("list secrets: %w", err)
		}
		for _, s := range body.Secrets {
			if strings.EqualFold(s.Name, getName) {
				secret = s
				break
			}
		}
		if secret == nil {
			return fmt.Errorf("secret %q not found", getName)
		}

		if getShowValue {
			path := fmt.Sprintf("/api/v1/secrets/%d?include_value=true", secret.ID)
			var vbody struct {
				Secret *models.SecretNode `json:"secret"`
				Value  string             `json:"value"`
			}
			if err := rc.Get(ctx, path, &vbody); err != nil {
				return fmt.Errorf("get secret value: %w", err)
			}
			if vbody.Secret != nil {
				secret = vbody.Secret
			}
			value = vbody.Value
		}
	}

	displaySecret(secret, value)
	return nil
}

// ── Embedded mode ─────────────────────────────────────────────────────────────

func runGetEmbedded(ctx context.Context) error {
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	var secret *models.SecretNode

	if getID != 0 {
		secret, err = service.GetSecret(ctx, getID)
		if err != nil {
			return fmt.Errorf("failed to get secret: %w", err)
		}
	} else {
		filter := &coreStorage.SecretFilter{Page: 1, PageSize: 1000}
		if getNamespace != 0 {
			filter.NamespaceID = &getNamespace
		}
		if getZone != 0 {
			filter.ZoneID = &getZone
		}
		if getEnv != 0 {
			filter.EnvironmentID = &getEnv
		}
		secrets, _, err := service.ListSecrets(ctx, filter)
		if err != nil {
			return fmt.Errorf("failed to list secrets: %w", err)
		}
		for _, s := range secrets {
			if strings.EqualFold(s.Name, getName) {
				secret = s
				break
			}
		}
		if secret == nil {
			return fmt.Errorf("secret %q not found", getName)
		}
	}

	var value string
	if getShowValue {
		val, err := service.GetSecretValue(ctx, secret.ID)
		if err != nil {
			return fmt.Errorf("failed to get secret value: %w", err)
		}
		value = string(val)
	}

	displaySecret(secret, value)
	return nil
}

// ── Display ───────────────────────────────────────────────────────────────────

func displaySecret(secret *models.SecretNode, value string) {
	fmt.Printf("Secret Information\n")
	fmt.Printf("==================\n")
	fmt.Printf("ID:          %d\n", secret.ID)
	fmt.Printf("Name:        %s\n", secret.Name)
	fmt.Printf("Type:        %s\n", secret.Type)
	fmt.Printf("Status:      %s\n", secret.Status)
	fmt.Printf("Namespace:   %d\n", secret.NamespaceID)
	fmt.Printf("Zone:        %d\n", secret.ZoneID)
	fmt.Printf("Environment: %d\n", secret.EnvironmentID)
	fmt.Printf("Created By:  %s\n", secret.CreatedBy)
	fmt.Printf("Created:     %s\n", secret.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Updated:     %s\n", secret.UpdatedAt.Format(time.RFC3339))

	if secret.MaxReads != nil {
		fmt.Printf("Max Reads:   %d\n", *secret.MaxReads)
	}
	if secret.Expiration != nil {
		fmt.Printf("Expires:     %s\n", secret.Expiration.Format(time.RFC3339))
		if time.Now().After(*secret.Expiration) {
			fmt.Printf("WARNING: secret is EXPIRED\n")
		}
	}

	if value != "" {
		fmt.Printf("\nDecrypted Value\n")
		fmt.Printf("---------------\n")
		fmt.Printf("%s\n", value)
	} else if getShowValue {
		fmt.Printf("\n(value unavailable)\n")
	} else {
		fmt.Printf("\nUse --show-value to display the decrypted value.\n")
	}
}
