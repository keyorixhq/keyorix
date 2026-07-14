package secret

import (
	"context"
	"fmt"
	"net/url"
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
	getRef       string
	getShowValue bool
	getProject   uint
	getEnv       uint
)

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a secret",
	Long: `Retrieve a secret by ID, by name, or by a project/environment/name reference.

--ref reads the secret's value by a human-readable "project/environment/name"
reference (ADR-059) — handy for scripts and automation. It always reads the value
(so it counts toward max_reads and is audited like any value read).

Examples:
  keyorix secret get --id 123
  keyorix secret get --name "db-password" --project 1 --environment 1
  keyorix secret get --id 123 --show-value          # show decrypted value
  keyorix secret get --ref app/production/db-password`,
	RunE: runGet,
}

func init() {
	getCmd.Flags().UintVar(&getID, "id", 0, "Secret ID")
	getCmd.Flags().StringVar(&getName, "name", "", "Secret name")
	getCmd.Flags().StringVar(&getRef, "ref", "", "Reference: project/environment/name (reads the value)")
	getCmd.Flags().UintVar(&getProject, "project", 1, "Project ID (required with --name)")
	getCmd.Flags().UintVar(&getEnv, "environment", 1, "Environment ID (required with --name)")
	getCmd.Flags().BoolVar(&getShowValue, "show-value", false, "Show decrypted secret value")
}

func runGet(cmd *cobra.Command, args []string) error {
	selectors := 0
	for _, set := range []bool{getID != 0, getName != "", getRef != ""} {
		if set {
			selectors++
		}
	}
	if selectors == 0 {
		return fmt.Errorf("one of --id, --name, or --ref is required")
	}
	if selectors > 1 {
		return fmt.Errorf("--id, --name, and --ref are mutually exclusive")
	}
	// A reference read is value-oriented (it resolves to one secret and returns its value).
	if getRef != "" {
		getShowValue = true
	}

	ctx := context.Background()

	if rc, ok := common.NewRemoteClient(); ok {
		return runGetRemote(ctx, rc)
	}
	return runGetEmbedded(ctx)
}

// ── Remote mode ───────────────────────────────────────────────────────────────

func runGetRemote(ctx context.Context, rc *common.RemoteClient) error { // NOSONAR -- cognitive complexity 23, suppress go:S3776
	var secret *models.SecretNode
	var value string

	if getRef != "" {
		q := url.Values{}
		q.Set("ref", getRef)
		var body struct {
			Secret *models.SecretNode `json:"secret"`
			Value  string             `json:"value"`
		}
		if err := rc.Get(ctx, "/api/v1/secrets/value?"+q.Encode(), &body); err != nil {
			return fmt.Errorf("get secret by ref: %w", err)
		}
		displaySecret(body.Secret, body.Value)
		return nil
	}

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
			"/api/v1/secrets?project_id=%d&environment_id=%d&page_size=1000&page=1",
			getProject, getEnv,
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

func runGetEmbedded(ctx context.Context) error { // NOSONAR -- cognitive complexity 28, suppress go:S3776
	service, err := common.InitializeCoreService()
	if err != nil {
		return fmt.Errorf("failed to initialize service: %w", err)
	}

	if getRef != "" {
		secret, err := service.ResolveSecretRef(ctx, getRef)
		if err != nil {
			return fmt.Errorf("resolve ref %q: %w", getRef, err)
		}
		val, err := service.GetSecretValue(ctx, secret.ID)
		if err != nil {
			return fmt.Errorf("failed to get secret value: %w", err)
		}
		displaySecret(secret, string(val))
		return nil
	}

	var secret *models.SecretNode

	if getID != 0 {
		secret, err = service.GetSecret(ctx, getID)
		if err != nil {
			return fmt.Errorf("failed to get secret: %w", err)
		}
	} else {
		// Page through the matching secrets to find the named one — a single capped
		// page would fail to find a secret that sorts beyond it ("not found" for a
		// secret that exists).
		const pageSize = 500
		for page := 1; secret == nil; page++ {
			filter := &coreStorage.SecretFilter{Page: page, PageSize: pageSize}
			if getProject != 0 {
				filter.ProjectID = &getProject
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
			if len(secrets) < pageSize {
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
	fmt.Printf("Project:     %d\n", secret.ProjectID)
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
