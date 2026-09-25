//go:build !nomigrate_azure

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/migrate/internal/azuresource"
	"github.com/keyorixhq/keyorix/migrate/internal/cloudentry"
	"github.com/keyorixhq/keyorix/migrate/internal/plan"
	"github.com/keyorixhq/keyorix/migrate/internal/target"
)

var (
	azureServer        string
	azureKeyorixToken  string
	azureTokenFile     string
	azureProjectID     int
	azureEnvironmentID int
	azureApply         bool
	azureForce         bool
	azureReportPath    string

	azureVaultURL   string
	azureNamePrefix string
	azureSplitJSON  bool
)

var azureCmd = &cobra.Command{
	Use:   "azure",
	Short: "Import secrets from an Azure Key Vault",
	Long: `Import secrets from an Azure Key Vault into Keyorix.

  keyorix-migrate azure --vault-url https://myvault.vault.azure.net/ --name-prefix team-a- \
    --server https://keyorix.example.com --project 7 --environment 3

Defaults to a dry run: prints the mapping plan (source secret -> Keyorix
secret name, and create/update/skip/conflict for each) without writing
anything. Pass --apply to execute it. Before printing the plan (and again
before executing it), the Keyorix token is checked: valid, not revoked, not
expiring within the next hour, and scoped to write in the target
project/environment.

Azure credentials come from the ambient identity chain
(DefaultAzureCredential: managed identity, workload identity, environment,
or Azure CLI login) — never from a flag. A secret whose current version is
disabled is reported as skipped, not imported.

A secret whose value is a JSON object can be split into one Keyorix secret
per top-level key with --split-json; without it, the whole JSON string is
imported as a single secret.

Credentials (--token) can also be passed via the sibling --*-file flag (a
path, or "-" for stdin) instead of directly on the command line, which is
visible via ps/proc and shell history.`,
	SilenceUsage: true,
	RunE:         runAzure,
}

func init() {
	azureCmd.Flags().StringVar(&azureServer, "server", "", "Keyorix server URL (or $KEYORIX_SERVER)")
	azureCmd.Flags().StringVar(&azureKeyorixToken, "token", "", "Keyorix Personal Access Token (or $KEYORIX_TOKEN)")
	azureCmd.Flags().StringVar(&azureTokenFile, "token-file", "", "read the Keyorix token from this file (\"-\" for stdin)")
	azureCmd.Flags().IntVar(&azureProjectID, "project", 0, "target Keyorix project ID (required)")
	azureCmd.Flags().IntVar(&azureEnvironmentID, "environment", 0, "target Keyorix environment ID (required)")
	azureCmd.Flags().BoolVar(&azureApply, "apply", false, "execute the plan (default: dry run, print the plan only)")
	azureCmd.Flags().BoolVar(&azureForce, "force", false, "overwrite a conflicting secret this tool did not create (requires --apply)")
	azureCmd.Flags().StringVar(&azureReportPath, "report", "", "write the JSON per-item report to this path (optional)")

	azureCmd.Flags().StringVar(&azureVaultURL, "vault-url", "", "Azure Key Vault URL, e.g. https://myvault.vault.azure.net/ (required, or $AZURE_VAULT_URL)")
	azureCmd.Flags().StringVar(&azureNamePrefix, "name-prefix", "", "only import secrets whose name has this prefix")
	azureCmd.Flags().BoolVar(&azureSplitJSON, "split-json", false, "import each top-level key of a JSON-object secret as its own Keyorix secret")

	rootCmd.AddCommand(azureCmd)
}

func runAzure(cmd *cobra.Command, _ []string) error {
	if azureProjectID == 0 || azureEnvironmentID == 0 {
		return fmt.Errorf("--project and --environment are both required")
	}
	if azureForce && !azureApply {
		return fmt.Errorf("--force requires --apply")
	}
	vaultURL := envDefault(azureVaultURL, "AZURE_VAULT_URL")
	if vaultURL == "" {
		return fmt.Errorf("--vault-url (or $AZURE_VAULT_URL) is required")
	}

	ctx := cmd.Context()

	serverURL, err := resolveServer(azureServer)
	if err != nil {
		return err
	}
	keyorixTok, err := resolveCredential(cmd, "token", azureKeyorixToken, azureTokenFile, "KEYORIX_TOKEN")
	if err != nil {
		return err
	}
	if keyorixTok == "" {
		return fmt.Errorf("no token configured: use --token, --token-file, or $KEYORIX_TOKEN (a Keyorix Personal Access Token)")
	}
	apiClient, err := newAPIClient(serverURL, keyorixTok)
	if err != nil {
		return err
	}
	tgt := target.New(apiClient, azureProjectID, azureEnvironmentID)

	if err := tgt.Preflight(ctx, keyorixTok); err != nil {
		return err
	}

	src := azuresource.New(azuresource.Config{VaultURL: vaultURL, NamePrefix: azureNamePrefix, SplitJSON: azureSplitJSON})
	cloudEntries, skipped, err := src.List(ctx)
	if err != nil {
		return err
	}
	if len(cloudEntries) == 0 && len(skipped) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "no secrets found in this Key Vault")
		return nil
	}

	skippedItems := make([]plan.Item, 0, len(skipped))
	for _, s := range skipped {
		skippedItems = append(skippedItems, plan.Item{Entry: plan.Entry{SourceKind: "azure", Path: s.Locator}, Outcome: plan.Skip, Reason: s.Reason})
	}

	planEntries := buildCloudPlanEntries("azure", cloudEntries, func(e cloudentry.Entry) string {
		field := e.Field
		if field == "" {
			field = "value"
		}
		return plan.SourceID("azure-key-vault", vaultURL, e.RawName, field)
	})

	unique, collided := splitIntraBatchNameCollisions(planEntries)
	built, err := plan.BuildPlan(ctx, tgt, unique)
	if err != nil {
		return err
	}
	items := make([]plan.Item, 0, len(skippedItems)+len(collided)+len(built))
	items = append(items, skippedItems...)
	items = append(items, collided...)
	items = append(items, built...)

	return runCloudPlan(ctx, tgt, keyorixTok, items, built, azureApply, azureForce, azureReportPath)
}
