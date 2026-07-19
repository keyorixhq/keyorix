// import.go — Cobra command, runImport, doImport, and name resolution helpers.
//
// For format parsers (dotenv, vault, json) see import_parsers.go.
package secret

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
)

var (
	importFile         string
	importFormat       string
	importEnv          string
	importProject      string
	importDryRun       bool
	importSkipExisting bool
	importDecryptWith  string
)

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import secrets from a file or a live source (Vault / AWS / Azure)",
	Long: `Import secrets from a file, or directly from a running secrets manager.

File mode (--file):
  keyorix secret import --file .env --format dotenv --env production
  keyorix secret import --file vault-export.yaml --format vault --env production
  keyorix secret import --file secrets.json --format json --env staging
  keyorix secret import --file .env --format dotenv --env development --dry-run
  keyorix secret import --file secrets.enc.json --decrypt-with private.pem --env production

Live-source mode (--source) — reads directly from a running provider using your
local credentials and never sends them to the Keyorix server:
  keyorix secret import --source vault --vault-path prod --env production
  keyorix secret import --source aws   --aws-region eu-west-1 --env production
  keyorix secret import --source azure --azure-vault-url https://kv.vault.azure.net --env production
  keyorix secret import --source gcp   --gcp-project my-gcp-project --env production

Supported file formats (--format):
  dotenv  .env files (KEY=VALUE, comments and blank lines ignored)
  vault   Medusa/Vault YAML export (path hierarchy, last two segments become name)
  json    Flat key-value JSON object

Encrypted imports (--decrypt-with):
  When the file is a keyorix-encrypted-export-v1 envelope (produced by
  'keyorix secret export --format encrypted-json'), pass the RSA private key
  with --decrypt-with. The file is decrypted transparently and then imported
  as a standard JSON payload.

Live sources (--source):
  vault   HashiCorp Vault KV engine (VAULT_ADDR / VAULT_TOKEN or --vault-* flags)
  aws     AWS Secrets Manager (standard AWS credential chain)
  azure   Azure Key Vault (DefaultAzureCredential)
  gcp     Google Cloud Secret Manager (Application Default Credentials)

Multi-field secrets (Vault KV paths, AWS/Azure JSON values) explode into one
Keyorix secret per field ("<name>-<field>") unless --no-explode is set.`,
	RunE: runImport,
}

func init() {
	importCmd.Flags().StringVar(&importFile, "file", "", "Path to the file to import (file mode)")
	importCmd.Flags().StringVar(&importFormat, "format", "dotenv", "File format: dotenv, vault, json")
	importCmd.Flags().StringVar(&importEnv, "env", "development", "Environment name (e.g. production)")
	importCmd.Flags().StringVar(&importProject, "project", "default", "Project name")
	importCmd.Flags().BoolVar(&importDryRun, "dry-run", false, "Show what would be imported without creating anything")
	importCmd.Flags().BoolVar(&importSkipExisting, "skip-existing", true, "Skip secrets that already exist instead of failing")
	importCmd.Flags().StringVar(&importDecryptWith, "decrypt-with", "", "Path to RSA private key PEM to decrypt an encrypted-json export")

	// Live-source flags (mutually exclusive with --file).
	importCmd.Flags().StringVar(&importSource, "source", "", "Live source: vault, aws, azure, gcp (instead of --file)")
	importCmd.Flags().StringVar(&importPrefix, "prefix", "", "Prepend this prefix to every imported secret name")
	importCmd.Flags().BoolVar(&importNoExplode, "no-explode", false, "Store JSON-object values as a single secret instead of one per field")
	// Vault
	importCmd.Flags().StringVar(&vaultAddr, "vault-addr", "", "Vault address (default: $VAULT_ADDR)")
	importCmd.Flags().StringVar(&vaultToken, "vault-token", "", "Vault token (default: $VAULT_TOKEN)")
	importCmd.Flags().StringVar(&vaultMount, "vault-mount", "secret", "Vault KV mount path")
	importCmd.Flags().StringVar(&vaultPath, "vault-path", "", "Vault path prefix to import (default: whole mount)")
	importCmd.Flags().IntVar(&vaultKVVersion, "vault-kv-version", 2, "Vault KV engine version (1 or 2)")
	// AWS
	importCmd.Flags().StringVar(&awsRegion, "aws-region", "", "AWS region (default: SDK credential chain)")
	importCmd.Flags().StringVar(&awsPrefix, "aws-prefix", "", "Only import AWS secrets whose name starts with this prefix")
	// Azure
	importCmd.Flags().StringVar(&azureVaultURL, "azure-vault-url", "", "Azure Key Vault URL (https://<vault>.vault.azure.net)")
	// GCP
	importCmd.Flags().StringVar(&gcpProject, "gcp-project", "", "GCP project ID to import Secret Manager secrets from")
	importCmd.Flags().StringVar(&gcpPrefix, "gcp-prefix", "", "Only import GCP secrets whose name starts with this prefix")
}

// secretEntry is a parsed key/value pair ready to be created.
type secretEntry struct {
	Name  string
	Value string
}

// sanitizeForTerminal strips control characters (CR/LF, ANSI/C1 escapes, NUL,
// etc.) from untrusted import-file content before it's echoed to the operator's
// terminal in progress/dry-run output. A crafted import file could otherwise
// embed terminal escape sequences that overwrite or hide the CLI's own status
// lines during the same run. This only affects what's printed — the value
// actually stored in the vault is left untouched.
func sanitizeForTerminal(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1 // drop
		}
		return r
	}, s)
}

func runImport(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	entries, err := collectEntries(ctx)
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Println("No secrets found.")
		return nil
	}

	if importDryRun {
		fmt.Printf("Dry run — would import %d secret(s):\n\n", len(entries))
		for _, e := range entries {
			preview := e.Value
			if len(preview) > 20 {
				preview = preview[:20] + "..."
			}
			fmt.Printf("  %-30s = %s\n", sanitizeForTerminal(e.Name), sanitizeForTerminal(preview))
		}
		fmt.Printf("\nNo changes made (--dry-run).\n")
		return nil
	}

	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("no remote server configured; set KEYORIX_SERVER and KEYORIX_TOKEN or run 'keyorix auth login'")
	}

	nsID, err := resolveProjectID(ctx, rc, importProject)
	if err != nil {
		return err
	}
	envID, err := resolveEnvironmentID(ctx, rc, importEnv)
	if err != nil {
		return err
	}

	return doImport(ctx, rc, entries, nsID, envID)
}

// collectEntries gathers the secrets to import from exactly one of the two
// modes: a live provider (--source) or a local file (--file). The modes are
// mutually exclusive and one is required.
func collectEntries(ctx context.Context) ([]secretEntry, error) {
	switch {
	case importSource != "" && importFile != "":
		return nil, fmt.Errorf("--source and --file are mutually exclusive; use one")
	case importSource != "":
		entries, err := fetchFromSource(ctx, importSource)
		if err != nil {
			return nil, fmt.Errorf("read from %s: %w", importSource, err)
		}
		return entries, nil
	case importFile != "":
		clean := filepath.Clean(importFile)
		if _, err := os.Stat(clean); err != nil {
			return nil, fmt.Errorf("cannot open file %q: %w", importFile, err)
		}
		// Detect encrypted-json envelope and decrypt transparently.
		if importDecryptWith != "" {
			fileBytes, err := os.ReadFile(clean) // #nosec G304 — path already cleaned
			if err != nil {
				return nil, fmt.Errorf("read file %q: %w", clean, err)
			}
			if bytes.HasPrefix(bytes.TrimSpace(fileBytes), []byte(`{"format":"`+encryptedExportFormat)) {
				plain, err := decryptExport(fileBytes, importDecryptWith)
				if err != nil {
					return nil, fmt.Errorf("decrypt %q: %w", clean, err)
				}
				return parseJSONBytes(plain)
			}
		}
		entries, err := parseFile(clean, importFormat)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s file: %w", importFormat, err)
		}
		return entries, nil
	default:
		return nil, fmt.Errorf("specify a source: --file <path> (with --format) or --source <vault|aws|azure>")
	}
}

// ── Name resolution ───────────────────────────────────────────────────────────

func resolveProjectID(ctx context.Context, rc *common.RemoteClient, name string) (uint, error) {
	var body struct {
		Projects []*models.Project `json:"projects"`
	}
	if err := rc.Get(ctx, "/api/v1/projects", &body); err != nil {
		return 0, fmt.Errorf("list projects: %w", err)
	}
	for _, p := range body.Projects {
		if strings.EqualFold(p.Name, name) {
			return p.ID, nil
		}
	}
	return 0, fmt.Errorf("project %q not found", name)
}

func resolveEnvironmentID(ctx context.Context, rc *common.RemoteClient, name string) (uint, error) {
	var body struct {
		Environments []*models.Environment `json:"environments"`
	}
	if err := rc.Get(ctx, "/api/v1/environments", &body); err != nil {
		return 0, fmt.Errorf("list environments: %w", err)
	}
	for _, e := range body.Environments {
		if strings.EqualFold(e.Name, name) {
			return e.ID, nil
		}
	}
	return 0, fmt.Errorf("environment %q not found", name)
}

// ── Import logic ──────────────────────────────────────────────────────────────

func doImport(ctx context.Context, rc *common.RemoteClient, entries []secretEntry, nsID, envID uint) error {
	imported, skipped, failed := 0, 0, 0

	for _, e := range entries {
		displayName := sanitizeForTerminal(e.Name)
		body := map[string]interface{}{
			"name":           e.Name,
			"value":          e.Value,
			"type":           "generic",
			"project_id":     nsID,
			"environment_id": envID,
		}
		var created models.SecretNode
		err := rc.Post(ctx, "/api/v1/secrets", body, &created)
		if err != nil {
			errStr := err.Error()
			if importSkipExisting && (strings.Contains(errStr, "409") || strings.Contains(errStr, "already exists")) {
				fmt.Printf("  - Skipped  %-30s (already exists)\n", displayName)
				skipped++
				continue
			}
			fmt.Printf("  x Failed   %-30s %v\n", displayName, err)
			failed++
			continue
		}
		fmt.Printf("  + Imported %-30s (id=%d)\n", displayName, created.ID)
		imported++
	}

	total := imported + skipped + failed
	fmt.Printf("\nImported %d/%d secrets", imported, total)
	if skipped > 0 {
		fmt.Printf(", %d skipped", skipped)
	}
	if failed > 0 {
		fmt.Printf(", %d failed", failed)
	}
	fmt.Println()

	if failed > 0 {
		return fmt.Errorf("%d secret(s) failed to import", failed)
	}
	return nil
}
