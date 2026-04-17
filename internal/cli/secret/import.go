package secret

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	importFile         string
	importFormat       string
	importEnv          string
	importNamespace    string
	importZone         string
	importDryRun       bool
	importSkipExisting bool
)

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import secrets from a file",
	Long: `Import secrets from a dotenv, Vault YAML, or JSON file.

Examples:
  keyorix secret import --file .env --format dotenv --env production
  keyorix secret import --file vault-export.yaml --format vault --env production
  keyorix secret import --file secrets.json --format json --env staging
  keyorix secret import --file .env --format dotenv --env development --dry-run

Supported formats:
  dotenv  .env files (KEY=VALUE, comments and blank lines ignored)
  vault   Medusa/Vault YAML export (path hierarchy, last two segments become name)
  json    Flat key-value JSON object`,
	RunE: runImport,
}

func init() {
	importCmd.Flags().StringVar(&importFile, "file", "", "Path to the file to import (required)")
	importCmd.Flags().StringVar(&importFormat, "format", "dotenv", "File format: dotenv, vault, json")
	importCmd.Flags().StringVar(&importEnv, "env", "development", "Environment name (e.g. production)")
	importCmd.Flags().StringVar(&importNamespace, "namespace", "default", "Namespace name")
	importCmd.Flags().StringVar(&importZone, "zone", "default", "Zone name")
	importCmd.Flags().BoolVar(&importDryRun, "dry-run", false, "Show what would be imported without creating anything")
	importCmd.Flags().BoolVar(&importSkipExisting, "skip-existing", true, "Skip secrets that already exist instead of failing")
	_ = importCmd.MarkFlagRequired("file")
}

// secretEntry is a parsed key/value pair ready to be created.
type secretEntry struct {
	Name  string
	Value string
}

func runImport(cmd *cobra.Command, args []string) error {
	// Validate and clean the file path.
	clean := filepath.Clean(importFile)
	if _, err := os.Stat(clean); err != nil {
		return fmt.Errorf("cannot open file %q: %w", importFile, err)
	}

	// Parse the file into a flat list of entries.
	entries, err := parseFile(clean, importFormat)
	if err != nil {
		return fmt.Errorf("failed to parse %s file: %w", importFormat, err)
	}

	if len(entries) == 0 {
		fmt.Println("No secrets found in file.")
		return nil
	}

	// Dry run: just print what would be imported.
	if importDryRun {
		fmt.Printf("Dry run — would import %d secret(s):\n\n", len(entries))
		for _, e := range entries {
			preview := e.Value
			if len(preview) > 20 {
				preview = preview[:20] + "..."
			}
			fmt.Printf("  %-30s = %s\n", e.Name, preview)
		}
		fmt.Printf("\nNo changes made (--dry-run).\n")
		return nil
	}

	// Require a remote client — import is a server operation.
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("no remote server configured; set KEYORIX_SERVER and KEYORIX_TOKEN or run 'keyorix auth login'")
	}

	ctx := cmd.Context()

	// Resolve namespace name → ID.
	nsID, err := resolveNamespaceID(ctx, rc, importNamespace)
	if err != nil {
		return err
	}

	// Resolve zone name → ID.
	zoneID, err := resolveZoneID(ctx, rc, importZone)
	if err != nil {
		return err
	}

	// Resolve environment name → ID.
	envID, err := resolveEnvironmentID(ctx, rc, importEnv)
	if err != nil {
		return err
	}

	return doImport(ctx, rc, entries, nsID, zoneID, envID)
}

// ── Name resolution ───────────────────────────────────────────────────────────

func resolveNamespaceID(ctx context.Context, rc *common.RemoteClient, name string) (uint, error) {
	var body struct {
		Namespaces []*models.Namespace `json:"namespaces"`
	}
	if err := rc.Get(ctx, "/api/v1/namespaces", &body); err != nil {
		return 0, fmt.Errorf("list namespaces: %w", err)
	}
	for _, ns := range body.Namespaces {
		if strings.EqualFold(ns.Name, name) {
			return ns.ID, nil
		}
	}
	return 0, fmt.Errorf("namespace %q not found", name)
}

func resolveZoneID(ctx context.Context, rc *common.RemoteClient, name string) (uint, error) {
	var body struct {
		Zones []*models.Zone `json:"zones"`
	}
	if err := rc.Get(ctx, "/api/v1/zones", &body); err != nil {
		return 0, fmt.Errorf("list zones: %w", err)
	}
	for _, z := range body.Zones {
		if strings.EqualFold(z.Name, name) {
			return z.ID, nil
		}
	}
	return 0, fmt.Errorf("zone %q not found", name)
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

func doImport(ctx context.Context, rc *common.RemoteClient, entries []secretEntry, nsID, zoneID, envID uint) error {
	imported, skipped, failed := 0, 0, 0

	for _, e := range entries {
		body := map[string]interface{}{
			"name":           e.Name,
			"value":          e.Value,
			"type":           "generic",
			"namespace_id":   nsID,
			"zone_id":        zoneID,
			"environment_id": envID,
		}

		var created models.SecretNode
		err := rc.Post(ctx, "/api/v1/secrets", body, &created)
		if err != nil {
			errStr := err.Error()
			if importSkipExisting && (strings.Contains(errStr, "409") || strings.Contains(errStr, "already exists")) {
				fmt.Printf("  - Skipped  %-30s (already exists)\n", e.Name)
				skipped++
				continue
			}
			fmt.Printf("  x Failed   %-30s %v\n", e.Name, err)
			failed++
			continue
		}

		fmt.Printf("  + Imported %-30s (id=%d)\n", e.Name, created.ID)
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

// ── Format parsers ────────────────────────────────────────────────────────────

func parseFile(path, format string) ([]secretEntry, error) {
	switch strings.ToLower(format) {
	case "dotenv", "env":
		return parseDotenv(path)
	case "vault":
		return parseVault(path)
	case "json":
		return parseJSON(path)
	default:
		return nil, fmt.Errorf("unknown format %q (supported: dotenv, vault, json)", format)
	}
}

// parseDotenv reads a standard .env file.
// Rules:
//   - Lines starting with # are comments.
//   - Blank lines are skipped.
//   - KEY=VALUE (value may be quoted with " or ').
//   - Keys with empty values are skipped.
func parseDotenv(path string) ([]secretEntry, error) {
	f, err := os.Open(path) // #nosec G304 — path already cleaned by caller
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []secretEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Split on the first '=' only.
		idx := strings.IndexByte(line, '=')
		if idx < 1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])

		// Strip surrounding quotes (" or ').
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}

		if key == "" || val == "" {
			continue
		}
		entries = append(entries, secretEntry{Name: key, Value: val})
	}
	return entries, scanner.Err()
}

// parseVault reads a Medusa/Vault YAML export.
//
// Expected shape (as produced by 'keyorix secret export --format vault'):
//
//	secret/production/database-password:
//	  value: supersecret123
//	secret/production/api-key:
//	  value: sk_live_abc123
//
// The secret name is the last path segment; the "value" key holds the secret value.
func parseVault(path string) ([]secretEntry, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	var entries []secretEntry
	for pathKey, v := range raw {
		// Secret name = last path segment (e.g. "database-password" from "secret/production/database-password").
		parts := strings.Split(strings.Trim(pathKey, "/"), "/")
		name := parts[len(parts)-1]
		if name == "" {
			continue
		}

		fields, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		// The "value" key holds the secret value.
		fval, exists := fields["value"]
		if !exists {
			continue
		}
		val := fmt.Sprintf("%v", fval)
		if val == "" {
			continue
		}
		entries = append(entries, secretEntry{Name: name, Value: val})
	}
	return entries, nil
}

// parseJSON reads a flat key-value JSON object.
//
//	{"DB_PASSWORD": "supersecret123", "API_KEY": "sk_live_abc123"}
func parseJSON(path string) ([]secretEntry, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	var entries []secretEntry
	for k, v := range raw {
		val := fmt.Sprintf("%v", v)
		if k == "" || val == "" {
			continue
		}
		entries = append(entries, secretEntry{Name: k, Value: val})
	}
	return entries, nil
}
