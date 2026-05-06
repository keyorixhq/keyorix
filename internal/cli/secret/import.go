// import.go — Cobra command, runImport, doImport, and name resolution helpers.
//
// For format parsers (dotenv, vault, json) see import_parsers.go.
package secret

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	importCmd.Flags().StringVar(&importProject, "project", "default", "Project name")
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
	clean := filepath.Clean(importFile)
	if _, err := os.Stat(clean); err != nil {
		return fmt.Errorf("cannot open file %q: %w", importFile, err)
	}

	entries, err := parseFile(clean, importFormat)
	if err != nil {
		return fmt.Errorf("failed to parse %s file: %w", importFormat, err)
	}

	if len(entries) == 0 {
		fmt.Println("No secrets found in file.")
		return nil
	}

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

	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("no remote server configured; set KEYORIX_SERVER and KEYORIX_TOKEN or run 'keyorix auth login'")
	}

	ctx := cmd.Context()

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
