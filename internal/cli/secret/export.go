package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	exportFormat  string
	exportOutput  string
	exportEnv     string
	exportProject string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export secrets to a file or stdout",
	Long: `Export secrets from Keyorix to dotenv, JSON, or Vault YAML format.

Examples:
  keyorix secret export --env production --format dotenv
  keyorix secret export --env production --format json --output secrets.json
  keyorix secret export --env staging --format vault --output vault-export.yaml

Supported formats:
  dotenv  .env files (KEY=VALUE)
  json    Flat key-value JSON object
  vault   Medusa/Vault YAML (importable back via 'keyorix secret import --format vault')

Output goes to stdout unless --output is specified.
Warnings and summary are always printed to stderr.`,
	RunE: runExport,
}

func init() {
	exportCmd.Flags().StringVar(&exportFormat, "format", "dotenv", "Output format: dotenv, json, vault")
	exportCmd.Flags().StringVar(&exportOutput, "output", "", "Output file path (default: stdout)")
	exportCmd.Flags().StringVar(&exportEnv, "env", "development", "Environment name (e.g. production)")
	exportCmd.Flags().StringVar(&exportProject, "project", "default", "Project name")
}

// exportedSecret holds a secret's name and decrypted value.
type exportedSecret struct {
	ID    uint
	Name  string
	Value string
}

func runExport(cmd *cobra.Command, args []string) error {
	rc, ok := common.NewRemoteClient()
	if !ok {
		return fmt.Errorf("no remote server configured; set KEYORIX_SERVER and KEYORIX_TOKEN or run 'keyorix auth login'")
	}

	ctx := cmd.Context()

	nsID, err := resolveProjectID(ctx, rc, exportProject)
	if err != nil {
		return err
	}

	envID, err := resolveEnvironmentID(ctx, rc, exportEnv)
	if err != nil {
		return err
	}

	secrets, err := listSecretsForExport(ctx, rc, nsID, envID)
	if err != nil {
		return err
	}

	if len(secrets) == 0 {
		fmt.Fprintln(os.Stderr, "No secrets found.")
		return nil
	}

	fetched, err := fetchSecretValues(ctx, rc, secrets)
	if err != nil {
		return err
	}

	var out io.Writer = os.Stdout
	if exportOutput != "" {
		f, err := os.Create(exportOutput) // #nosec G304
		if err != nil {
			return fmt.Errorf("cannot create output file %q: %w", exportOutput, err)
		}
		defer f.Close()
		out = f
	}

	fmt.Fprintln(os.Stderr, "WARNING: exported secrets are in plaintext. Handle with care.")

	switch strings.ToLower(exportFormat) {
	case "dotenv", "env":
		err = writeDotenv(out, fetched)
	case "json":
		err = writeExportJSON(out, fetched)
	case "vault":
		err = writeVault(out, fetched, exportEnv)
	default:
		return fmt.Errorf("unknown format %q (supported: dotenv, json, vault)", exportFormat)
	}
	if err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Exported %d secrets\n", len(fetched))
	return nil
}

// ── Fetch helpers ─────────────────────────────────────────────────────────────

func listSecretsForExport(ctx context.Context, rc *common.RemoteClient, projectID, envID uint) ([]struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}, error) {
	path := fmt.Sprintf(
		"/api/v1/secrets?project_id=%d&environment_id=%d&page_size=1000&page=1",
		projectID, envID,
	)
	var body struct {
		Secrets []struct {
			ID   uint   `json:"id"`
			Name string `json:"name"`
		} `json:"secrets"`
	}
	if err := rc.Get(ctx, path, &body); err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	return body.Secrets, nil
}

func fetchSecretValues(ctx context.Context, rc *common.RemoteClient, list []struct {
	ID   uint   `json:"id"`
	Name string `json:"name"`
}) ([]exportedSecret, error) {
	result := make([]exportedSecret, 0, len(list))
	for _, s := range list {
		var body struct {
			Value string `json:"value"`
		}
		path := fmt.Sprintf("/api/v1/secrets/%d?include_value=true", s.ID)
		if err := rc.Get(ctx, path, &body); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: skipping %q (id=%d): %v\n", s.Name, s.ID, err)
			continue
		}
		result = append(result, exportedSecret{ID: s.ID, Name: s.Name, Value: body.Value})
	}
	return result, nil
}

// ── Format writers ────────────────────────────────────────────────────────────

func writeDotenv(w io.Writer, secrets []exportedSecret) error {
	fmt.Fprintf(w, "# Exported by Keyorix — %s\n", time.Now().Format("2006-01-02"))
	for _, s := range secrets {
		val := s.Value
		if strings.ContainsAny(val, " \t\n\"'=\\") {
			val = `"` + strings.ReplaceAll(strings.ReplaceAll(val, `\`, `\\`), `"`, `\"`) + `"`
		}
		fmt.Fprintf(w, "%s=%s\n", s.Name, val)
	}
	return nil
}

func writeExportJSON(w io.Writer, secrets []exportedSecret) error {
	m := make(map[string]string, len(secrets))
	for _, s := range secrets {
		m[s.Name] = s.Value
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

func writeVault(w io.Writer, secrets []exportedSecret, envName string) error {
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, s := range secrets {
		pathKey := fmt.Sprintf("secret/%s/%s", envName, s.Name)
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: pathKey},
			&yaml.Node{
				Kind: yaml.MappingNode,
				Tag:  "!!map",
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "value"},
					{Kind: yaml.ScalarNode, Value: s.Value},
				},
			},
		)
	}
	doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	defer enc.Close()
	return enc.Encode(doc)
}
