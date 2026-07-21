package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const fmtEncryptedJSON = "encrypted-json"

var (
	exportFormat     string
	exportOutput     string
	exportEnv        string
	exportProject    string
	exportEncryptFor string
)

// createExportFile opens path for a fresh plaintext-secrets export. O_EXCL
// refuses to write through a pre-existing path — including a symlink an
// attacker (with write access to a shared directory, e.g. /tmp) planted at the
// target ahead of time, which os.Create's default O_TRUNC would silently
// follow, writing plaintext secrets to wherever the symlink points. O_NOFOLLOW
// is a second layer against a dangling symlink placed in the instant between
// the check and the open. 0600 keeps the export from being world/group-
// readable on disk (#114).
func createExportFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) // #nosec G304 -- operator-supplied CLI output path, not attacker input
}

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export secrets to a file or stdout",
	Long: `Export secrets from Keyorix to dotenv, JSON, Vault YAML, or encrypted-json format.

Examples:
  keyorix secret export --env production --format dotenv
  keyorix secret export --env production --format json --output secrets.json
  keyorix secret export --env staging --format vault --output vault-export.yaml
  keyorix secret export --env production --format encrypted-json --encrypt-for recipient.pub.pem --output secrets.enc.json
  keyorix secret export --env production --encrypt-for recipient.pub.pem --output secrets.enc.json

Supported formats:
  dotenv         .env files (KEY=VALUE)
  json           Flat key-value JSON object
  vault          Medusa/Vault YAML (importable back via 'keyorix secret import --format vault')
  encrypted-json RSA-OAEP-SHA256 + AES-256-GCM encrypted envelope (safe for airgap transfer)

The encrypted-json format wraps the standard JSON export in a hybrid encryption
envelope. Provide the recipient's RSA public key via --encrypt-for. Decrypt and
import with: keyorix secret import --file secrets.enc.json --decrypt-with private.pem

Output goes to stdout unless --output is specified.
Warnings and summary are always printed to stderr.`,
	RunE: runExport,
}

func init() {
	exportCmd.Flags().StringVar(&exportFormat, "format", "dotenv", "Output format: dotenv, json, vault, encrypted-json")
	exportCmd.Flags().StringVar(&exportOutput, "output", "", "Output file path (default: stdout)")
	exportCmd.Flags().StringVar(&exportEnv, "env", "development", "Environment name (e.g. production)")
	exportCmd.Flags().StringVar(&exportProject, "project", "default", "Project name")
	exportCmd.Flags().StringVar(&exportEncryptFor, "encrypt-for", "", "Path to RSA public key PEM (switches format to encrypted-json)")
}

// exportedSecret holds a secret's name and decrypted value.
type exportedSecret struct {
	ID    uint
	Name  string
	Value string
}

func runExport(cmd *cobra.Command, args []string) (retErr error) {
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

	// If --encrypt-for is set and format was not explicitly chosen as
	// encrypted-json, auto-switch and inform the operator.
	exportFormat = applyEncryptForDefault(exportFormat, exportEncryptFor)

	var out io.Writer = os.Stdout
	if exportOutput != "" {
		f, err := createExportFile(exportOutput)
		if err != nil {
			return fmt.Errorf("cannot create output file %q (it may already exist — remove it or choose a different path): %w", exportOutput, err)
		}
		defer func() {
			if cerr := f.Close(); cerr != nil && retErr == nil {
				retErr = fmt.Errorf("failed to close output file: %w", cerr)
			}
		}()
		out = f
	}

	if strings.ToLower(exportFormat) != fmtEncryptedJSON {
		fmt.Fprintln(os.Stderr, "WARNING: exported secrets are in plaintext. Handle with care.")
	}

	if err = writeSecrets(out, exportFormat, fetched, exportEncryptFor, exportEnv); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Exported %d secrets\n", len(fetched))
	return nil
}

// applyEncryptForDefault switches format to encrypted-json when --encrypt-for is
// set but the operator did not explicitly choose that format.
func applyEncryptForDefault(format, encryptFor string) string {
	if encryptFor != "" && strings.ToLower(format) != fmtEncryptedJSON {
		fmt.Fprintf(os.Stderr, "NOTE: --encrypt-for is set; switching format to encrypted-json.\n")
		return fmtEncryptedJSON
	}
	return format
}

// writeSecrets dispatches to the appropriate format writer.
func writeSecrets(out io.Writer, format string, fetched []exportedSecret, encryptFor, env string) error {
	switch strings.ToLower(format) {
	case "dotenv", "env":
		return writeDotenv(out, fetched)
	case "json":
		return writeExportJSON(out, fetched)
	case "vault":
		return writeVault(out, fetched, env)
	case fmtEncryptedJSON:
		if encryptFor == "" {
			return fmt.Errorf("--encrypt-for <pubkey.pem> is required for the encrypted-json format")
		}
		return writeEncryptedJSON(out, fetched, encryptFor)
	default:
		return fmt.Errorf("unknown format %q (supported: dotenv, json, vault, encrypted-json)", format)
	}
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

// writeDotenv emits KEY=VALUE lines. The VALUE is quote-escaped above, but a KEY
// containing an embedded newline (or carriage return) has no native escape in the
// dotenv format — emitting it raw (#384) would let a secret named e.g.
// "FOO\nINJECTED=evil" inject an extra, attacker-controlled KEY=VALUE line into an
// artifact downstream tooling (docker run --env-file, CI --env-file) treats as fully
// trusted. Refuse the export instead of silently producing an unsafe file.
func writeDotenv(w io.Writer, secrets []exportedSecret) error {
	for _, s := range secrets {
		if strings.ContainsAny(s.Name, "\r\n") {
			return fmt.Errorf("secret %q (id=%d) has a name containing a newline, which cannot be safely represented as a dotenv key — rename the secret before exporting to dotenv format", s.Name, s.ID)
		}
	}
	fmt.Fprintf(w, "# Exported by Keyorix — %s\n", time.Now().Format("2006-01-02")) //nolint:errcheck
	for _, s := range secrets {
		val := s.Value
		if strings.ContainsAny(val, " \t\n\"'=\\") {
			val = `"` + strings.ReplaceAll(strings.ReplaceAll(val, `\`, `\\`), `"`, `\"`) + `"`
		}
		fmt.Fprintf(w, "%s=%s\n", s.Name, val) //nolint:errcheck
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

// writeEncryptedJSON produces the RSA-OAEP + AES-256-GCM envelope JSON on w.
func writeEncryptedJSON(w io.Writer, secrets []exportedSecret, pubKeyPath string) error {
	// Reuse the existing JSON serialisation logic via a bytes buffer.
	var buf strings.Builder
	if err := writeExportJSON(&buf, secrets); err != nil {
		return err
	}
	envelope, err := encryptExport([]byte(buf.String()), pubKeyPath)
	if err != nil {
		return err
	}
	_, err = w.Write(envelope)
	return err
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
	defer enc.Close() //nolint:errcheck
	return enc.Encode(doc)
}
