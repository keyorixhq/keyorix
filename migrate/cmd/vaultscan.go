package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
	"github.com/keyorixhq/keyorix/migrate/internal/migrateversion"
)

var (
	scanAddr          string
	scanToken         string
	scanTokenFile     string
	scanRoleID        string
	scanSecretID      string
	scanSecretIDFile  string
	scanNamespace     string
	scanCACert        string
	scanCAPath        string
	scanTLSSkipVerify bool
	scanOutput        string
)

// scanCmd is `keyorix-migrate vault scan`: a strictly read-only inspection of a Vault (or
// OpenBao) install, safe to run against production. Deliberately a separate command from
// `keyorix-migrate vault` (which imports secrets into Keyorix) — scan never touches Keyorix at
// all, has no --project/--environment/--apply, and needs no Keyorix token.
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a read-only health scan against a Vault (or OpenBao) install",
	Long: `Run a read-only health scan against a Vault (or OpenBao) install and write a report.

  keyorix-migrate vault scan --addr https://vault.example.com:8200 --output report

Writes report.md, report.json, and report.html (Markdown, machine-readable JSON, and a
single-file HTML report — inline CSS, no external assets). Exit code is 0 unless the tool itself
failed to run (a bad flag, no Vault address, auth failure) — an individual check being denied by
policy is reported as "not checked," never a run failure.

This command issues Vault HTTP requests using GET and LIST only — see docs/vault-health-scan.md
for the read-only guarantee and how it's enforced. It never reads KV *data* (secret values),
only metadata. See healthscan-policy.hcl for the minimal read-only policy to attach to the token
or AppRole this command runs with.

Auth: --token/$VAULT_TOKEN, or --role-id/--secret-id (AppRole, or $VAULT_ROLE_ID/$VAULT_SECRET_ID).
--namespace/$VAULT_NAMESPACE selects a Vault Enterprise / OpenBao namespace. --cacert/$VAULT_CACERT
(a PEM file) or --capath/$VAULT_CAPATH (a directory of PEM files) trusts a private/internal CA.
--tls-skip-verify disables TLS certificate verification entirely — refused unless passed
explicitly, and always prints a loud warning when used.`,
	SilenceUsage: true,
	RunE:         runVaultScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanAddr, "addr", "", "Vault server address (or $VAULT_ADDR)")
	scanCmd.Flags().StringVar(&scanToken, "token", "", "Vault token (or $VAULT_TOKEN)")
	scanCmd.Flags().StringVar(&scanTokenFile, "token-file", "", "read the Vault token from this file (\"-\" for stdin)")
	scanCmd.Flags().StringVar(&scanRoleID, "role-id", "", "Vault AppRole role-id (or $VAULT_ROLE_ID)")
	scanCmd.Flags().StringVar(&scanSecretID, "secret-id", "", "Vault AppRole secret-id (or $VAULT_SECRET_ID)")
	scanCmd.Flags().StringVar(&scanSecretIDFile, "secret-id-file", "", "read the Vault AppRole secret-id from this file (\"-\" for stdin)")
	scanCmd.Flags().StringVar(&scanNamespace, "namespace", "", "Vault Enterprise / OpenBao namespace (or $VAULT_NAMESPACE)")
	scanCmd.Flags().StringVar(&scanCACert, "cacert", "", "PEM file for a private/internal Vault CA (or $VAULT_CACERT)")
	scanCmd.Flags().StringVar(&scanCAPath, "capath", "", "directory of PEM files for a private/internal Vault CA (or $VAULT_CAPATH)")
	scanCmd.Flags().BoolVar(&scanTLSSkipVerify, "tls-skip-verify", false, "disable TLS certificate verification (insecure — see the command's help text)")
	scanCmd.Flags().StringVar(&scanOutput, "output", "", "output path prefix — writes <prefix>.md, <prefix>.json, <prefix>.html (required)")

	vaultCmd.AddCommand(scanCmd)
}

func runVaultScan(cmd *cobra.Command, _ []string) error {
	if scanOutput == "" {
		return fmt.Errorf("--output is required (a path prefix — this command writes <prefix>.md, <prefix>.json, <prefix>.html)")
	}

	ctx := cmd.Context()

	token, err := resolveCredential(cmd, "token", scanToken, scanTokenFile, "VAULT_TOKEN")
	if err != nil {
		return err
	}
	secretID, err := resolveCredential(cmd, "secret-id", scanSecretID, scanSecretIDFile, "VAULT_SECRET_ID")
	if err != nil {
		return err
	}

	c, err := healthscan.New(ctx, healthscan.Config{
		Addr:          envDefault(scanAddr, "VAULT_ADDR"),
		Namespace:     envDefault(scanNamespace, "VAULT_NAMESPACE"),
		Token:         token,
		RoleID:        envDefault(scanRoleID, "VAULT_ROLE_ID"),
		SecretID:      secretID,
		CACertPath:    envDefault(scanCACert, "VAULT_CACERT"),
		CACertDir:     envDefault(scanCAPath, "VAULT_CAPATH"),
		TLSSkipVerify: scanTLSSkipVerify,
	}, cmd.ErrOrStderr())
	if err != nil {
		return err
	}

	addr := envDefault(scanAddr, "VAULT_ADDR")
	report := healthscan.Run(ctx, c, addr, "keyorix-migrate "+migrateversion.Version)

	prefix := strings.TrimSuffix(scanOutput, ".md")
	prefix = strings.TrimSuffix(prefix, ".json")
	prefix = strings.TrimSuffix(prefix, ".html")

	if err := writeReportFile(prefix+".json", func(f *os.File) error { return healthscan.WriteJSON(f, report) }); err != nil {
		return err
	}
	if err := writeReportFile(prefix+".md", func(f *os.File) error { return healthscan.WriteMarkdown(f, report) }); err != nil {
		return err
	}
	if err := writeReportFile(prefix+".html", func(f *os.File) error { return healthscan.WriteHTML(f, report) }); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%d findings, %d not checked — wrote %s.md, %s.json, %s.html\n",
		len(report.Findings), len(report.NotChecked), prefix, prefix, prefix)
	return nil
}

func writeReportFile(path string, write func(*os.File) error) error {
	f, err := os.Create(path) // #nosec G304 -- operator-supplied output path, a CLI flag, not user/network input
	if err != nil {
		return fmt.Errorf("create %q: %w", path, err)
	}
	defer f.Close() //nolint:errcheck
	if err := write(f); err != nil {
		return fmt.Errorf("write %q: %w", path, err)
	}
	return nil
}
