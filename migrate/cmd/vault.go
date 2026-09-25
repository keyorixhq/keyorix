package cmd

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/migrate/internal/plan"
	"github.com/keyorixhq/keyorix/migrate/internal/report"
	"github.com/keyorixhq/keyorix/migrate/internal/target"
	"github.com/keyorixhq/keyorix/migrate/internal/vaultsource"
)

var (
	vaultServer        string
	keyorixToken       string
	keyorixTokenFile   string
	vaultProjectID     int
	vaultEnvironmentID int
	vaultApply         bool
	vaultForce         bool
	vaultReportPath    string

	vaultAddr         string
	vaultToken        string
	vaultTokenFile    string
	vaultRoleID       string
	vaultSecretID     string
	vaultSecretIDFile string
	vaultNamespace    string
	vaultMount        string
	vaultRootPath     string
	vaultAllVersions  bool
	vaultCACert       string
	vaultCAPath       string
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Import secrets from a HashiCorp Vault (or OpenBao) KV tree",
	Long: `Import secrets from a HashiCorp Vault (or OpenBao) KV v1/v2 tree into Keyorix.

  keyorix-migrate vault --vault-addr https://vault.example.com:8200 \
    --vault-mount secret --vault-path team-a \
    --server https://keyorix.example.com --project 7 --environment 3

Defaults to a dry run: prints the mapping plan (source path -> Keyorix secret
name, and create/update/skip/conflict for each) without writing anything.
Pass --apply to execute it. Before printing the plan (and again before
executing it), the Keyorix token is checked: valid, not revoked, not
expiring within the next hour, and scoped to write in the target
project/environment.

Vault auth: --vault-token/$VAULT_TOKEN, or --vault-role-id/--vault-secret-id
(AppRole, or $VAULT_ROLE_ID/$VAULT_SECRET_ID). --vault-namespace/$VAULT_NAMESPACE
selects a Vault Enterprise / OpenBao namespace. --vault-cacert/$VAULT_CACERT
(a PEM file) or --vault-capath/$VAULT_CAPATH (a directory of PEM files) trusts
a private/internal CA -- there is no option to skip TLS verification.

Credentials (--token, --vault-token, --vault-secret-id) can also be passed
via the sibling --*-file flag (a path, or "-" for stdin) instead of directly
on the command line, which is visible via ps/proc and shell history.`,
	SilenceUsage: true,
	RunE:         runVault,
}

func init() {
	vaultCmd.Flags().StringVar(&vaultServer, "server", "", "Keyorix server URL (or $KEYORIX_SERVER)")
	vaultCmd.Flags().StringVar(&keyorixToken, "token", "", "Keyorix Personal Access Token (or $KEYORIX_TOKEN)")
	vaultCmd.Flags().StringVar(&keyorixTokenFile, "token-file", "", "read the Keyorix token from this file (\"-\" for stdin)")
	vaultCmd.Flags().IntVar(&vaultProjectID, "project", 0, "target Keyorix project ID (required)")
	vaultCmd.Flags().IntVar(&vaultEnvironmentID, "environment", 0, "target Keyorix environment ID (required)")
	vaultCmd.Flags().BoolVar(&vaultApply, "apply", false, "execute the plan (default: dry run, print the plan only)")
	vaultCmd.Flags().BoolVar(&vaultForce, "force", false, "overwrite a conflicting secret this tool did not create (requires --apply)")
	vaultCmd.Flags().StringVar(&vaultReportPath, "report", "", "write the JSON per-item report to this path (optional)")

	vaultCmd.Flags().StringVar(&vaultAddr, "vault-addr", "", "Vault server address (or $VAULT_ADDR)")
	vaultCmd.Flags().StringVar(&vaultToken, "vault-token", "", "Vault token (or $VAULT_TOKEN)")
	vaultCmd.Flags().StringVar(&vaultTokenFile, "vault-token-file", "", "read the Vault token from this file (\"-\" for stdin)")
	vaultCmd.Flags().StringVar(&vaultRoleID, "vault-role-id", "", "Vault AppRole role-id (or $VAULT_ROLE_ID)")
	vaultCmd.Flags().StringVar(&vaultSecretID, "vault-secret-id", "", "Vault AppRole secret-id (or $VAULT_SECRET_ID)")
	vaultCmd.Flags().StringVar(&vaultSecretIDFile, "vault-secret-id-file", "", "read the Vault AppRole secret-id from this file (\"-\" for stdin)")
	vaultCmd.Flags().StringVar(&vaultNamespace, "vault-namespace", "", "Vault Enterprise / OpenBao namespace (or $VAULT_NAMESPACE)")
	vaultCmd.Flags().StringVar(&vaultMount, "vault-mount", "secret", "KV mount path")
	vaultCmd.Flags().StringVar(&vaultRootPath, "vault-path", "", "KV path to import, recursively (empty = the whole mount)")
	vaultCmd.Flags().BoolVar(&vaultAllVersions, "all-versions", false, "import every KV v2 version, not just the latest (not yet supported — see docs/design-keyorix-migrate.md)")
	vaultCmd.Flags().StringVar(&vaultCACert, "vault-cacert", "", "PEM file for a private/internal Vault CA (or $VAULT_CACERT)")
	vaultCmd.Flags().StringVar(&vaultCAPath, "vault-capath", "", "directory of PEM files for a private/internal Vault CA (or $VAULT_CAPATH)")

	rootCmd.AddCommand(vaultCmd)
}

func runVault(cmd *cobra.Command, _ []string) error {
	if vaultProjectID == 0 || vaultEnvironmentID == 0 {
		return fmt.Errorf("--project and --environment are both required")
	}
	if vaultForce && !vaultApply {
		return fmt.Errorf("--force requires --apply")
	}

	ctx := cmd.Context()

	serverURL, err := resolveServer(vaultServer)
	if err != nil {
		return err
	}
	keyorixTok, err := resolveCredential(cmd, "token", keyorixToken, keyorixTokenFile, "KEYORIX_TOKEN")
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
	tgt := target.New(apiClient, vaultProjectID, vaultEnvironmentID)

	// Preflight before any Vault traffic (docs/design-keyorix-migrate.md's "Pre-flight
	// check"): a bad Keyorix token fails here, not after walking a potentially large Vault
	// tree. Run for both dry-run and --apply.
	if err := tgt.Preflight(ctx, keyorixTok); err != nil {
		return err
	}

	vaultTok, err := resolveCredential(cmd, "vault-token", vaultToken, vaultTokenFile, "VAULT_TOKEN")
	if err != nil {
		return err
	}
	vaultSecretIDVal, err := resolveCredential(cmd, "vault-secret-id", vaultSecretID, vaultSecretIDFile, "VAULT_SECRET_ID")
	if err != nil {
		return err
	}

	vc, err := vaultsource.New(ctx, vaultsource.Config{
		Addr:       envDefault(vaultAddr, "VAULT_ADDR"),
		Namespace:  envDefault(vaultNamespace, "VAULT_NAMESPACE"),
		Mount:      vaultMount,
		Token:      vaultTok,
		RoleID:     envDefault(vaultRoleID, "VAULT_ROLE_ID"),
		SecretID:   vaultSecretIDVal,
		CACertPath: envDefault(vaultCACert, "VAULT_CACERT"),
		CACertDir:  envDefault(vaultCAPath, "VAULT_CAPATH"),
	})
	if err != nil {
		return err
	}

	entries, skipped, err := vc.Walk(ctx, vaultRootPath, vaultAllVersions)
	if err != nil {
		return err
	}
	if len(entries) == 0 && len(skipped) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "no secrets found under the given Vault path")
		return nil
	}

	addr := envDefault(vaultAddr, "VAULT_ADDR")
	skippedItems := make([]plan.Item, 0, len(skipped))
	for _, s := range skipped {
		skippedItems = append(skippedItems, plan.Item{
			Entry:   plan.Entry{SourceKind: "vault", Path: "vault:" + vaultMount + "/" + s.Path},
			Outcome: plan.Skip,
			Reason:  s.Reason,
		})
	}

	planEntries := make([]plan.Entry, 0, len(entries))
	for _, e := range entries {
		name := sanitizeSecretName(e.Path)
		if e.Field != "" {
			name = sanitizeSecretName(e.Path + "-" + e.Field)
		}
		humanPath := "vault:" + vaultMount + "/" + e.Path
		if e.Field != "" {
			humanPath += "#" + e.Field
		}
		version := ""
		if e.Version != 0 {
			version = strconv.Itoa(e.Version)
		}
		planEntries = append(planEntries, plan.Entry{
			SourceKind:      "vault",
			Path:            humanPath,
			Name:            name,
			Value:           e.Value,
			Metadata:        e.Metadata,
			SourceID:        plan.SourceID(addr, vaultMount, e.Path, valueOr(e.Field, "value")),
			SourceVersion:   version,
			SourceCreatedAt: e.CreatedAt,
		})
	}
	built, err := plan.BuildPlan(ctx, tgt, planEntries)
	if err != nil {
		return err
	}
	items := make([]plan.Item, 0, len(skippedItems)+len(built))
	items = append(items, skippedItems...)
	items = append(items, built...)

	var reportFile *os.File
	jsonOut := io.Discard
	if vaultReportPath != "" {
		reportFile, err = os.Create(vaultReportPath) // #nosec G304 -- operator-supplied output path, a CLI flag, not user/network input
		if err != nil {
			return fmt.Errorf("create report file: %w", err)
		}
		defer reportFile.Close() //nolint:errcheck
		jsonOut = reportFile
	}
	w := report.New(jsonOut, os.Stdout)

	if !vaultApply {
		for _, item := range items {
			if err := w.PlanLine(item); err != nil {
				return fmt.Errorf("write report: %w", err)
			}
		}
		printSummary(items)
		_, _ = fmt.Fprintln(os.Stdout, "\nDry run only — pass --apply to execute this plan.")
		return nil
	}

	// Re-check the token immediately before executing, not just at the top of the run — the
	// dry-run plan may have been shown seconds or minutes earlier (docs/design-keyorix-migrate.md's
	// "Pre-flight check": "run in dry-run and before --apply").
	if err := tgt.Preflight(ctx, keyorixTok); err != nil {
		return err
	}

	results := plan.Apply(ctx, tgt, built, vaultForce)
	allResults := make([]plan.Result, 0, len(skippedItems)+len(results))
	for _, item := range skippedItems {
		allResults = append(allResults, plan.Result{Item: item, Ran: false})
	}
	allResults = append(allResults, results...)
	for _, res := range allResults {
		if err := w.ResultLine(res); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	}
	printSummary(items)
	return nil
}

func printSummary(items []plan.Item) {
	counts := report.Summary(items)
	_, _ = fmt.Fprintf(os.Stdout, "\n%d create, %d update, %d skip, %d conflict, %d error\n",
		counts[plan.Create], counts[plan.Update], counts[plan.Skip], counts[plan.Conflict], counts[plan.Error])
}

func envDefault(flagVal, envVar string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv(envVar)
}

func valueOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
