package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/migrate/internal/plan"
	"github.com/keyorixhq/keyorix/migrate/internal/report"
	"github.com/keyorixhq/keyorix/migrate/internal/target"
	"github.com/keyorixhq/keyorix/migrate/internal/vaultsource"
)

var (
	vaultServer        string
	vaultToken2        string // Keyorix token; named to avoid colliding with vaultToken (Vault's own token flag) below.
	vaultProjectID     int
	vaultEnvironmentID int
	vaultApply         bool
	vaultForce         bool
	vaultReportPath    string

	vaultAddr        string
	vaultToken       string
	vaultRoleID      string
	vaultSecretID    string
	vaultNamespace   string
	vaultMount       string
	vaultRootPath    string
	vaultAllVersions bool
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
Pass --apply to execute it.

Auth: --vault-token/$VAULT_TOKEN, or --vault-role-id/--vault-secret-id
(AppRole, or $VAULT_ROLE_ID/$VAULT_SECRET_ID). --vault-namespace/$VAULT_NAMESPACE
selects a Vault Enterprise / OpenBao namespace.`,
	SilenceUsage: true,
	RunE:         runVault,
}

func init() {
	vaultCmd.Flags().StringVar(&vaultServer, "server", "", "Keyorix server URL (or $KEYORIX_SERVER)")
	vaultCmd.Flags().StringVar(&vaultToken2, "token", "", "Keyorix Personal Access Token (or $KEYORIX_TOKEN)")
	vaultCmd.Flags().IntVar(&vaultProjectID, "project", 0, "target Keyorix project ID (required)")
	vaultCmd.Flags().IntVar(&vaultEnvironmentID, "environment", 0, "target Keyorix environment ID (required)")
	vaultCmd.Flags().BoolVar(&vaultApply, "apply", false, "execute the plan (default: dry run, print the plan only)")
	vaultCmd.Flags().BoolVar(&vaultForce, "force", false, "overwrite a conflicting secret this tool did not create (requires --apply)")
	vaultCmd.Flags().StringVar(&vaultReportPath, "report", "", "write the JSON per-item report to this path (optional)")

	vaultCmd.Flags().StringVar(&vaultAddr, "vault-addr", "", "Vault server address (or $VAULT_ADDR)")
	vaultCmd.Flags().StringVar(&vaultToken, "vault-token", "", "Vault token (or $VAULT_TOKEN)")
	vaultCmd.Flags().StringVar(&vaultRoleID, "vault-role-id", "", "Vault AppRole role-id (or $VAULT_ROLE_ID)")
	vaultCmd.Flags().StringVar(&vaultSecretID, "vault-secret-id", "", "Vault AppRole secret-id (or $VAULT_SECRET_ID)")
	vaultCmd.Flags().StringVar(&vaultNamespace, "vault-namespace", "", "Vault Enterprise / OpenBao namespace (or $VAULT_NAMESPACE)")
	vaultCmd.Flags().StringVar(&vaultMount, "vault-mount", "secret", "KV mount path")
	vaultCmd.Flags().StringVar(&vaultRootPath, "vault-path", "", "KV path to import, recursively (empty = the whole mount)")
	vaultCmd.Flags().BoolVar(&vaultAllVersions, "all-versions", false, "import every KV v2 version, not just the latest (not yet supported — see docs/design-keyorix-migrate.md)")

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

	vc, err := vaultsource.New(ctx, vaultsource.Config{
		Addr:      envDefault(vaultAddr, "VAULT_ADDR"),
		Namespace: envDefault(vaultNamespace, "VAULT_NAMESPACE"),
		Mount:     vaultMount,
		Token:     envDefault(vaultToken, "VAULT_TOKEN"),
		RoleID:    envDefault(vaultRoleID, "VAULT_ROLE_ID"),
		SecretID:  envDefault(vaultSecretID, "VAULT_SECRET_ID"),
	})
	if err != nil {
		return err
	}

	entries, err := vc.Walk(ctx, vaultRootPath, vaultAllVersions)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "no secrets found under the given Vault path")
		return nil
	}

	serverURL, token, err := resolveServerAndToken(vaultServer, vaultToken2)
	if err != nil {
		return err
	}
	apiClient, err := newAPIClient(serverURL, token)
	if err != nil {
		return err
	}
	tgt := target.New(apiClient, vaultProjectID, vaultEnvironmentID)

	planEntries := make([]plan.Entry, 0, len(entries))
	addr := envDefault(vaultAddr, "VAULT_ADDR")
	for _, e := range entries {
		name := sanitizeSecretName(e.Path)
		if e.Field != "" {
			name = sanitizeSecretName(e.Path + "-" + e.Field)
		}
		humanPath := "vault:" + vaultMount + "/" + e.Path
		if e.Field != "" {
			humanPath += "#" + e.Field
		}
		planEntries = append(planEntries, plan.Entry{
			SourceKind: "vault",
			Path:       humanPath,
			Name:       name,
			Value:      e.Value,
			Metadata:   e.Metadata,
			SourceID:   plan.SourceID(addr, vaultMount, e.Path, valueOr(e.Field, "value")),
		})
	}

	items, err := plan.BuildPlan(ctx, tgt, planEntries)
	if err != nil {
		return err
	}

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

	results := plan.Apply(ctx, tgt, items, vaultForce)
	for _, res := range results {
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
