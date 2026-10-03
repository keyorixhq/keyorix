package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/migrate/internal/accessplan"
	"github.com/keyorixhq/keyorix/migrate/internal/accessreport"
	"github.com/keyorixhq/keyorix/migrate/internal/accesstarget"
	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

var (
	aaPlanPath       string
	aaCredentialsOut string
)

// applyAccessCmd is `keyorix-migrate vault apply-access` (ADR-114): executes a reviewed
// plan-access plan. Reuses plan-access's exact Vault/Keyorix connection flags (same global
// variables, see vaultplanaccess.go's init) — apply-access must be run with the SAME --vault-*/
// --server/--token/--k8s-issuer/--path-map flags the plan-access run that produced --plan used,
// since it re-derives the plan fresh rather than trusting the file.
var applyAccessCmd = &cobra.Command{
	Use:   "apply-access",
	Short: "Execute a reviewed Vault access-model migration plan (ADR-114)",
	Long: `Execute a plan produced by "vault plan-access --output <prefix>" (pass its .json file
as --plan). Re-derives and re-checks the plan fresh against live Vault and Keyorix immediately
before executing each item — never trusting the file's snapshot — and only ever executes an
item that is BOTH present in the reviewed file AND still resolves to "create" in the fresh
re-derivation. Idempotent and resumable: an item already migrated by a prior run resolves to
"skip" and is left untouched.

  keyorix-migrate vault apply-access --vault-addr https://vault.example.com:8200 \
    --server https://keyorix.example.com --token-file ./pat.txt \
    --k8s-issuer https://k8s.example.com \
    --plan access-plan.json --credentials-out ./migrated-credentials.txt

Every freshly issued machine-identity credential is appended to --credentials-out (created with
0600 permissions) exactly once, in the order created — never printed to stdout/stderr, never
written to any report. Nothing else this command creates is ever a secret, so everything else
is summarized on stdout.

Pass the SAME --vault-*, --server/--token, --k8s-issuer, and --path-map flags the plan-access
run that produced --plan used — apply-access does not read Vault/Keyorix connection settings
from the plan file.`,
	SilenceUsage: true,
	RunE:         runApplyAccess,
}

func init() {
	applyAccessCmd.Flags().StringVar(&paAddr, "vault-addr", "", "Vault server address (or $VAULT_ADDR)")
	applyAccessCmd.Flags().StringVar(&paToken, "vault-token", "", "Vault token (or $VAULT_TOKEN)")
	applyAccessCmd.Flags().StringVar(&paTokenFile, "vault-token-file", "", "read the Vault token from this file (\"-\" for stdin)")
	applyAccessCmd.Flags().StringVar(&paRoleID, "vault-role-id", "", "Vault AppRole role-id (or $VAULT_ROLE_ID)")
	applyAccessCmd.Flags().StringVar(&paSecretID, "vault-secret-id", "", "Vault AppRole secret-id (or $VAULT_SECRET_ID)")
	applyAccessCmd.Flags().StringVar(&paSecretIDFile, "vault-secret-id-file", "", "read the Vault AppRole secret-id from this file (\"-\" for stdin)")
	applyAccessCmd.Flags().StringVar(&paNamespace, "vault-namespace", "", "Vault Enterprise / OpenBao namespace (or $VAULT_NAMESPACE)")
	applyAccessCmd.Flags().StringVar(&paCACert, "vault-cacert", "", "PEM file for a private/internal Vault CA (or $VAULT_CACERT)")
	applyAccessCmd.Flags().StringVar(&paCAPath, "vault-capath", "", "directory of PEM files for a private/internal Vault CA (or $VAULT_CAPATH)")
	applyAccessCmd.Flags().BoolVar(&paTLSSkipVerify, "tls-skip-verify", false, "disable TLS certificate verification against Vault (insecure)")

	applyAccessCmd.Flags().StringVar(&paServer, "server", "", "Keyorix server URL (or $KEYORIX_SERVER)")
	applyAccessCmd.Flags().StringVar(&paKeyorixTok, "token", "", "Keyorix Personal Access Token (or $KEYORIX_TOKEN)")
	applyAccessCmd.Flags().StringVar(&paKeyorixTokFl, "token-file", "", "read the Keyorix token from this file (\"-\" for stdin)")

	applyAccessCmd.Flags().StringVar(&paK8sIssuer, "k8s-issuer", "", "the Kubernetes cluster's OIDC token issuer URL (must match the plan-access run that produced --plan)")
	applyAccessCmd.Flags().StringArrayVar(&paPathMap, "path-map", nil, "must match the plan-access run that produced --plan (repeatable)")

	applyAccessCmd.Flags().StringVar(&aaPlanPath, "plan", "", "the reviewed plan-access JSON report to execute (required)")
	applyAccessCmd.Flags().StringVar(&aaCredentialsOut, "credentials-out", "", "append freshly issued machine-identity credentials here, 0600 (required)")

	vaultCmd.AddCommand(applyAccessCmd)
}

func runApplyAccess(cmd *cobra.Command, _ []string) error {
	if aaPlanPath == "" {
		return fmt.Errorf("--plan is required (the .json report from a prior \"vault plan-access\" run)")
	}
	if aaCredentialsOut == "" {
		return fmt.Errorf("--credentials-out is required (freshly issued machine-identity credentials are written here, once, 0600)")
	}
	ctx := cmd.Context()

	planFile, err := os.Open(aaPlanPath) // #nosec G304 -- operator-supplied plan path, a CLI flag, not user/network input
	if err != nil {
		return fmt.Errorf("open --plan %q: %w", aaPlanPath, err)
	}
	reviewedPlan, err := accessreport.ReadJSON(planFile)
	_ = planFile.Close()
	if err != nil {
		return fmt.Errorf("read --plan %q: %w", aaPlanPath, err)
	}
	reviewed := map[string]bool{}
	for _, it := range reviewedPlan.Items {
		if it.Outcome == accessplan.Create {
			reviewed[accessplan.Key(it)] = true
		}
	}
	if len(reviewed) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no \"create\" items in --plan — nothing to do.")
		return nil
	}

	serverURL, err := resolveServer(paServer)
	if err != nil {
		return err
	}
	keyorixTok, err := resolveCredential(cmd, "token", paKeyorixTok, paKeyorixTokFl, "KEYORIX_TOKEN")
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
	writer := accesstarget.New(apiClient)

	vaultTok, err := resolveCredential(cmd, "vault-token", paToken, paTokenFile, "VAULT_TOKEN")
	if err != nil {
		return err
	}
	vaultSecretIDVal, err := resolveCredential(cmd, "vault-secret-id", paSecretID, paSecretIDFile, "VAULT_SECRET_ID")
	if err != nil {
		return err
	}
	vc, err := healthscan.New(ctx, healthscan.Config{
		Addr:          envDefault(paAddr, "VAULT_ADDR"),
		Namespace:     envDefault(paNamespace, "VAULT_NAMESPACE"),
		Token:         vaultTok,
		RoleID:        envDefault(paRoleID, "VAULT_ROLE_ID"),
		SecretID:      vaultSecretIDVal,
		CACertPath:    envDefault(paCACert, "VAULT_CACERT"),
		CACertDir:     envDefault(paCAPath, "VAULT_CAPATH"),
		TLSSkipVerify: paTLSSkipVerify,
	}, cmd.ErrOrStderr())
	if err != nil {
		return err
	}

	fresh, warnings, err := buildFreshAccessPlan(ctx, vc, writer, paK8sIssuer, paPathMap)
	if err != nil {
		return fmt.Errorf("re-derive the plan before applying: %w", err)
	}
	for _, w := range warnings {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "WARNING:", w)
	}

	// SelectForApply also passes the fresh plan's Skip-outcome roles/machine identities (never
	// written, only their ids read) so a resumed run can attach grants to parents an earlier,
	// interrupted run created.
	toExecute, selWarnings := accessplan.SelectForApply(fresh.Items, reviewed)
	for _, w := range selWarnings {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "WARNING:", w)
	toExecute := make([]accessplan.Item, 0, len(reviewed))
	seen := map[string]bool{}
	for _, it := range fresh.Items {
		key := accessplan.Key(it)
		if !reviewed[key] {
			continue // never execute something the operator did not review.
		}
		seen[key] = true
		if it.Outcome != accessplan.Create {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: %s %s no longer resolves to \"create\" (now %q) — not applied; re-run plan-access and review\n", it.Kind, it.SourceRef, it.Outcome)
			continue
		}
		toExecute = append(toExecute, it)
	}
	for key := range reviewed {
		if !seen[key] {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: reviewed item %q is no longer part of the live Vault/Keyorix state — not applied; re-run plan-access and review\n", key)
		}
	}

	credFile, err := os.OpenFile(aaCredentialsOut, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- operator-supplied output path, a CLI flag, not user/network input
	if err != nil {
		return fmt.Errorf("open --credentials-out %q: %w", aaCredentialsOut, err)
	}
	defer credFile.Close() //nolint:errcheck
	// O_CREATE's 0600 applies only to a NEW file. An existing file that group/others can read
	// would receive live machine credentials, so refuse it instead of appending.
	if st, err := credFile.Stat(); err != nil {
		return fmt.Errorf("stat --credentials-out %q: %w", aaCredentialsOut, err)
	} else if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("--credentials-out %q is readable or writable by group/others (mode %04o): chmod 600 it or pass a new path", aaCredentialsOut, st.Mode().Perm())
	}

	results := accessplan.Apply(ctx, toExecute, writer)
	var created, skipped, failed int
	for _, res := range results {
		switch {
		case res.Error != "":
			failed++
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "ERROR: %s %s: %s\n", res.Item.Kind, res.Item.SourceRef, res.Error)
		case res.Ran:
			created++
			if res.Credential != "" {
				if _, err := fmt.Fprintf(credFile, "%s\t%s\t%s\n", res.Item.ProposedName, res.Item.ProposedIdentityType, res.Credential); err != nil {
					return fmt.Errorf("write credential to --credentials-out: %w", err)
				}
			}
		default:
			skipped++
		}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%d created, %d skipped (already applied), %d failed\n", created, skipped, failed)
	if failed > 0 {
		return fmt.Errorf("%d item(s) failed to apply — see the errors above", failed)
	}
	return nil
}
