package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/migrate/internal/accessplan"
	"github.com/keyorixhq/keyorix/migrate/internal/accesstarget"
	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

var aaJSON bool

// auditAccessCmd is `keyorix-migrate vault audit-access`: finds role grants that
// keyorix-migrate v0.96.0–v0.96.3's apply-access created wider than their source Vault policy
// (RD-SMT-SPIKE-1) and that still exist in Keyorix. Read-only on both sides.
var auditAccessCmd = &cobra.Command{
	Use:   "audit-access",
	Short: "List migrated Keyorix grants that are wider than their source Vault policy (read-only)",
	Long: `keyorix-migrate v0.96.0 to v0.96.3 could migrate a narrow Vault policy to a grant on a whole
Keyorix project/environment: a policy path narrower than the scope it resolved to (an exact
secret, a sub-folder, part of a --path-map prefix), or a stanza's "list" migrated as
secrets.read (list-only and KV v2 metadata/ stanzas, and write stanzas that also list, such
as ["create", "update", "list"]). This command re-reads Vault and Keyorix, works out which grants those
releases would have created that the current rules refuse, and lists the ones a migrated
machine identity still holds. It changes nothing in Vault or Keyorix.

Pass the SAME --vault-*, --server, --k8s-issuer and --path-map flags the original
apply-access run used: the grants it created depend on them. The --token must see every
Keyorix project (secrets.read at the global scope, not a project-restricted PAT): a
narrower token lists only some projects, and grants into the others cannot be audited.

  keyorix-migrate vault audit-access --vault-addr https://vault.example.com:8200 \
    --server https://keyorix.example.com --token-file ./pat.txt \
    --k8s-issuer https://k8s.example.com --path-map secret/data=2:6

Each finding names the machine identity, role, scope and Vault stanza, why the grant is wider,
and the API call that revokes exactly that grant. Exits 1 when it finds any, and also when the
audit is incomplete: a Vault input it needs (sys/mounts, the policy list, a policy, an auth
role) could not be read, or the Keyorix token cannot see every project, so some grants could
not be checked. Exits 0 only for a complete
audit with no findings. --json prints {"complete", "warnings", "findings"} on stdout instead.`,
	SilenceUsage: true,
	// main prints the returned error once; findings are an expected outcome, not a crash.
	SilenceErrors: true,
	RunE:          runAuditAccess,
}

func init() {
	f := auditAccessCmd.Flags()
	f.StringVar(&paAddr, "vault-addr", "", "Vault server address (or $VAULT_ADDR)")
	f.StringVar(&paToken, "vault-token", "", "Vault token (or $VAULT_TOKEN)")
	f.StringVar(&paTokenFile, "vault-token-file", "", "read the Vault token from this file (\"-\" for stdin)")
	f.StringVar(&paRoleID, "vault-role-id", "", "Vault AppRole role-id (or $VAULT_ROLE_ID)")
	f.StringVar(&paSecretID, "vault-secret-id", "", "Vault AppRole secret-id (or $VAULT_SECRET_ID)")
	f.StringVar(&paSecretIDFile, "vault-secret-id-file", "", "read the Vault AppRole secret-id from this file (\"-\" for stdin)")
	f.StringVar(&paNamespace, "vault-namespace", "", "Vault Enterprise / OpenBao namespace (or $VAULT_NAMESPACE)")
	f.StringVar(&paCACert, "vault-cacert", "", "PEM file for a private/internal Vault CA (or $VAULT_CACERT)")
	f.StringVar(&paCAPath, "vault-capath", "", "directory of PEM files for a private/internal Vault CA (or $VAULT_CAPATH)")
	f.BoolVar(&paTLSSkipVerify, "tls-skip-verify", false, "disable TLS certificate verification against Vault (insecure)")
	f.StringVar(&paServer, "server", "", "Keyorix server URL (or $KEYORIX_SERVER)")
	f.StringVar(&paKeyorixTok, "token", "", "Keyorix Personal Access Token (or $KEYORIX_TOKEN)")
	f.StringVar(&paKeyorixTokFl, "token-file", "", "read the Keyorix token from this file (\"-\" for stdin)")
	f.StringVar(&paK8sIssuer, "k8s-issuer", "", "the --k8s-issuer the original apply-access run used (Kubernetes identities are audited only with it)")
	f.StringArrayVar(&paPathMap, "path-map", nil, "the --path-map values the original apply-access run used (repeatable)")
	f.BoolVar(&aaJSON, "json", false, "print the findings as JSON on stdout")
	vaultCmd.AddCommand(auditAccessCmd)
}

// auditReport is audit-access's --json document. Complete is false when any input could not be
// read in full, including a Keyorix project list narrowed by the token's visibility (the
// warnings say which); a note such as unaudited Kubernetes roles is a warning that
// leaves it true.
type auditReport struct {
	Complete bool           `json:"complete"`
	Warnings []string       `json:"warnings"`
	Findings []auditFinding `json:"findings"`
}

// auditFinding is one widened grant checked against Keyorix, as printed by --json.
type auditFinding struct {
	Machine       string   `json:"machine_identity"`
	MachineID     int      `json:"machine_identity_id,omitempty"`
	ProjectID     int      `json:"project_id"`
	EnvironmentID int      `json:"environment_id"`
	Role          string   `json:"role"`
	RoleID        int      `json:"role_id,omitempty"`
	Permissions   []string `json:"permissions"`
	Source        string   `json:"vault_source"`
	Category      string   `json:"category"`
	Reason        string   `json:"reason"`
	// Status is "present" (the machine holds the role in the project), or "unconfirmed" when
	// the current rules also grant that role in the project at another environment (the API
	// lists roles without their environment, so the two cannot be told apart).
	Status string `json:"status"`
	Revoke string `json:"revoke"`
}

func runAuditAccess(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	stderr := cmd.ErrOrStderr()

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
	reader := accesstarget.New(apiClient)

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
	}, stderr)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(stderr, "audit-access: reading Vault policies/auth roles and Keyorix projects (read-only)...")
	in, mapper, unreadable, treeWarnings, err := readAccessInputs(ctx, vc, reader, paPathMap)
	if err != nil {
		return err
	}
	// The project listing holds only the projects this token may read. A legacy grant into a
	// project it cannot see resolves to nothing and would be dropped without a trace, so the
	// audit is complete only for a token that sees every project.
	seesAll, err := reader.SeesEveryProject(ctx)
	if err != nil {
		return err
	}
	// An unreadable input hides grants: the audit is incomplete. An unlistable KV path only
	// makes the stanzas it could affect findings (cross-mount-scope), so it is a warning.
	incomplete := len(unreadable)
	var warnings []string
	if !seesAll {
		incomplete++
		warnings = append(warnings, "the Keyorix token cannot see every project (GET /api/v1/projects?include_deleted=true answered 403: it lacks secrets.read at the global scope, or is a project-restricted PAT) — grants into the projects it cannot see cannot be audited; use an unrestricted admin token")
	}
	for _, w := range unreadable {
		warnings = append(warnings, w+" — grants from it cannot be audited")
	}
	warnings = append(warnings, treeWarnings...)
	for _, w := range warnings {
		_, _ = fmt.Fprintln(stderr, "WARNING:", w)
	}
	if paK8sIssuer == "" && len(in.KubernetesRoles) > 0 {
		w := fmt.Sprintf("%d Kubernetes auth role(s) not audited: v0.96.x created Kubernetes identities only with --k8s-issuer; if the original apply-access run used it, re-run with the same --k8s-issuer", len(in.KubernetesRoles))
		warnings = append(warnings, w)
		_, _ = fmt.Fprintln(stderr, "WARNING:", w)
	}
	candidates := accessplan.AuditWidenedGrants(in, mapper, paK8sIssuer)
	_, _ = fmt.Fprintf(stderr, "audit-access: %d grant(s) v0.96.x would have created wider than Vault; checking which exist in Keyorix...\n", len(candidates))

	var findings []auditFinding
	for _, c := range candidates {
		machineID, roleID, found, err := reader.MachineRoleGrant(ctx, c.ProjectID, c.MachineName, c.RoleName)
		if err != nil {
			return fmt.Errorf("check %s: %w", c.MachineName, err)
		}
		if !found {
			continue
		}
		status := "present"
		if c.AlsoGrantedByCurrentRules {
			status = "unconfirmed"
		}
		findings = append(findings, auditFinding{
			Machine: c.MachineName, MachineID: machineID, ProjectID: c.ProjectID, EnvironmentID: c.EnvironmentID,
			Role: c.RoleName, RoleID: roleID, Permissions: c.Permissions,
			Source: c.SourceRef, Category: string(c.Category), Reason: c.Reason, Status: status,
			Revoke: fmt.Sprintf("curl -X DELETE -H \"Authorization: Bearer $KEYORIX_TOKEN\" \"%s/api/v1/projects/%d/machine-identities/%d/roles/%d?environment_id=%d\"",
				strings.TrimSuffix(serverURL, "/"), c.ProjectID, machineID, roleID, c.EnvironmentID),
		})
	}

	out := cmd.OutOrStdout()
	if aaJSON {
		report := auditReport{Complete: incomplete == 0, Warnings: warnings, Findings: findings}
		if report.Warnings == nil {
			report.Warnings = []string{}
		}
		if report.Findings == nil {
			report.Findings = []auditFinding{}
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		for _, f := range findings {
			scope := fmt.Sprintf("environment %d", f.EnvironmentID)
			if f.EnvironmentID == 0 {
				scope = "all environments"
			}
			label := "WIDER THAN VAULT"
			if f.Status == "unconfirmed" {
				label = "POSSIBLY WIDER THAN VAULT (the same role is also granted correctly in this project; revoking a grant that does not exist is a harmless 404)"
			}
			_, _ = fmt.Fprintf(out, "%s: %s holds %s (%s) on project %d / %s\n  from %s [%s]: %s\n  revoke: %s\n",
				label, f.Machine, f.Role, strings.Join(f.Permissions, ", "), f.ProjectID, scope, f.Source, f.Category, f.Reason, f.Revoke)
		}
	}

	switch {
	case len(findings) == 0 && incomplete == 0:
		_, _ = fmt.Fprintln(stderr, "audit-access: done — no migrated grant is wider than its Vault policy.")
		return nil
	case len(findings) > 0:
		_, _ = fmt.Fprintf(stderr, "audit-access: done — %d migrated grant(s) wider than their Vault policy. Revoke each with the call shown, then re-run plan-access (it now reports these stanzas for review instead of widening them).\n", len(findings))
	}
	if incomplete > 0 {
		_, _ = fmt.Fprintf(stderr, "audit-access: INCOMPLETE — %d input(s) could not be read in full (see the warnings above), so grants from them were not checked. Give the Vault token the healthscan-policy.hcl stanzas, use a Keyorix token that sees every project, and re-run.\n", incomplete)
		return fmt.Errorf("audit incomplete: %d input(s) could not be read in full; %d migrated grant(s) found wider than their source Vault policy among the rest", incomplete, len(findings))
	}
	return fmt.Errorf("%d migrated grant(s) are wider than their source Vault policy", len(findings))
}
