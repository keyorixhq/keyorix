package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/migrate/internal/accessplan"
	"github.com/keyorixhq/keyorix/migrate/internal/accessreport"
	"github.com/keyorixhq/keyorix/migrate/internal/accesstarget"
	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

var (
	paAddr          string
	paToken         string
	paTokenFile     string
	paRoleID        string
	paSecretID      string
	paSecretIDFile  string
	paNamespace     string
	paCACert        string
	paCAPath        string
	paTLSSkipVerify bool

	paServer       string
	paKeyorixTok   string
	paKeyorixTokFl string

	paK8sIssuer string
	paPathMap   []string
	paOutput    string
)

// planAccessCmd is `keyorix-migrate vault plan-access` (ADR-114): a strictly read-only mapping
// of Vault's ACL policies and auth-method roles onto proposed Keyorix roles, grants, and
// machine identities. Like `vault scan`, it never writes to Vault; unlike `vault scan`, it also
// makes read-only calls against Keyorix (to classify create/skip/conflict and to resolve
// project/environment names) — but it writes nothing there either. `vault apply-access` (a
// separate command) executes a reviewed plan file; this command only ever produces one.
var planAccessCmd = &cobra.Command{
	Use:   "plan-access",
	Short: "Propose a Keyorix access-model migration plan from a Vault (or OpenBao) install (read-only)",
	Long: `Read Vault's ACL policies and AppRole/Kubernetes/userpass auth-method roles and propose
a Keyorix access-model migration: which roles, machine identities, grants, and OIDC bindings
would be created, and which Vault constructs have no safe automatic equivalent (sudo, deny
overlaps, Sentinel/templated policies, userpass credentials, direct tokens, wildcard Kubernetes
service-account bindings) and need human review instead. See docs/adr-114-vault-access-model-
migration.md for the full mapping rules.

  keyorix-migrate vault plan-access --vault-addr https://vault.example.com:8200 \
    --server https://keyorix.example.com --token-file ./pat.txt \
    --k8s-issuer https://k8s.example.com --output access-plan

Writes access-plan.json, access-plan.md, access-plan.html. Nothing is created in Vault or
Keyorix — review the report, then run "vault apply-access --plan access-plan.json".

Vault paths resolve to a Keyorix project/environment by name (first path segment after the KV
mount = project name, second = environment name — the same convention "vault" import's
mapping uses). --path-map <vault-prefix>=<projectID>:<environmentID> overrides this for a
prefix that doesn't follow it (repeatable, longest prefix wins).

--k8s-issuer is required to produce any Kubernetes auth role mapping: Vault's own Kubernetes
auth config has no OIDC-discoverable issuer URL to read (it stores a CA bundle and review-JWT
instead), so the operator must supply the cluster's actual token issuer. Every Kubernetes role
is reported unmappable without it.`,
	SilenceUsage: true,
	RunE:         runPlanAccess,
}

func init() {
	planAccessCmd.Flags().StringVar(&paAddr, "vault-addr", "", "Vault server address (or $VAULT_ADDR)")
	planAccessCmd.Flags().StringVar(&paToken, "vault-token", "", "Vault token (or $VAULT_TOKEN)")
	planAccessCmd.Flags().StringVar(&paTokenFile, "vault-token-file", "", "read the Vault token from this file (\"-\" for stdin)")
	planAccessCmd.Flags().StringVar(&paRoleID, "vault-role-id", "", "Vault AppRole role-id (or $VAULT_ROLE_ID)")
	planAccessCmd.Flags().StringVar(&paSecretID, "vault-secret-id", "", "Vault AppRole secret-id (or $VAULT_SECRET_ID)")
	planAccessCmd.Flags().StringVar(&paSecretIDFile, "vault-secret-id-file", "", "read the Vault AppRole secret-id from this file (\"-\" for stdin)")
	planAccessCmd.Flags().StringVar(&paNamespace, "vault-namespace", "", "Vault Enterprise / OpenBao namespace (or $VAULT_NAMESPACE)")
	planAccessCmd.Flags().StringVar(&paCACert, "vault-cacert", "", "PEM file for a private/internal Vault CA (or $VAULT_CACERT)")
	planAccessCmd.Flags().StringVar(&paCAPath, "vault-capath", "", "directory of PEM files for a private/internal Vault CA (or $VAULT_CAPATH)")
	planAccessCmd.Flags().BoolVar(&paTLSSkipVerify, "tls-skip-verify", false, "disable TLS certificate verification against Vault (insecure)")

	planAccessCmd.Flags().StringVar(&paServer, "server", "", "Keyorix server URL (or $KEYORIX_SERVER)")
	planAccessCmd.Flags().StringVar(&paKeyorixTok, "token", "", "Keyorix Personal Access Token (or $KEYORIX_TOKEN)")
	planAccessCmd.Flags().StringVar(&paKeyorixTokFl, "token-file", "", "read the Keyorix token from this file (\"-\" for stdin)")

	planAccessCmd.Flags().StringVar(&paK8sIssuer, "k8s-issuer", "", "the Kubernetes cluster's OIDC token issuer URL (required to map Kubernetes auth roles)")
	planAccessCmd.Flags().StringArrayVar(&paPathMap, "path-map", nil, "override the default project/environment resolution: \"<vault-prefix>=<projectID>:<environmentID>\" (repeatable)")
	planAccessCmd.Flags().StringVar(&paOutput, "output", "", "output path prefix — writes <prefix>.json, <prefix>.md, <prefix>.html (required)")

	vaultCmd.AddCommand(planAccessCmd)
}

func runPlanAccess(cmd *cobra.Command, _ []string) error {
	if paOutput == "" {
		return fmt.Errorf("--output is required (a path prefix — this command writes <prefix>.json, <prefix>.md, <prefix>.html)")
	}
	ctx := cmd.Context()

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
	}, cmd.ErrOrStderr())
	if err != nil {
		return err
	}

	var warnings []string
	warn := func(what string) {
		warnings = append(warnings, "could not read "+what+" (permission denied) — treated as empty; see healthscan-policy.hcl for the policy stanza that would allow it")
	}

	kvMountsRaw, status, err := healthscan.ListKVMounts(ctx, vc)
	if err != nil {
		return fmt.Errorf("list KV mounts: %w", err)
	}
	if status == healthscan.StatusForbidden {
		warn("sys/mounts")
	}
	kvMounts := make([]accessplan.KVMountInfo, 0, len(kvMountsRaw))
	for _, m := range kvMountsRaw {
		kvMounts = append(kvMounts, accessplan.KVMountInfo{Path: m.Path, KVVersion: m.KVVersion})
	}

	policies, unreadablePolicies, status, err := healthscan.ListPolicies(ctx, vc)
	if err != nil {
		return fmt.Errorf("list policies: %w", err)
	}
	if status == healthscan.StatusForbidden {
		warn("sys/policies/acl")
	}
	for _, name := range unreadablePolicies {
		warn("policy " + name)
	}

	appRoles, unreadableApproles, _, status, err := healthscan.ListAppRoleRoleConfigs(ctx, vc)
	if err != nil {
		return fmt.Errorf("list AppRole roles: %w", err)
	}
	if status == healthscan.StatusForbidden {
		warn("sys/auth (AppRole roles)")
	}
	for _, name := range unreadableApproles {
		warn("AppRole role " + name)
	}

	k8sRoles, unreadableK8s, _, status, err := healthscan.ListKubernetesAuthRoleConfigs(ctx, vc)
	if err != nil {
		return fmt.Errorf("list Kubernetes auth roles: %w", err)
	}
	if status == healthscan.StatusForbidden {
		warn("sys/auth (Kubernetes auth roles)")
	}
	for _, name := range unreadableK8s {
		warn("Kubernetes auth role " + name)
	}

	userpassUsers, unreadableUserpass, _, status, err := healthscan.ListUserpassUsers(ctx, vc)
	if err != nil {
		return fmt.Errorf("list userpass users: %w", err)
	}
	if status == healthscan.StatusForbidden {
		warn("sys/auth (userpass users)")
	}
	for _, name := range unreadableUserpass {
		warn("userpass user " + name)
	}

	projectsRaw, err := reader.ListProjects(ctx)
	if err != nil {
		return fmt.Errorf("list Keyorix projects: %w", err)
	}
	projects := make([]accessplan.ProjectRef, 0, len(projectsRaw))
	environments := make(map[int][]accessplan.EnvironmentRef, len(projectsRaw))
	for _, p := range projectsRaw {
		projects = append(projects, p)
		envs, err := reader.ListEnvironments(ctx, p.ID)
		if err != nil {
			return fmt.Errorf("list environments for project %q: %w", p.Name, err)
		}
		environments[p.ID] = envs
	}

	mapper, err := accessplan.NewPathMapper(projects, environments, kvMounts, paPathMap)
	if err != nil {
		return err
	}

	built := accessplan.Build(accessplan.BuildInput{
		Policies: policies, AppRoles: appRoles, KubernetesRoles: k8sRoles, UserpassUsers: userpassUsers,
	}, mapper, paK8sIssuer)

	if err := accessplan.Reconcile(ctx, built.Items, reader); err != nil {
		return fmt.Errorf("reconcile against Keyorix: %w", err)
	}

	for _, w := range warnings {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "WARNING:", w)
	}

	prefix := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(paOutput, ".json"), ".md"), ".html")
	addr := envDefault(paAddr, "VAULT_ADDR")
	if err := writeReportFile(prefix+".json", func(f *os.File) error { return accessreport.WriteJSON(f, built) }); err != nil {
		return err
	}
	if err := writeReportFile(prefix+".md", func(f *os.File) error { return accessreport.WriteMarkdown(f, built, addr) }); err != nil {
		return err
	}
	if err := writeReportFile(prefix+".html", func(f *os.File) error { return accessreport.WriteHTML(f, built, addr) }); err != nil {
		return err
	}

	var create, skip, conflict, unmappable int
	for _, it := range built.Items {
		switch it.Outcome {
		case accessplan.Create:
			create++
		case accessplan.Skip:
			skip++
		case accessplan.Conflict:
			conflict++
		case accessplan.Unmappable:
			unmappable++
		}
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%d to create, %d already migrated, %d conflicts, %d need human review — wrote %s.json, %s.md, %s.html\n",
		create, skip, conflict, unmappable, prefix, prefix, prefix)
	if conflict > 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Conflicts are never auto-resolved — review the report and rename one side before running apply-access.")
	}
	return nil
}
