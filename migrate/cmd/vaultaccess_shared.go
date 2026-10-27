package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/migrate/internal/accessplan"
	"github.com/keyorixhq/keyorix/migrate/internal/accesstarget"
	"github.com/keyorixhq/keyorix/migrate/internal/healthscan"
)

// buildFreshAccessPlan is the read-and-build pipeline shared by `vault plan-access` and `vault
// apply-access`: read every Vault policy/auth-method surface ADR-114 maps, read every Keyorix
// project/environment, build the plan, and reconcile it against live Keyorix state. apply-access
// calls this AGAIN immediately before executing (ADR-114: "re-derives and re-checks the plan
// immediately before executing each item... never trusting the file's snapshot") rather than
// trusting what a --plan file says — this function is what makes that re-derivation exact and
// not a second, drifting implementation.
func buildFreshAccessPlan(ctx context.Context, vc *healthscan.Client, reader *accesstarget.Client, k8sIssuer string, pathMapOverrides []string) (accessplan.Plan, []string, error) {
	in, mapper, unreadable, treeWarnings, err := readAccessInputs(ctx, vc, reader, pathMapOverrides)
	if err != nil {
		return accessplan.Plan{}, nil, err
	}
	warnings := append(unreadable, treeWarnings...)

	built := accessplan.Build(in, mapper, k8sIssuer)

	if err := accessplan.Reconcile(ctx, built.Items, reader); err != nil {
		return accessplan.Plan{}, nil, fmt.Errorf("reconcile against Keyorix: %w", err)
	}

	return built, warnings, nil
}

// readAccessInputs reads every Vault policy/auth-method surface ADR-114 maps and every Keyorix
// project/environment, and builds the PathMapper: the shared input of plan-access,
// apply-access and audit-access. unreadable names each Vault input Vault refused (treated as
// empty, so whatever it holds is missing from the result); treeWarnings names each KV listing
// Vault refused (the mapper then fails closed on the scopes it could hold, see listKVScopeTree).
func readAccessInputs(ctx context.Context, vc *healthscan.Client, reader *accesstarget.Client, pathMapOverrides []string) (in accessplan.BuildInput, mapper *accessplan.PathMapper, unreadable, treeWarnings []string, err error) {
	var warnings []string
	warn := func(what string) {
		warnings = append(warnings, "could not read "+what+" (permission denied) — treated as empty; see healthscan-policy.hcl for the policy stanza that would allow it")
	}

	kvMountsRaw, status, err := healthscan.ListKVMounts(ctx, vc)
	if err != nil {
		return accessplan.BuildInput{}, nil, nil, nil, fmt.Errorf("list KV mounts: %w", err)
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
		return accessplan.BuildInput{}, nil, nil, nil, fmt.Errorf("list policies: %w", err)
	}
	if status == healthscan.StatusForbidden {
		warn("sys/policies/acl")
	}
	for _, name := range unreadablePolicies {
		warn("policy " + name)
	}

	appRoles, unreadableApproles, _, status, err := healthscan.ListAppRoleRoleConfigs(ctx, vc)
	if err != nil {
		return accessplan.BuildInput{}, nil, nil, nil, fmt.Errorf("list AppRole roles: %w", err)
	}
	if status == healthscan.StatusForbidden {
		warn("sys/auth (AppRole roles)")
	}
	for _, name := range unreadableApproles {
		warn("AppRole role " + name)
	}

	k8sRoles, unreadableK8s, _, status, err := healthscan.ListKubernetesAuthRoleConfigs(ctx, vc)
	if err != nil {
		return accessplan.BuildInput{}, nil, nil, nil, fmt.Errorf("list Kubernetes auth roles: %w", err)
	}
	if status == healthscan.StatusForbidden {
		warn("sys/auth (Kubernetes auth roles)")
	}
	for _, name := range unreadableK8s {
		warn("Kubernetes auth role " + name)
	}

	userpassUsers, unreadableUserpass, _, status, err := healthscan.ListUserpassUsers(ctx, vc)
	if err != nil {
		return accessplan.BuildInput{}, nil, nil, nil, fmt.Errorf("list userpass users: %w", err)
	}
	if status == healthscan.StatusForbidden {
		warn("sys/auth (userpass users)")
	}
	for _, name := range unreadableUserpass {
		warn("userpass user " + name)
	}

	projectsRaw, err := reader.ListProjects(ctx)
	if err != nil {
		return accessplan.BuildInput{}, nil, nil, nil, fmt.Errorf("list Keyorix projects: %w", err)
	}
	projects := make([]accessplan.ProjectRef, 0, len(projectsRaw))
	environments := make(map[int][]accessplan.EnvironmentRef, len(projectsRaw))
	for _, p := range projectsRaw {
		projects = append(projects, p)
		envs, err := reader.ListEnvironments(ctx, p.ID)
		if err != nil {
			return accessplan.BuildInput{}, nil, nil, nil, fmt.Errorf("list environments for project %q: %w", p.Name, err)
		}
		environments[p.ID] = envs
	}

	mapper, err = accessplan.NewPathMapper(projects, environments, kvMounts, pathMapOverrides)
	if err != nil {
		return accessplan.BuildInput{}, nil, nil, nil, err
	}
	tree, treeWarnings, err := listKVScopeTree(ctx, vc, kvMountsRaw, projects)
	if err != nil {
		return accessplan.BuildInput{}, nil, nil, nil, err
	}
	mapper.SetKVTree(tree)

	return accessplan.BuildInput{
		Policies: policies, AppRoles: appRoles, KubernetesRoles: k8sRoles, UserpassUsers: userpassUsers,
	}, mapper, warnings, treeWarnings, nil
}

// listKVScopeTree lists, on every KV mount, the root and each root directory named like a
// Keyorix project: the two levels the default convention maps (<project>/<env>/). Names only,
// never values. A listing Vault refuses is recorded as not listed, and every default-convention
// stanza whose scope it could hold is then reported unmappable (cross-mount-scope) rather than
// assumed empty.
func listKVScopeTree(ctx context.Context, vc *healthscan.Client, mounts []healthscan.KVMount, projects []accessplan.ProjectRef) (map[string]accessplan.KVMountListing, []string, error) {
	isProject := make(map[string]bool, len(projects))
	for _, p := range projects {
		isProject[p.Name] = true
	}
	var warnings []string
	notListed := func(what string, status int) {
		warnings = append(warnings, fmt.Sprintf("could not list %s (HTTP %d) — default-convention policies whose project/environment it could hold are reported unmappable (cross-mount-scope); grant this token \"list\" there (KV v2: <mount>/metadata/*, KV v1: <mount>/*) to check it", what, status))
	}
	tree := make(map[string]accessplan.KVMountListing, len(mounts))
	for _, mount := range mounts {
		rootKeys, status, err := healthscan.ListKVKeys(ctx, vc, mount, "")
		if err != nil {
			return nil, nil, fmt.Errorf("list KV mount %s: %w", mount.Path, err)
		}
		if status != healthscan.StatusOK && status != healthscan.StatusNotFound {
			notListed("KV mount "+mount.Path, status)
			tree[mount.Path] = accessplan.KVMountListing{RootListed: false}
			continue
		}
		listing := accessplan.KVMountListing{RootListed: true, Projects: map[string]accessplan.KVProjectListing{}}
		for _, key := range rootKeys {
			name, isDir := strings.CutSuffix(key, "/")
			if !isProject[name] {
				continue
			}
			p, seen := listing.Projects[name]
			if !seen {
				p.Listed = true // a secret named <project> holds nothing under <project>/.
			}
			if isDir {
				envKeys, status, err := healthscan.ListKVKeys(ctx, vc, mount, key)
				if err != nil {
					return nil, nil, fmt.Errorf("list %s%s: %w", mount.Path, key, err)
				}
				if status != healthscan.StatusOK && status != healthscan.StatusNotFound {
					notListed(mount.Path+key, status)
					p.Listed = false
				} else {
					for _, k := range envKeys {
						p.Envs = append(p.Envs, strings.TrimSuffix(k, "/"))
					}
				}
			}
			listing.Projects[name] = p
		}
		tree[mount.Path] = listing
	}
	return tree, warnings, nil
}
