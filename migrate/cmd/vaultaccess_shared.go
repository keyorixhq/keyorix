package cmd

import (
	"context"
	"fmt"

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
	var warnings []string
	warn := func(what string) {
		warnings = append(warnings, "could not read "+what+" (permission denied) — treated as empty; see healthscan-policy.hcl for the policy stanza that would allow it")
	}

	kvMountsRaw, status, err := healthscan.ListKVMounts(ctx, vc)
	if err != nil {
		return accessplan.Plan{}, nil, fmt.Errorf("list KV mounts: %w", err)
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
		return accessplan.Plan{}, nil, fmt.Errorf("list policies: %w", err)
	}
	if status == healthscan.StatusForbidden {
		warn("sys/policies/acl")
	}
	for _, name := range unreadablePolicies {
		warn("policy " + name)
	}

	appRoles, unreadableApproles, _, status, err := healthscan.ListAppRoleRoleConfigs(ctx, vc)
	if err != nil {
		return accessplan.Plan{}, nil, fmt.Errorf("list AppRole roles: %w", err)
	}
	if status == healthscan.StatusForbidden {
		warn("sys/auth (AppRole roles)")
	}
	for _, name := range unreadableApproles {
		warn("AppRole role " + name)
	}

	k8sRoles, unreadableK8s, _, status, err := healthscan.ListKubernetesAuthRoleConfigs(ctx, vc)
	if err != nil {
		return accessplan.Plan{}, nil, fmt.Errorf("list Kubernetes auth roles: %w", err)
	}
	if status == healthscan.StatusForbidden {
		warn("sys/auth (Kubernetes auth roles)")
	}
	for _, name := range unreadableK8s {
		warn("Kubernetes auth role " + name)
	}

	userpassUsers, unreadableUserpass, _, status, err := healthscan.ListUserpassUsers(ctx, vc)
	if err != nil {
		return accessplan.Plan{}, nil, fmt.Errorf("list userpass users: %w", err)
	}
	if status == healthscan.StatusForbidden {
		warn("sys/auth (userpass users)")
	}
	for _, name := range unreadableUserpass {
		warn("userpass user " + name)
	}

	projectsRaw, err := reader.ListProjects(ctx)
	if err != nil {
		return accessplan.Plan{}, nil, fmt.Errorf("list Keyorix projects: %w", err)
	}
	projects := make([]accessplan.ProjectRef, 0, len(projectsRaw))
	environments := make(map[int][]accessplan.EnvironmentRef, len(projectsRaw))
	for _, p := range projectsRaw {
		projects = append(projects, p)
		envs, err := reader.ListEnvironments(ctx, p.ID)
		if err != nil {
			return accessplan.Plan{}, nil, fmt.Errorf("list environments for project %q: %w", p.Name, err)
		}
		environments[p.ID] = envs
	}

	mapper, err := accessplan.NewPathMapper(projects, environments, kvMounts, pathMapOverrides)
	if err != nil {
		return accessplan.Plan{}, nil, err
	}

	built := accessplan.Build(accessplan.BuildInput{
		Policies: policies, AppRoles: appRoles, KubernetesRoles: k8sRoles, UserpassUsers: userpassUsers,
	}, mapper, k8sIssuer)

	if err := accessplan.Reconcile(ctx, built.Items, reader); err != nil {
		return accessplan.Plan{}, nil, fmt.Errorf("reconcile against Keyorix: %w", err)
	}

	return built, warnings, nil
}
