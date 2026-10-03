package healthscan

import (
	"context"
	"fmt"
	"sort"
)

// maxPoliciesInspected bounds how many individual policies checkWildcardSudoPolicies reads
// (sys/policies/acl/<name>) in one scan — see maxAppRoleRolesInspected's doc comment for the
// same "no silent cap" reasoning.
const maxPoliciesInspected = 500

func init() {
	RegisterCheck(Check{ID: "policy-sprawl", Title: "Policy count", Fn: checkPolicySprawl})
	RegisterCheck(Check{ID: "policy-wildcard-sudo", Title: "Wildcard/sudo policies", Fn: checkWildcardSudoPolicies})
}

// checkPolicySprawl is SESSION-G2 item (g)'s count/sprawl half.
func checkPolicySprawl(ctx context.Context, c *Client) Result {
	names, status, err := listPolicyNames(ctx, c)
	if err != nil {
		return Result{Err: err}
	}
	if status == StatusForbidden {
		return denied("policy-sprawl", "sys/policies/acl", `path "sys/policies/acl" { capabilities = ["list"] }`)
	}

	sev := SeverityInfo
	remediation := ""
	if len(names) > 50 {
		sev = SeverityLow
		remediation = "A large policy count is a maintainability signal, not a vulnerability by itself — periodically audit for policies attached to nothing."
	}
	return Result{Finding: &Finding{
		ID: "policy-sprawl", Title: "Policy count", Severity: sev,
		Evidence: fmt.Sprintf("%d ACL policies", len(names)), Remediation: remediation,
	}}
}

// checkWildcardSudoPolicies is (g)'s wildcard/sudo half: any policy granting sudo, or both
// create and update, on "*" or "sys/*" is a near-total-privilege grant.
func checkWildcardSudoPolicies(ctx context.Context, c *Client) Result {
	names, status, err := listPolicyNames(ctx, c)
	if err != nil {
		return Result{Err: err}
	}
	if status == StatusForbidden {
		return denied("policy-wildcard-sudo", "sys/policies/acl", `path "sys/policies/acl" { capabilities = ["list"] }`)
	}
	sort.Strings(names)

	var offenders []string
	inspected, truncated := 0, false
	for _, name := range names {
		if inspected >= maxPoliciesInspected {
			truncated = true
			break
		}
		var pol struct {
			Data struct {
				Policy string `json:"policy"`
			} `json:"data"`
		}
		pStatus, err := getJSON(ctx, c, "sys/policies/acl/"+name, &pol)
		if err != nil {
			return Result{Err: err}
		}
		if pStatus == StatusForbidden {
			return denied("policy-wildcard-sudo", "sys/policies/acl/"+name, `path "sys/policies/acl/+" { capabilities = ["read"] }`)
		}
		if pStatus != StatusOK {
			continue
		}
		inspected++
		for _, b := range ParsePolicyHCL(pol.Data.Policy) {
			if isWildcardSudoGrant(b) {
				offenders = append(offenders, fmt.Sprintf("%s (path %q)", name, b.Path))
				break
			}
		}
	}

	sev := SeverityInfo
	remediation := ""
	if len(offenders) > 0 {
		sev = SeverityHigh
		remediation = "Scope these policies to specific paths instead of \"*\"/\"sys/*\" with sudo or create+update — each is close to full admin."
	}
	evidence := fmt.Sprintf("%d/%d policies inspected; wildcard/sudo grants: %v", inspected, len(names), offenders)
	if truncated {
		evidence += fmt.Sprintf(" — truncated at %d policies; more exist and were not inspected", maxPoliciesInspected)
	}

	return Result{Finding: &Finding{
		ID: "policy-wildcard-sudo", Title: "Wildcard/sudo policies", Severity: sev,
		Evidence: evidence, WhyItMatters: "A policy with sudo or create+update on \"*\" or \"sys/*\" grants near-total control over this Vault to anyone it's attached to.",
		Remediation: remediation,
	}}
}

func listPolicyNames(ctx context.Context, c *Client) ([]string, int, error) {
	var policies struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	status, err := listJSON(ctx, c, "sys/policies/acl", &policies)
	if err != nil {
		return nil, status, err
	}
	if status != StatusOK && status != StatusForbidden {
		return nil, status, fmt.Errorf("unexpected HTTP %d from sys/policies/acl", status)
	}
	return policies.Data.Keys, status, nil
}
