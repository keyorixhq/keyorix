package healthscan

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

func init() {
	RegisterCheck(Check{ID: "auth-methods", Title: "Auth methods", Fn: checkAuthMethods})
	RegisterCheck(Check{ID: "approle-secret-id-hygiene", Title: "AppRole secret_id hygiene", Fn: checkAppRoleSecretIDHygiene})
}

// maxAppRoleRolesInspected bounds how many roles checkAppRoleSecretIDHygiene reads per AppRole
// mount, so a scan against a Vault with thousands of roles still finishes in bounded time. A
// truncated scan says so in its evidence — CLAUDE.md's "no silent caps" — rather than quietly
// reporting a partial count as if it were complete.
const maxAppRoleRolesInspected = 200

// checkAuthMethods is SESSION-G2 item (f)'s inventory half: which auth methods are enabled,
// whether the mount set is only token+userpass (weaker than SSO/AppRole for anything beyond a
// handful of humans), and whether OIDC is present.
func checkAuthMethods(ctx context.Context, c *Client) Result {
	var auth struct {
		Data map[string]struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	status, err := getJSON(ctx, c, "sys/auth", &auth)
	if err != nil {
		return Result{Err: err}
	}
	if status == StatusForbidden {
		return denied("auth-methods", "sys/auth", `path "sys/auth" { capabilities = ["read"] }`)
	}
	if status != StatusOK {
		return Result{Err: fmt.Errorf("unexpected HTTP %d from sys/auth", status)}
	}

	types := map[string]bool{}
	mounts := make([]string, 0, len(auth.Data))
	for path, m := range auth.Data {
		types[m.Type] = true
		mounts = append(mounts, fmt.Sprintf("%s(%s)", path, m.Type))
	}
	sort.Strings(mounts)

	sev := SeverityInfo
	remediation := ""
	nonToken := map[string]bool{}
	for t := range types {
		if t != "token" {
			nonToken[t] = true
		}
	}
	if len(nonToken) == 1 && nonToken["userpass"] {
		sev = SeverityMedium
		remediation = "userpass-only auth has no MFA/SSO integration and no per-secret-id lifecycle. Add AppRole (for machines) and/or OIDC (for humans) alongside it."
	}
	if types["oidc"] {
		remediation += " OIDC is enabled — good, prefer it over userpass for human access."
	}

	return Result{Finding: &Finding{
		ID: "auth-methods", Title: "Auth methods", Severity: sev,
		Evidence:     fmt.Sprintf("%d auth methods: %v", len(mounts), mounts),
		WhyItMatters: "The auth methods enabled determine how both humans and machines authenticate, and userpass-only setups don't scale credential lifecycle safely.",
		Remediation:  strings.TrimSpace(remediation),
	}}
}

// checkAppRoleSecretIDHygiene is (f)'s AppRole-specific half: secret_id_ttl=0 (never expires)
// or secret_id_num_uses=0 (unlimited uses) on any role. Requires LISTing every AppRole mount's
// roles and GETing each role's config — real GET/LIST traffic proportional to role count,
// bounded by maxAppRoleRolesInspected.
func checkAppRoleSecretIDHygiene(ctx context.Context, c *Client) Result {
	var auth struct {
		Data map[string]struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	status, err := getJSON(ctx, c, "sys/auth", &auth)
	if err != nil {
		return Result{Err: err}
	}
	if status == StatusForbidden {
		return denied("approle-secret-id-hygiene", "sys/auth", `path "sys/auth" { capabilities = ["read"] }`)
	}

	var approleMounts []string
	for path, m := range auth.Data {
		if m.Type == "approle" {
			// sys/auth's keys are mount points relative to "auth/" (e.g. "approle/") — the
			// actual API path an auth method's own routes live under is "auth/<mount>/...".
			approleMounts = append(approleMounts, "auth/"+strings.TrimSuffix(path, "/"))
		}
	}
	sort.Strings(approleMounts)
	if len(approleMounts) == 0 {
		return Result{Finding: &Finding{
			ID: "approle-secret-id-hygiene", Title: "AppRole secret_id hygiene", Severity: SeverityInfo,
			Evidence: "no AppRole auth method enabled",
		}}
	}

	inspected, unlimitedTTL, unlimitedUses, truncated := 0, 0, 0, false
	for _, mount := range approleMounts {
		var roles struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		rStatus, err := listJSON(ctx, c, mount+"/role", &roles)
		if err != nil {
			return Result{Err: err}
		}
		if rStatus == StatusForbidden {
			return denied("approle-secret-id-hygiene", mount+"/role", fmt.Sprintf(`path "%s/role" { capabilities = ["list"] }`, mount))
		}
		for _, role := range roles.Data.Keys {
			if inspected >= maxAppRoleRolesInspected {
				truncated = true
				break
			}
			var roleCfg struct {
				Data struct {
					SecretIDTTL     int `json:"secret_id_ttl"`
					SecretIDNumUses int `json:"secret_id_num_uses"`
				} `json:"data"`
			}
			cStatus, err := getJSON(ctx, c, mount+"/role/"+role, &roleCfg)
			if err != nil {
				return Result{Err: err}
			}
			if cStatus == StatusForbidden {
				return denied("approle-secret-id-hygiene", mount+"/role/"+role, fmt.Sprintf(`path "%s/role/+" { capabilities = ["read"] }`, mount))
			}
			if cStatus != StatusOK {
				continue
			}
			inspected++
			if roleCfg.Data.SecretIDTTL == 0 {
				unlimitedTTL++
			}
			if roleCfg.Data.SecretIDNumUses == 0 {
				unlimitedUses++
			}
		}
	}

	sev := SeverityInfo
	remediation := ""
	if unlimitedTTL > 0 || unlimitedUses > 0 {
		sev = SeverityMedium
		remediation = "Set secret_id_ttl and secret_id_num_uses on every AppRole role — an unlimited-lifetime or unlimited-use secret_id never has to be rotated, defeating the point of AppRole over a static token."
	}
	evidence := fmt.Sprintf("%d roles inspected across %d AppRole mount(s): %d with secret_id_ttl=0 (never expires), %d with secret_id_num_uses=0 (unlimited uses)",
		inspected, len(approleMounts), unlimitedTTL, unlimitedUses)
	if truncated {
		evidence += fmt.Sprintf(" — truncated at %d roles; more roles exist and were not inspected", maxAppRoleRolesInspected)
	}

	return Result{Finding: &Finding{
		ID: "approle-secret-id-hygiene", Title: "AppRole secret_id hygiene", Severity: sev,
		Evidence: evidence, WhyItMatters: "An AppRole secret_id that never expires or has unlimited uses behaves like a long-lived static credential.",
		Remediation: remediation,
	}}
}
