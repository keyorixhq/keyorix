// access_read.go adds the exported, read-only Vault inspection calls ADR-114's
// `keyorix-migrate vault plan-access` needs: full policy bodies (parsed), auth-method mounts,
// and per-role configuration for AppRole, Kubernetes auth, and userpass. These extend this
// package's existing read-only inventory (checkPolicySprawl/checkAuthMethods/
// checkAppRoleSecretIDHygiene already enumerate the same Vault surface for scoring) rather than
// duplicating a second Vault-reading layer — docs/design-keyorix-migrate.md's "already reads
// policies/auth for scoring: extend, don't duplicate" (issue #2542). Every function here issues
// only the GET/LIST Client already enforces (see this package's own doc comment) — plan-access
// stays exactly as read-only against Vault as `vault scan` is.
//
// Known limitation, stated rather than silently accepted: these functions never enumerate
// directly-issued Vault tokens (`vault token create`) — ADR-114 excludes tokens by design (they
// are never migrated), and discovering arbitrary existing tokens needs `sys/auth/token/accessors`
// plus a per-accessor lookup, a materially larger and riskier read surface this package does not
// add for that reason.
package healthscan

import (
	"context"
	"sort"
)

// maxAuthRolesInspected bounds how many roles ListAppRoleRoleConfigs/ListKubernetesAuthRoleConfigs/
// ListUserpassUsers read per mount, matching maxAppRoleRolesInspected/maxPoliciesInspected's
// existing "no silent cap" precedent in this package: a truncated read says so via the returned
// truncated flag rather than quietly reporting a partial list as complete.
const maxAuthRolesInspected = 500

// KVMount is one enabled KV secrets engine mount: its path (as Vault reports it, trailing "/")
// and KV version (1 or 2) — ADR-114's `accessplan` package needs this to strip KV v2's
// "data/"/"metadata/" routing segment from a policy path before resolving project/environment,
// the same resolution vaultsource.resolveKVMountVersion already does for the value-import path.
type KVMount struct {
	Path      string
	KVVersion int
}

// ListKVMounts returns every enabled KV mount, reusing checkSecretsEnginesInventory's own
// listMounts rather than a second sys/mounts read.
func ListKVMounts(ctx context.Context, c *Client) ([]KVMount, int, error) {
	mounts, status, err := listMounts(ctx, c)
	if err != nil || status != StatusOK {
		return nil, status, err
	}
	out := make([]KVMount, 0, len(mounts))
	for path, m := range mounts {
		if m.Type != "kv" {
			continue
		}
		v := 1
		if m.Options.Version == "2" {
			v = 2
		}
		out = append(out, KVMount{Path: path, KVVersion: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, status, nil
}

// Policy is one Vault ACL policy: its name, raw HCL body, and the path/capability stanzas
// ParsePolicyHCL extracted from it.
type Policy struct {
	Name   string
	HCL    string
	Blocks []PolicyPathBlock
}

// ListPolicies lists every ACL policy and reads+parses each one. status is StatusForbidden if
// the LIST of policy names itself was denied (nothing was read); a policy that exists but
// couldn't be individually read (a narrower policy unreadable even though list is allowed) is
// returned in unreadable rather than silently omitted from policies.
func ListPolicies(ctx context.Context, c *Client) (policies []Policy, unreadable []string, status int, err error) {
	names, status, err := listPolicyNames(ctx, c)
	if err != nil || status != StatusOK {
		return nil, nil, status, err
	}
	sort.Strings(names)
	for _, name := range names {
		var pol struct {
			Data struct {
				Policy string `json:"policy"`
			} `json:"data"`
		}
		pStatus, err := getJSON(ctx, c, "sys/policies/acl/"+name, &pol)
		if err != nil {
			return nil, nil, status, err
		}
		if pStatus != StatusOK {
			unreadable = append(unreadable, name)
			continue
		}
		policies = append(policies, Policy{Name: name, HCL: pol.Data.Policy, Blocks: ParsePolicyHCL(pol.Data.Policy)})
	}
	return policies, unreadable, StatusOK, nil
}

// AuthMount is one entry from sys/auth: its mount path (as Vault reports it, trailing "/") and
// auth-method type ("approle", "userpass", "kubernetes", "token", ...).
type AuthMount struct {
	Path string
	Type string
}

// rawAuthMounts is the single GET sys/auth call every auth-method-aware check/read in this
// package needs — shared by checkAuthMethods, checkAppRoleSecretIDHygiene, and ListAuthMounts so
// the same traversal isn't re-issued three times with three slightly different decode shapes.
func rawAuthMounts(ctx context.Context, c *Client) (map[string]AuthMount, int, error) {
	var auth struct {
		Data map[string]struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	status, err := getJSON(ctx, c, "sys/auth", &auth)
	if err != nil {
		return nil, status, err
	}
	if status != StatusOK {
		return nil, status, nil
	}
	out := make(map[string]AuthMount, len(auth.Data))
	for path, m := range auth.Data {
		out[path] = AuthMount{Path: path, Type: m.Type}
	}
	return out, status, nil
}

// ListAuthMounts returns every enabled auth method.
func ListAuthMounts(ctx context.Context, c *Client) ([]AuthMount, int, error) {
	raw, status, err := rawAuthMounts(ctx, c)
	if err != nil || status != StatusOK {
		return nil, status, err
	}
	out := make([]AuthMount, 0, len(raw))
	for _, m := range raw {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, status, nil
}

// mountsOfType returns every enabled auth mount's "auth/<mount>" API path prefix (trailing "/"
// trimmed) for the given method type, sorted.
func mountsOfType(ctx context.Context, c *Client, methodType string) ([]string, int, error) {
	raw, status, err := rawAuthMounts(ctx, c)
	if err != nil || status != StatusOK {
		return nil, status, err
	}
	var out []string
	for path, m := range raw {
		if m.Type == methodType {
			out = append(out, "auth/"+trimSuffixSlash(path))
		}
	}
	sort.Strings(out)
	return out, status, nil
}

func trimSuffixSlash(s string) string {
	if len(s) > 0 && s[len(s)-1] == '/' {
		return s[:len(s)-1]
	}
	return s
}

// AppRoleRoleConfig is one AppRole role's configuration relevant to ADR-114's mapping: which
// token policies it grants, and the secret_id hygiene settings checkAppRoleSecretIDHygiene
// already scores. Mount is the "auth/<mount>" prefix the role was read from.
type AppRoleRoleConfig struct {
	Mount           string
	Name            string
	TokenPolicies   []string
	TokenTTL        int
	SecretIDTTL     int
	SecretIDNumUses int
}

// ListAppRoleRoleConfigs reads every role under every enabled AppRole mount. truncated is true
// when more roles exist than maxAuthRolesInspected and were not read.
func ListAppRoleRoleConfigs(ctx context.Context, c *Client) (configs []AppRoleRoleConfig, unreadable []string, truncated bool, status int, err error) {
	mounts, status, err := mountsOfType(ctx, c, "approle")
	if err != nil || status != StatusOK {
		return nil, nil, false, status, err
	}
	inspected := 0
	for _, mount := range mounts {
		var roles struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		rStatus, err := listJSON(ctx, c, mount+"/role", &roles)
		if err != nil {
			return nil, nil, false, status, err
		}
		if rStatus != StatusOK {
			continue
		}
		sort.Strings(roles.Data.Keys)
		for _, role := range roles.Data.Keys {
			if inspected >= maxAuthRolesInspected {
				truncated = true
				break
			}
			var roleCfg struct {
				Data struct {
					TokenPolicies   []string `json:"token_policies"`
					TokenTTL        int      `json:"token_ttl"`
					SecretIDTTL     int      `json:"secret_id_ttl"`
					SecretIDNumUses int      `json:"secret_id_num_uses"`
				} `json:"data"`
			}
			cStatus, err := getJSON(ctx, c, mount+"/role/"+role, &roleCfg)
			if err != nil {
				return nil, nil, false, status, err
			}
			if cStatus != StatusOK {
				unreadable = append(unreadable, mount+"/role/"+role)
				continue
			}
			inspected++
			configs = append(configs, AppRoleRoleConfig{
				Mount: mount, Name: role,
				TokenPolicies:   roleCfg.Data.TokenPolicies,
				TokenTTL:        roleCfg.Data.TokenTTL,
				SecretIDTTL:     roleCfg.Data.SecretIDTTL,
				SecretIDNumUses: roleCfg.Data.SecretIDNumUses,
			})
		}
	}
	return configs, unreadable, truncated, StatusOK, nil
}

// KubernetesAuthRoleConfig is one Kubernetes auth role's configuration: the service-account
// names/namespaces it's bound to, and the token policies it grants. Net new — this package had
// no Kubernetes-auth-method read path before ADR-114 (unlike AppRole/policies, there was no
// existing scoring check to extend).
type KubernetesAuthRoleConfig struct {
	Mount                         string
	Name                          string
	BoundServiceAccountNames      []string
	BoundServiceAccountNamespaces []string
	TokenPolicies                 []string
	TokenTTL                      int
}

// ListKubernetesAuthRoleConfigs reads every role under every enabled Kubernetes auth mount.
func ListKubernetesAuthRoleConfigs(ctx context.Context, c *Client) (configs []KubernetesAuthRoleConfig, unreadable []string, truncated bool, status int, err error) {
	mounts, status, err := mountsOfType(ctx, c, "kubernetes")
	if err != nil || status != StatusOK {
		return nil, nil, false, status, err
	}
	inspected := 0
	for _, mount := range mounts {
		var roles struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		rStatus, err := listJSON(ctx, c, mount+"/role", &roles)
		if err != nil {
			return nil, nil, false, status, err
		}
		if rStatus != StatusOK {
			continue
		}
		sort.Strings(roles.Data.Keys)
		for _, role := range roles.Data.Keys {
			if inspected >= maxAuthRolesInspected {
				truncated = true
				break
			}
			var roleCfg struct {
				Data struct {
					BoundServiceAccountNames      []string `json:"bound_service_account_names"`
					BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces"`
					TokenPolicies                 []string `json:"token_policies"`
					TokenTTL                      int      `json:"token_ttl"`
				} `json:"data"`
			}
			cStatus, err := getJSON(ctx, c, mount+"/role/"+role, &roleCfg)
			if err != nil {
				return nil, nil, false, status, err
			}
			if cStatus != StatusOK {
				unreadable = append(unreadable, mount+"/role/"+role)
				continue
			}
			inspected++
			configs = append(configs, KubernetesAuthRoleConfig{
				Mount: mount, Name: role,
				BoundServiceAccountNames:      roleCfg.Data.BoundServiceAccountNames,
				BoundServiceAccountNamespaces: roleCfg.Data.BoundServiceAccountNamespaces,
				TokenPolicies:                 roleCfg.Data.TokenPolicies,
				TokenTTL:                      roleCfg.Data.TokenTTL,
			})
		}
	}
	return configs, unreadable, truncated, StatusOK, nil
}

// UserpassUserConfig is one userpass user's attached token policies — read for the human-review
// report's recommendation only (ADR-114: userpass credentials are never migrated).
type UserpassUserConfig struct {
	Mount         string
	Username      string
	TokenPolicies []string
}

// ListUserpassUsers reads every username under every enabled userpass mount. Never reads or
// reports a password — userpass has no API to read one back (Vault only accepts a write), so
// there is nothing to accidentally expose here.
func ListUserpassUsers(ctx context.Context, c *Client) (configs []UserpassUserConfig, unreadable []string, truncated bool, status int, err error) {
	mounts, status, err := mountsOfType(ctx, c, "userpass")
	if err != nil || status != StatusOK {
		return nil, nil, false, status, err
	}
	inspected := 0
	for _, mount := range mounts {
		var users struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		rStatus, err := listJSON(ctx, c, mount+"/users", &users)
		if err != nil {
			return nil, nil, false, status, err
		}
		if rStatus != StatusOK {
			continue
		}
		sort.Strings(users.Data.Keys)
		for _, username := range users.Data.Keys {
			if inspected >= maxAuthRolesInspected {
				truncated = true
				break
			}
			var userCfg struct {
				Data struct {
					TokenPolicies []string `json:"token_policies"`
				} `json:"data"`
			}
			cStatus, err := getJSON(ctx, c, mount+"/users/"+username, &userCfg)
			if err != nil {
				return nil, nil, false, status, err
			}
			if cStatus != StatusOK {
				unreadable = append(unreadable, mount+"/users/"+username)
				continue
			}
			inspected++
			configs = append(configs, UserpassUserConfig{Mount: mount, Username: username, TokenPolicies: userCfg.Data.TokenPolicies})
		}
	}
	return configs, unreadable, truncated, StatusOK, nil
}
