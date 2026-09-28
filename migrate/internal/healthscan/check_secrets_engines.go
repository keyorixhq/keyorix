package healthscan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// maxKVLeavesInspected bounds the total number of KV v2 leaves checkSecretStaleness reads
// metadata for, summed across every KV v2 mount — see maxAppRoleRolesInspected's doc comment.
const maxKVLeavesInspected = 5000

// staleAfter is SESSION-G2 item (i)'s own threshold: a KV v2 secret whose latest version's
// updated_time is older than this is flagged.
const staleAfter = 365 * 24 * time.Hour

// nonDynamicMountTypes are secrets engine types this scan does NOT count as "dynamic" for (i)'s
// inventory — a deliberately short, documented allowlist rather than an exhaustive denylist of
// every dynamic engine type Vault ships (database, aws, azure, gcp, pki, ssh, transit, nomad,
// consul, rabbitmq, and any plugin — an enumeration of THOSE would need updating every time
// Vault ships a new one; treating "not one of these three" as dynamic doesn't).
var nonDynamicMountTypes = map[string]bool{"kv": true, "cubbyhole": true, "system": true, "identity": true}

func init() {
	RegisterCheck(Check{ID: "secrets-engines-inventory", Title: "Secrets engines inventory", Fn: checkSecretsEnginesInventory})
	RegisterCheck(Check{ID: "kv-v2-config", Title: "KV v2 configuration", Fn: checkKVv2Config})
	RegisterCheck(Check{ID: "secret-staleness", Title: "Stale secrets (>365 days)", Fn: checkSecretStaleness})
}

type mountInfo struct {
	Type    string `json:"type"`
	Options struct {
		Version string `json:"version"`
	} `json:"options"`
}

func listMounts(ctx context.Context, c *Client) (map[string]mountInfo, int, error) {
	var mounts struct {
		Data map[string]mountInfo `json:"data"`
	}
	status, err := getJSON(ctx, c, "sys/mounts", &mounts)
	return mounts.Data, status, err
}

// checkSecretsEnginesInventory is (i)'s inventory half: which engines are enabled, KV v1 vs v2
// counts, and which mounts look like dynamic secrets engines.
func checkSecretsEnginesInventory(ctx context.Context, c *Client) Result {
	mounts, status, err := listMounts(ctx, c)
	if err != nil {
		return Result{Err: err}
	}
	if status == StatusForbidden {
		return denied("secrets-engines-inventory", "sys/mounts", `path "sys/mounts" { capabilities = ["read"] }`)
	}

	kvV1, kvV2 := 0, 0
	var dynamic []string
	paths := sortedKeys(mounts)
	for _, path := range paths {
		m := mounts[path]
		if m.Type == "kv" {
			if m.Options.Version == "2" {
				kvV2++
			} else {
				kvV1++
			}
			continue
		}
		if !nonDynamicMountTypes[m.Type] {
			dynamic = append(dynamic, fmt.Sprintf("%s(%s)", path, m.Type))
		}
	}

	return Result{Finding: &Finding{
		ID: "secrets-engines-inventory", Title: "Secrets engines inventory", Severity: SeverityInfo,
		Evidence: fmt.Sprintf("%d mounts total; KV v1: %d, KV v2: %d; likely dynamic-secrets mounts: %v", len(mounts), kvV1, kvV2, dynamic),
	}}
}

// checkKVv2Config is (i)'s max_versions/cas half.
func checkKVv2Config(ctx context.Context, c *Client) Result {
	mounts, status, err := listMounts(ctx, c)
	if err != nil {
		return Result{Err: err}
	}
	if status == StatusForbidden {
		return denied("kv-v2-config", "sys/mounts", `path "sys/mounts" { capabilities = ["read"] }`)
	}

	var noCAS []string
	var configs []string
	for _, path := range sortedKeys(mounts) {
		m := mounts[path]
		if m.Type != "kv" || m.Options.Version != "2" {
			continue
		}
		var cfg struct {
			Data struct {
				MaxVersions int  `json:"max_versions"`
				CASRequired bool `json:"cas_required"`
			} `json:"data"`
		}
		cStatus, err := getJSON(ctx, c, path+"config", &cfg)
		if err != nil {
			return Result{Err: err}
		}
		if cStatus == StatusForbidden {
			return denied("kv-v2-config", path+"config", fmt.Sprintf(`path "%sconfig" { capabilities = ["read"] }`, path))
		}
		if cStatus != StatusOK {
			continue
		}
		configs = append(configs, fmt.Sprintf("%s: max_versions=%d cas_required=%t", path, cfg.Data.MaxVersions, cfg.Data.CASRequired))
		if !cfg.Data.CASRequired {
			noCAS = append(noCAS, path)
		}
	}

	sev := SeverityInfo
	remediation := ""
	if len(noCAS) > 0 {
		sev = SeverityLow
		remediation = "Consider cas_required=true on KV v2 mounts where concurrent writers are possible, so a stale write can't silently clobber a newer one."
	}
	return Result{Finding: &Finding{
		ID: "kv-v2-config", Title: "KV v2 configuration", Severity: sev,
		Evidence: fmt.Sprintf("%v", configs), Remediation: remediation,
	}}
}

// checkSecretStaleness is (i)'s staleness half. Walks ONLY <mount>/metadata/<path> — never
// <mount>/data/<path> — bounded by maxKVLeavesInspected across all KV v2 mounts combined.
func checkSecretStaleness(ctx context.Context, c *Client) Result {
	mounts, status, err := listMounts(ctx, c)
	if err != nil {
		return Result{Err: err}
	}
	if status == StatusForbidden {
		return denied("secret-staleness", "sys/mounts", `path "sys/mounts" { capabilities = ["read"] }`)
	}

	cutoff := time.Now().Add(-staleAfter)
	budget := maxKVLeavesInspected
	var stale []string
	var checked int
	truncated := false

	for _, path := range sortedKeys(mounts) {
		m := mounts[path]
		if m.Type != "kv" || m.Options.Version != "2" {
			continue
		}
		if err := walkKVv2Metadata(ctx, c, path, "", cutoff, &budget, &checked, &stale, &truncated); err != nil {
			return Result{Err: err}
		}
	}

	sev := SeverityInfo
	remediation := ""
	if len(stale) > 0 {
		sev = SeverityLow
		remediation = "Review secrets not updated in over a year — confirm they're still needed and still correct, or rotate/remove them."
	}
	evidence := fmt.Sprintf("%d secrets inspected across all KV v2 mounts; %d not updated in >365 days", checked, len(stale))
	if truncated {
		evidence += fmt.Sprintf(" — truncated at %d secrets; more exist and were not inspected", maxKVLeavesInspected)
	}
	return Result{Finding: &Finding{
		ID: "secret-staleness", Title: "Stale secrets (>365 days)", Severity: sev,
		Evidence: evidence, Remediation: remediation,
	}}
}

func walkKVv2Metadata(ctx context.Context, c *Client, mount, prefix string, cutoff time.Time, budget, checked *int, stale *[]string, truncated *bool) error {
	if *budget <= 0 {
		*truncated = true
		return nil
	}
	var list struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	status, err := listJSON(ctx, c, mount+"metadata/"+prefix, &list)
	if err != nil {
		return err
	}
	if status == StatusForbidden || status == StatusNotFound {
		return readKVv2LeafMetadata(ctx, c, mount, prefix, cutoff, budget, checked, stale)
	}
	if len(list.Data.Keys) == 0 {
		return readKVv2LeafMetadata(ctx, c, mount, prefix, cutoff, budget, checked, stale)
	}
	for _, k := range list.Data.Keys {
		child := prefix + strings.TrimSuffix(k, "/")
		if strings.HasSuffix(k, "/") {
			if err := walkKVv2Metadata(ctx, c, mount, child+"/", cutoff, budget, checked, stale, truncated); err != nil {
				return err
			}
			continue
		}
		if *budget <= 0 {
			*truncated = true
			return nil
		}
		if err := readKVv2LeafMetadata(ctx, c, mount, child, cutoff, budget, checked, stale); err != nil {
			return err
		}
	}
	return nil
}

func readKVv2LeafMetadata(ctx context.Context, c *Client, mount, path string, cutoff time.Time, budget, checked *int, stale *[]string) error {
	if path == "" {
		return nil // the mount root itself is never a leaf.
	}
	var meta struct {
		Data struct {
			UpdatedTime string `json:"updated_time"`
		} `json:"data"`
	}
	status, err := getJSON(ctx, c, mount+"metadata/"+path, &meta)
	if err != nil {
		return err
	}
	if status != StatusOK || meta.Data.UpdatedTime == "" {
		return nil // 403/404/absent — nothing to report, not an error (matches vaultsource's own "absent is not an error" convention).
	}
	*budget--
	*checked++
	updated, err := time.Parse(time.RFC3339, meta.Data.UpdatedTime)
	if err != nil {
		return nil // an unparseable timestamp isn't worth failing the whole scan over.
	}
	if updated.Before(cutoff) {
		*stale = append(*stale, mount+path)
	}
	return nil
}

func sortedKeys(m map[string]mountInfo) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
