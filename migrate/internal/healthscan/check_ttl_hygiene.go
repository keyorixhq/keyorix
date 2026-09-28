package healthscan

import (
	"context"
	"fmt"
	"sort"
)

// maxSupportedLeaseTTLSeconds is 768h in seconds — SESSION-G2 item (h)'s own threshold: a
// default/max lease TTL of exactly 0 (meaning "inherit the system default," which is itself
// opaque from this scan's vantage point) or explicitly set above this is flagged.
const maxSupportedLeaseTTLSeconds = 768 * 3600

func init() {
	RegisterCheck(Check{ID: "ttl-hygiene", Title: "Token/lease TTL hygiene", Fn: checkTTLHygiene})
	RegisterCheck(Check{ID: "lease-counts", Title: "Lease counts per mount", Fn: checkLeaseCounts})
}

type ttlConfig struct {
	Type   string `json:"type"`
	Config struct {
		DefaultLeaseTTL int `json:"default_lease_ttl"`
		MaxLeaseTTL     int `json:"max_lease_ttl"`
	} `json:"config"`
}

// checkTTLHygiene is (h)'s TTL half: default/max lease TTLs on every secrets mount and auth
// method, from sys/mounts and sys/auth (both already read by other checks — this one reads them
// again independently so it stays correct if it's ever the only check enabled).
func checkTTLHygiene(ctx context.Context, c *Client) Result {
	var mounts, auths struct {
		Data map[string]ttlConfig `json:"data"`
	}
	mStatus, err := getJSON(ctx, c, "sys/mounts", &mounts)
	if err != nil {
		return Result{Err: err}
	}
	if mStatus == StatusForbidden {
		return denied("ttl-hygiene", "sys/mounts", `path "sys/mounts" { capabilities = ["read"] }`)
	}
	aStatus, err := getJSON(ctx, c, "sys/auth", &auths)
	if err != nil {
		return Result{Err: err}
	}
	if aStatus == StatusForbidden {
		return denied("ttl-hygiene", "sys/auth", `path "sys/auth" { capabilities = ["read"] }`)
	}

	var flagged []string
	for path, cfg := range mounts.Data {
		if f := ttlFlag(cfg); f != "" {
			flagged = append(flagged, fmt.Sprintf("mount %s(%s): %s", path, cfg.Type, f))
		}
	}
	for path, cfg := range auths.Data {
		if f := ttlFlag(cfg); f != "" {
			flagged = append(flagged, fmt.Sprintf("auth %s(%s): %s", path, cfg.Type, f))
		}
	}
	sort.Strings(flagged)

	sev := SeverityInfo
	remediation := ""
	if len(flagged) > 0 {
		sev = SeverityMedium
		remediation = "Set explicit, bounded default_lease_ttl/max_lease_ttl (≤768h) on each flagged mount/auth method rather than leaving it at the unbounded system default."
	}
	return Result{Finding: &Finding{
		ID: "ttl-hygiene", Title: "Token/lease TTL hygiene", Severity: sev,
		Evidence:     fmt.Sprintf("%d mount(s)/auth method(s) with a 0 or >768h TTL: %v", len(flagged), flagged),
		WhyItMatters: "An unbounded or unset lease TTL means credentials issued through that mount can live indefinitely if never explicitly revoked.",
		Remediation:  remediation,
	}}
}

func ttlFlag(cfg ttlConfig) string {
	switch {
	case cfg.Config.DefaultLeaseTTL == 0 && cfg.Config.MaxLeaseTTL == 0:
		return "default and max lease TTL both 0 (system default)"
	case cfg.Config.DefaultLeaseTTL > maxSupportedLeaseTTLSeconds:
		return fmt.Sprintf("default lease TTL %ds > 768h", cfg.Config.DefaultLeaseTTL)
	case cfg.Config.MaxLeaseTTL > maxSupportedLeaseTTLSeconds:
		return fmt.Sprintf("max lease TTL %ds > 768h", cfg.Config.MaxLeaseTTL)
	default:
		return ""
	}
}

// checkLeaseCounts is (h)'s "lease counts per mount, if visible" half — deliberately
// best-effort: LIST sys/leases/lookup/<mount>/ one level deep (no recursion into each lease's
// own subtree, to keep this bounded) for every secrets mount, skipping (not failing) any mount
// this token can't list leases for.
func checkLeaseCounts(ctx context.Context, c *Client) Result {
	var mounts struct {
		Data map[string]struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	status, err := getJSON(ctx, c, "sys/mounts", &mounts)
	if err != nil {
		return Result{Err: err}
	}
	if status == StatusForbidden {
		return denied("lease-counts", "sys/mounts", `path "sys/mounts" { capabilities = ["read"] }`)
	}

	counts := map[string]int{}
	var notVisible []string
	paths := make([]string, 0, len(mounts.Data))
	for p := range mounts.Data {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, path := range paths {
		var leases struct {
			Data struct {
				Keys []string `json:"keys"`
			} `json:"data"`
		}
		lStatus, err := listJSON(ctx, c, "sys/leases/lookup/"+path, &leases)
		if err != nil {
			return Result{Err: err}
		}
		switch lStatus {
		case StatusOK:
			counts[path] = len(leases.Data.Keys)
		case StatusForbidden, StatusNotFound:
			notVisible = append(notVisible, path)
		}
	}

	evidence := fmt.Sprintf("top-level lease key counts by mount (best-effort, not recursive): %v", counts)
	if len(notVisible) > 0 {
		evidence += fmt.Sprintf("; not visible for: %v", notVisible)
	}
	return Result{Finding: &Finding{
		ID: "lease-counts", Title: "Lease counts per mount", Severity: SeverityInfo,
		Evidence: evidence,
	}}
}
