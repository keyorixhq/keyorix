package healthscan

import (
	"context"
	"fmt"
)

// maxSecretsCountedPerMount bounds the top-level (non-recursive) secret count
// checkMigrationReadiness takes per KV mount — an approximation, stated as such, not a full
// recursive walk (checkSecretStaleness already does that walk for a different purpose; doing it
// twice per scan would double the Vault traffic for a number this section only needs
// approximately).
const maxSecretsCountedPerMount = 1000

func init() {
	RegisterCheck(Check{ID: "migration-readiness", Title: "Migration readiness", Fn: checkMigrationReadiness})
}

// MigrationReadiness summarizes what keyorix-migrate can and can't import from this Vault,
// derived from the same secrets-engine inventory the "i" checks use. Report.WriteMarkdown/HTML
// render this as its own section (not folded into the generic findings list) — see report.go.
type MigrationReadiness struct {
	KVv1Mounts        int      `json:"kv_v1_mounts"`
	KVv2Mounts        int      `json:"kv_v2_mounts"`
	KVTopLevelSecrets int      `json:"kv_top_level_secrets_approx"`
	Truncated         bool     `json:"truncated"`
	DynamicMounts     []string `json:"dynamic_mounts_not_importable"`
}

// checkMigrationReadiness is the registered-check wrapper around computeMigrationReadiness, for
// the generic findings list and for "which checks ran" bookkeeping. Report.WriteMarkdown/HTML
// render the structured MigrationReadiness field (populated separately by Run — see report.go
// and check.go) as this scan's own dedicated section rather than this Finding's evidence text,
// but the Finding still carries the same summary for JSON consumers that only look at Findings.
func checkMigrationReadiness(ctx context.Context, c *Client) Result {
	mr, status, err := computeMigrationReadiness(ctx, c)
	if err != nil {
		return Result{Err: err}
	}
	if status == StatusForbidden {
		return denied("migration-readiness", "sys/mounts", `path "sys/mounts" { capabilities = ["read"] }`)
	}

	evidence := fmt.Sprintf("KV v1 mounts: %d, KV v2 mounts: %d, approx. top-level secrets: %d, dynamic (not importable): %d",
		mr.KVv1Mounts, mr.KVv2Mounts, mr.KVTopLevelSecrets, len(mr.DynamicMounts))
	if mr.Truncated {
		evidence += " (secret count truncated — this is a lower bound)"
	}

	return Result{Finding: &Finding{
		ID: "migration-readiness", Title: "Migration readiness", Severity: SeverityInfo,
		Evidence: evidence,
	}}
}

// computeMigrationReadiness is what `keyorix-migrate vault` (the import command, not this scan)
// can pull in today: KV v1/v2 mounts, an approximate top-level secret count, and which mounts it
// CANNOT import (dynamic-secrets engines have no static value to migrate — a database engine
// issues credentials on demand, it doesn't hold one to copy). Shared by checkMigrationReadiness
// (the registered check) and Run (which populates Report.MigrationReadiness directly).
func computeMigrationReadiness(ctx context.Context, c *Client) (MigrationReadiness, int, error) {
	mounts, status, err := listMounts(ctx, c)
	if err != nil {
		return MigrationReadiness{}, status, err
	}
	if status == StatusForbidden {
		return MigrationReadiness{}, status, nil
	}

	mr := MigrationReadiness{}
	for _, path := range sortedKeys(mounts) {
		m := mounts[path]
		if m.Type == "kv" {
			if m.Options.Version == "2" {
				mr.KVv2Mounts++
			} else {
				mr.KVv1Mounts++
			}
			n, truncated, err := countTopLevelSecrets(ctx, c, path, m.Options.Version)
			if err != nil {
				return MigrationReadiness{}, status, err
			}
			mr.KVTopLevelSecrets += n
			mr.Truncated = mr.Truncated || truncated
			continue
		}
		if !nonDynamicMountTypes[m.Type] {
			mr.DynamicMounts = append(mr.DynamicMounts, fmt.Sprintf("%s(%s)", path, m.Type))
		}
	}
	return mr, status, nil
}

func countTopLevelSecrets(ctx context.Context, c *Client, mount, kvVersion string) (count int, truncated bool, err error) {
	listPath := mount
	if kvVersion == "2" {
		listPath = mount + "metadata/"
	}
	var list struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	status, err := listJSON(ctx, c, listPath, &list)
	if err != nil {
		return 0, false, err
	}
	if status != StatusOK {
		return 0, false, nil
	}
	if len(list.Data.Keys) > maxSecretsCountedPerMount {
		return maxSecretsCountedPerMount, true, nil
	}
	return len(list.Data.Keys), false, nil
}
