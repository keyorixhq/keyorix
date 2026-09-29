package healthscan

import (
	"context"
	"fmt"
)

func init() {
	RegisterCheck(Check{ID: "raft-auto-snapshot", Title: "Raft auto-snapshot (backups)", Fn: checkRaftAutoSnapshot})
}

// checkRaftAutoSnapshot is SESSION-G2 item (l). sys/storage/raft/snapshot-auto/config only
// exists on Vault Enterprise with raft storage — a 404 here (OSS, non-raft storage, or
// OpenBao, none of which have this specific API) is genuinely "unknown, ask" per G2's own
// wording, not "not applicable": backups may well exist through some other mechanism (a
// storage-layer snapshot, a cron job) this scan has no way to see through Vault's API at all.
func checkRaftAutoSnapshot(ctx context.Context, c *Client) Result {
	var configs struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	status, err := listJSON(ctx, c, "sys/storage/raft/snapshot-auto/config", &configs)
	if err != nil {
		return Result{Err: err}
	}
	switch status {
	case StatusForbidden:
		return denied("raft-auto-snapshot", "sys/storage/raft/snapshot-auto/config", `path "sys/storage/raft/snapshot-auto/config" { capabilities = ["list", "read"] }`)
	case StatusNotFound:
		return Result{Finding: &Finding{
			ID: "raft-auto-snapshot", Title: "Raft auto-snapshot (backups)", Severity: SeverityInfo,
			Evidence:     "unknown, ask — this API isn't present on this Vault edition/storage backend, which doesn't mean backups don't exist by some other means",
			WhyItMatters: "A tested backup/restore process is essential operational readiness this scan cannot verify from the API alone in this case.",
			Remediation:  "Ask your team how backups are performed and tested for this install.",
		}}
	case StatusOK:
		sev := SeverityInfo
		remediation := ""
		if len(configs.Data.Keys) == 0 {
			sev = SeverityHigh
			remediation = "Configure automated raft snapshots (`vault write sys/storage/raft/snapshot-auto/config/<name> ...`) and periodically test restoring one."
		}
		return Result{Finding: &Finding{
			ID: "raft-auto-snapshot", Title: "Raft auto-snapshot (backups)", Severity: sev,
			Evidence:    fmt.Sprintf("%d automated snapshot config(s): %v", len(configs.Data.Keys), configs.Data.Keys),
			Remediation: remediation,
		}}
	default:
		return Result{Err: fmt.Errorf("unexpected HTTP %d from sys/storage/raft/snapshot-auto/config", status)}
	}
}
