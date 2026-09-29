package healthscan

import (
	"context"
	"fmt"
)

func init() {
	RegisterCheck(Check{ID: "audit-devices", Title: "Audit devices", Fn: checkAuditDevices})
}

// checkAuditDevices is SESSION-G2 item (d): no audit device enabled is critical (no record of
// who did what), exactly one is medium (a single point of failure for the audit trail itself —
// if that device's target becomes unwritable, Vault blocks all requests and there's no
// secondary trail), two or more is informational.
func checkAuditDevices(ctx context.Context, c *Client) Result {
	var devices struct {
		Data map[string]struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	status, err := getJSON(ctx, c, "sys/audit", &devices)
	if err != nil {
		return Result{Err: err}
	}
	if status == StatusForbidden {
		return denied("audit-devices", "sys/audit", `path "sys/audit" { capabilities = ["read"] }`)
	}
	if status != StatusOK {
		return Result{Err: fmt.Errorf("unexpected HTTP %d from sys/audit", status)}
	}

	n := len(devices.Data)
	types := make([]string, 0, n)
	for path, d := range devices.Data {
		types = append(types, fmt.Sprintf("%s(%s)", path, d.Type))
	}

	switch n {
	case 0:
		return Result{Finding: &Finding{
			ID: "audit-devices", Title: "Audit devices", Severity: SeverityCritical,
			Evidence: "no audit device enabled", WhyItMatters: "With no audit device, there is no record of who accessed or changed anything through Vault.",
			Remediation: `Enable at least one audit device, e.g. "vault audit enable file file_path=/var/log/vault_audit.log".`,
		}}
	case 1:
		return Result{Finding: &Finding{
			ID: "audit-devices", Title: "Audit devices", Severity: SeverityMedium,
			Evidence:     fmt.Sprintf("one audit device enabled: %s", types[0]),
			WhyItMatters: "Vault blocks all requests if its only audit device's target becomes unwritable (e.g. a full disk) — a single audit device is also a single point of failure for availability, not just for the audit trail.",
			Remediation:  "Enable a second audit device with an independent failure domain (e.g. syslog alongside file).",
		}}
	default:
		return Result{Finding: &Finding{
			ID: "audit-devices", Title: "Audit devices", Severity: SeverityInfo,
			Evidence: fmt.Sprintf("%d audit devices enabled: %v", n, types),
		}}
	}
}
