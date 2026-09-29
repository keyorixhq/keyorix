package healthscan

import (
	"context"
	"fmt"
)

func init() {
	RegisterCheck(Check{ID: "tls-listener", Title: "TLS/listener configuration", Fn: checkTLSListener})
}

// checkTLSListener is SESSION-G2 item (j): sys/config/state/sanitized exposes the running
// server config, including listener stanzas — often sudo/root-only in a locked-down policy, so
// a 403 here is expected and unremarkable, not a scan failure.
func checkTLSListener(ctx context.Context, c *Client) Result {
	var sanitized struct {
		Data struct {
			Listeners []struct {
				Config struct {
					TLSDisable    bool   `json:"tls_disable"`
					TLSMinVersion string `json:"tls_min_version"`
				} `json:"config"`
			} `json:"listeners"`
		} `json:"data"`
	}
	status, err := getJSON(ctx, c, "sys/config/state/sanitized", &sanitized)
	if err != nil {
		return Result{Err: err}
	}
	if status == StatusForbidden {
		return denied("tls-listener", "sys/config/state/sanitized", `path "sys/config/state/sanitized" { capabilities = ["read"] }`)
	}
	if status != StatusOK {
		return Result{Err: fmt.Errorf("unexpected HTTP %d from sys/config/state/sanitized", status)}
	}

	var issues []string
	anyTLSDisabled, anyWeakVersion := false, false
	for i, l := range sanitized.Data.Listeners {
		switch {
		case l.Config.TLSDisable:
			anyTLSDisabled = true
			issues = append(issues, fmt.Sprintf("listener[%d]: TLS disabled", i))
		case isWeakTLSVersion(l.Config.TLSMinVersion):
			anyWeakVersion = true
			issues = append(issues, fmt.Sprintf("listener[%d]: tls_min_version=%s", i, l.Config.TLSMinVersion))
		}
	}

	sev := SeverityInfo
	remediation := ""
	switch {
	case anyTLSDisabled:
		sev = SeverityCritical
		remediation = "Enable TLS on every listener — a listener without TLS sends tokens and secrets over the network in cleartext."
	case anyWeakVersion:
		sev = SeverityMedium
		remediation = "Set tls_min_version to at least \"tls12\" on every listener."
	}

	return Result{Finding: &Finding{
		ID: "tls-listener", Title: "TLS/listener configuration", Severity: sev,
		Evidence:     fmt.Sprintf("%d listener(s); issues: %v", len(sanitized.Data.Listeners), issues),
		WhyItMatters: "A listener without TLS (or with a weak minimum version) exposes tokens and traffic to network eavesdropping.",
		Remediation:  remediation,
	}}
}

func isWeakTLSVersion(v string) bool {
	switch v {
	case "tls10", "tls11":
		return true
	default:
		return false
	}
}
