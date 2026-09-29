package healthscan

import (
	"context"
	"fmt"
)

func init() {
	RegisterCheck(Check{ID: "seal", Title: "Seal configuration", Fn: checkSeal})
}

// checkSeal is SESSION-G2 item (b): seal type (shamir vs. auto-unseal), recovery vs. unseal key
// shares/threshold, and sealed status — all from the single sys/seal-status endpoint.
func checkSeal(ctx context.Context, c *Client) Result {
	var status struct {
		Type         string `json:"type"`
		Sealed       bool   `json:"sealed"`
		Initialized  bool   `json:"initialized"`
		T            int    `json:"t"`
		N            int    `json:"n"`
		RecoverySeal bool   `json:"recovery_seal"`
	}
	httpStatus, err := getJSON(ctx, c, "sys/seal-status", &status)
	if err != nil {
		return Result{Err: err}
	}
	if httpStatus == StatusForbidden {
		return denied("seal", "sys/seal-status", `path "sys/seal-status" { capabilities = ["read"] }`)
	}
	if httpStatus != StatusOK {
		return Result{Err: fmt.Errorf("unexpected HTTP %d from sys/seal-status", httpStatus)}
	}

	if !status.Initialized {
		return Result{Finding: &Finding{
			ID: "seal", Title: "Seal configuration", Severity: SeverityCritical,
			Evidence: "Vault is not initialized", WhyItMatters: "An uninitialized Vault has no data and serves no requests.",
			Remediation: "Run `vault operator init` (or the equivalent for your deployment automation).",
		}}
	}
	if status.Sealed {
		return Result{Finding: &Finding{
			ID: "seal", Title: "Seal configuration", Severity: SeverityCritical,
			Evidence: fmt.Sprintf("Vault is sealed (type=%s)", status.Type), WhyItMatters: "A sealed Vault serves no requests at all until unsealed.",
			Remediation: "Unseal Vault (`vault operator unseal`, or confirm your auto-unseal mechanism — KMS, HSM — is reachable).",
		}}
	}

	shareKind := "unseal"
	if status.RecoverySeal {
		shareKind = "recovery"
	}
	autoUnseal := status.Type != "" && status.Type != "shamir"

	sev := SeverityInfo
	remediation := ""
	evidence := fmt.Sprintf("seal type=%s, %s key shares: %d-of-%d threshold", status.Type, shareKind, status.T, status.N)
	if !autoUnseal && status.T <= 1 {
		sev = SeverityHigh
		remediation = "A 1-of-N (or single-share) shamir threshold means one person can unseal Vault alone, defeating shamir's split-knowledge purpose. Re-key to a threshold of at least 3."
	}

	return Result{Finding: &Finding{
		ID: "seal", Title: "Seal configuration", Severity: sev,
		Evidence:     evidence,
		WhyItMatters: "The seal mechanism and key threshold determine who can unseal Vault and how resilient that process is to one person being unavailable or compromised.",
		Remediation:  remediation,
	}}
}
