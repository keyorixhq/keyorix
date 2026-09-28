package healthscan

import (
	"context"
	"fmt"
)

func init() {
	RegisterCheck(Check{ID: "namespaces", Title: "Namespaces", Fn: checkNamespaces})
}

// checkNamespaces is SESSION-G2 item (k): Vault Enterprise namespace inventory. A 404 means
// namespaces aren't a feature on this Vault at all (OSS, or OpenBao without the feature) — not
// a gap, an informational fact.
func checkNamespaces(ctx context.Context, c *Client) Result {
	var namespaces struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	status, err := listJSON(ctx, c, "sys/namespaces", &namespaces)
	if err != nil {
		return Result{Err: err}
	}
	switch status {
	case StatusForbidden:
		return denied("namespaces", "sys/namespaces", `path "sys/namespaces" { capabilities = ["list"] }`)
	case StatusNotFound:
		return Result{Finding: &Finding{
			ID: "namespaces", Title: "Namespaces", Severity: SeverityInfo,
			Evidence: "namespaces not supported on this Vault (Community Edition/OpenBao, or Enterprise without the feature enabled)",
		}}
	case StatusOK:
		return Result{Finding: &Finding{
			ID: "namespaces", Title: "Namespaces", Severity: SeverityInfo,
			Evidence: fmt.Sprintf("%d namespace(s): %v", len(namespaces.Data.Keys), namespaces.Data.Keys),
		}}
	default:
		return Result{Err: fmt.Errorf("unexpected HTTP %d from sys/namespaces", status)}
	}
}
