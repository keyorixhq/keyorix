package healthscan

import (
	"context"
	"fmt"
)

func init() {
	RegisterCheck(Check{ID: "token-accessor-count", Title: "Token accessor count", Fn: checkTokenAccessorCount})
	RegisterCheck(Check{ID: "root-tokens", Title: "Root-policy tokens", Fn: checkRootTokens})
}

// checkTokenAccessorCount is a supporting inventory fact for SESSION-G2 item (e): the total
// number of live token accessors, via LIST auth/token/accessors — a genuine LIST, allowed under
// this client's GET/LIST-only guarantee.
func checkTokenAccessorCount(ctx context.Context, c *Client) Result {
	var accessors struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	status, err := listJSON(ctx, c, "auth/token/accessors", &accessors)
	if err != nil {
		return Result{Err: err}
	}
	if status == StatusForbidden {
		return denied("token-accessor-count", "auth/token/accessors", `path "auth/token/accessors" { capabilities = ["list"] }`)
	}
	if status != StatusOK {
		return Result{Err: fmt.Errorf("unexpected HTTP %d from auth/token/accessors", status)}
	}
	return Result{Finding: &Finding{
		ID: "token-accessor-count", Title: "Token accessor count", Severity: SeverityInfo,
		Evidence: fmt.Sprintf("%d live token accessors", len(accessors.Data.Keys)),
	}}
}

// checkRootTokens is (e)'s "count of root-policy tokens" requirement, and it always reports
// NotChecked — deliberately, not as a permission gap. Identifying which accessor carries the
// root policy requires POST auth/token/lookup-accessor (Vault keeps the accessor out of the
// URL/audit trail on purpose — there's no GET/LIST-shaped equivalent). This client refuses every
// HTTP method except GET/LIST at the code level (see client.go's request()), so this check can
// never complete under that guarantee no matter what policy the token holds — PolicyLine is
// left empty on purpose: no policy grant would fix this, only relaxing the read-only guarantee
// would, and that guarantee is this tool's entire safety story for running against production.
// See docs/vault-health-scan.md.
func checkRootTokens(_ context.Context, _ *Client) Result {
	return Result{NotChecked: &NotChecked{
		ID: "root-tokens",
		Reason: "identifying root-policy tokens requires POST auth/token/lookup-accessor per accessor, which this scanner never issues " +
			"(it only ever performs GET/LIST — see docs/vault-health-scan.md's read-only guarantee). See the \"token-accessor-count\" " +
			"finding for the total accessor count, which IS available via LIST.",
	}}
}
