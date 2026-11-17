//go:build !nogcp

package rotation

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

// The IAM service and adapter are the executor's own (gcpIAMClient over iam.Service);
// only the endpoint and the credential source differ. One route per call: list, create
// and delete differ by method and path. The prior key makes the delete step run in the
// pristine control; a program broken on "delete" ends in the PartialRotationError path.
func TestHostileGCPServiceAccountGenerateUpstream(t *testing.T) {
	const sa = "/v1/projects/-/serviceAccounts/rot@proj.iam.gserviceaccount.com/keys"
	js := func(s string) hostile.Resp { return hostile.Resp{Status: 200, CT: "application/json", Body: []byte(s)} }
	keyFile := base64.StdEncoding.EncodeToString([]byte(`{"type":"service_account","private_key_id":"new1"}`))
	runCloudExecutorHostile(t, cloudExecutorTarget{
		name: "gcp-service-account",
		routes: []hostile.Route{
			{Name: "list", Method: "GET", Prefix: sa, Valid: func(int, *http.Request) hostile.Resp {
				return js(`{"keys":[{"name":"projects/p/serviceAccounts/rot@proj.iam.gserviceaccount.com/keys/old1","validAfterTime":"2020-01-01T00:00:00Z"}]}`)
			}},
			{Name: "create", Method: "POST", Prefix: sa, Valid: func(int, *http.Request) hostile.Resp {
				return js(`{"name":"projects/p/serviceAccounts/rot@proj.iam.gserviceaccount.com/keys/new1","privateKeyData":"` + keyFile + `"}`)
			}},
			// DeleteKey gets the key's full resource name back from the list, not the "-" alias.
			{Name: "delete", Method: "DELETE", Prefix: "/v1/projects/p/serviceAccounts/rot@proj.iam.gserviceaccount.com/keys/", Valid: func(int, *http.Request) hostile.Resp {
				return js(`{}`)
			}},
		},
		build: func(_ context.Context, h *hostile.Harness) (Executor, string) {
			e := NewGCPServiceAccountKeyExecutor("gcp", []string{"rot@"})
			e.newClient = func(ctx context.Context) (gcpKeyAPI, error) {
				svc, err := iam.NewService(ctx, option.WithEndpoint(h.URL()), option.WithoutAuthentication())
				if err != nil {
					return nil, err
				}
				return &gcpIAMClient{svc: svc}, nil
			}
			return e, "rot@proj.iam.gserviceaccount.com"
		},
	})
}
