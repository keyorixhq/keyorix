//go:build !nogcp

package dynamic

import (
	"context"
	"net/http"
	"testing"

	iamcredentials "google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

// The IAM Credentials service is the one realGCPMinter builds (iamcredentials.Service,
// GenerateAccessToken(...).Do()); only the endpoint and the credential source differ.
// The client is unauthenticated, so it sends no credential for the leak oracle to scan
// for (the service-account name is an identifier, and is in the request URL by design);
// the harness's canary still must not appear in an error or the log.
func TestHostileGCPIssue(t *testing.T) {
	runCloudHostile(t, cloudHostileTarget{
		name: "gcp",
		routes: []hostile.Route{{
			Name: "token", Method: "POST", Prefix: "/v1/projects/-/serviceAccounts/",
			Valid: func(int, *http.Request) hostile.Resp {
				return hostile.Resp{Status: 200, CT: "application/json", Body: []byte(`{"accessToken":"ya29.hostile-token-0001","expireTime":"2031-01-02T03:04:05Z"}`)}
			},
		}},
		issue: func(ctx context.Context, h *hostile.Harness) error {
			svc, err := iamcredentials.NewService(ctx, option.WithEndpoint(h.URL()), option.WithoutAuthentication())
			if err != nil {
				return err
			}
			eng := Contain(&GCPEngine{minter: &realGCPMinter{svc: svc}})
			_, _, err = eng.Issue(ctx, `{"service_account":"hostile-sa@hostile-proj.iam.gserviceaccount.com"}`, "", hostileIssueTTL)
			return err
		},
	})
}
