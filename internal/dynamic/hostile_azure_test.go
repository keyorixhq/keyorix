//go:build !noazure

package dynamic

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

const hostileAzureClientSecret = "hostile-azure-client-secret-canary-0001"

// The token is acquired through azidentity (the credential DefaultAzureCredential's
// environment link builds) against a TLS authority standing in for Entra; the engine's
// own realAzureMinter.mintToken is what runs. The harness certificate is trusted by the
// transport handed to the credential, not by disabling verification.
func TestHostileAzureIssue(t *testing.T) {
	runCloudHostile(t, cloudHostileTarget{
		name:  "azure",
		tls:   true,
		creds: []string{hostileAzureClientSecret},
		routes: []hostile.Route{{
			Name: "token", Prefix: "/hostile-tenant/",
			// MSAL reads the tenant's OpenID configuration before the token call even with
			// instance discovery off; that document is answered pristinely, only the token
			// exchange is mutated.
			Pass: func(r *http.Request) (hostile.Resp, bool) {
				if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
					return hostile.Resp{}, false
				}
				base := "https://" + r.Host + "/hostile-tenant"
				return hostile.Resp{Status: 200, CT: "application/json", Body: []byte(`{"token_endpoint":"` + base + `/oauth2/v2.0/token","authorization_endpoint":"` + base + `/oauth2/v2.0/authorize","issuer":"` + base + `/v2.0"}`)}, true
			},
			Valid: func(int, *http.Request) hostile.Resp {
				return hostile.Resp{Status: 200, CT: "application/json", Body: []byte(`{"token_type":"Bearer","expires_in":3600,"ext_expires_in":3600,"access_token":"eyJ.hostile-azure-token.0001"}`)}
			},
		}},
		issue: func(ctx context.Context, h *hostile.Harness) error {
			cred, err := azidentity.NewClientSecretCredential("hostile-tenant", "hostile-client", hostileAzureClientSecret, &azidentity.ClientSecretCredentialOptions{
				ClientOptions: azcore.ClientOptions{
					Cloud:     cloud.Configuration{ActiveDirectoryAuthorityHost: h.URL()},
					Transport: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: h.CertPool(), MinVersion: tls.VersionTLS12}}},
				},
				DisableInstanceDiscovery: true,
			})
			if err != nil {
				return err
			}
			eng := Contain(&AzureEngine{minter: &realAzureMinter{cred: cred}})
			_, _, err = eng.Issue(ctx, `{"scopes":["https://management.azure.com/.default"]}`, "", hostileIssueTTL)
			return err
		},
	})
}
