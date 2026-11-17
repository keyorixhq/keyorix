package rotation

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

const hostileGraphBearer = "hostile-graph-bearer-canary-0001"

type hostileTokenSource struct{}

func (hostileTokenSource) Token(context.Context) (string, error) { return hostileGraphBearer, nil }

// retarget sends the executor's fixed https://graph.microsoft.com URLs to the harness
// (TLS, certificate trusted via the transport's pool). The client is otherwise the
// executor's own: azureGraphClient.do, the response size cap, the refuse-every-redirect
// policy and the HTTP timeout.
type retarget struct {
	to   *url.URL
	base http.RoundTripper
}

func (r retarget) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host, req.Host = r.to.Scheme, r.to.Host, r.to.Host
	return r.base.RoundTrip(req)
}

// One route per call: list (GET), add (POST .../addPassword), remove (POST .../removePassword).
func TestHostileAzureGraphGenerateUpstream(t *testing.T) {
	const app = "/v1.0/applications/00000000-0000-4000-8000-0000000000a1"
	js := func(s string) hostile.Resp { return hostile.Resp{Status: 200, CT: "application/json", Body: []byte(s)} }
	runCloudExecutorHostile(t, cloudExecutorTarget{
		name:     "azure-app",
		tls:      true,
		creds:    []string{hostileGraphBearer},
		bodyless: []string{"remove"},
		routes: []hostile.Route{
			{Name: "list", Method: "GET", Prefix: app, Valid: func(int, *http.Request) hostile.Resp {
				return js(`{"passwordCredentials":[{"keyId":"11111111-0000-4000-8000-000000000001"}]}`)
			}},
			{Name: "add", Method: "POST", Prefix: app + "/addPassword", Valid: func(int, *http.Request) hostile.Resp {
				return js(`{"secretText":"hostile-new-secret-text-0001","keyId":"22222222-0000-4000-8000-000000000002"}`)
			}},
			{Name: "remove", Method: "POST", Prefix: app + "/removePassword", Valid: func(int, *http.Request) hostile.Resp {
				return hostile.Resp{Status: 204}
			}},
		},
		build: func(_ context.Context, h *hostile.Harness) (Executor, string) {
			u, _ := url.Parse(h.URL())
			e := NewAzureAppSecretExecutor("azure", []string{"00000000-"})
			e.newClient = func(context.Context) (azureGraphAPI, error) {
				return &azureGraphClient{
					tokenSource: hostileTokenSource{},
					http: &http.Client{
						Timeout:       azureHTTPTimeout,
						CheckRedirect: refuseAzureGraphRedirect,
						Transport:     retarget{to: u, base: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: h.CertPool(), MinVersion: tls.VersionTLS12}}},
					},
				}, nil
			}
			return e, "00000000-0000-4000-8000-0000000000a1"
		},
	})
}
