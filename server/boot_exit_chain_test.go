package main

// REVIEW-4213-DEEP-2 N1/N2: an Azure token endpoint that cannot be reached,
// and a key-provider fallback chain whose members are all unreachable, may
// come back (75); a refusal in either stays an operator fix (78).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	keyorixcrypto "github.com/keyorixhq/keyorix/internal/crypto"
)

const testTenant = "00000000-0000-0000-0000-000000000001"

// closedPortURL is an https URL on 127.0.0.1 nothing listens on.
func closedPortURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "https://" + addr
}

func cloudAt(authorityHost string) cloud.Configuration {
	return cloud.Configuration{ActiveDirectoryAuthorityHost: authorityHost + "/"}
}

// kekStep is how the boot step that derives the KEK classifies its error
// (server/key_dir_lock.go).
func kekStep(err error) int {
	return bootExitCode(operatorFixUnlessUnreachable(fmt.Errorf("KEK from key provider %q failed: %w", "azure-kms", err)))
}

func azureToken(t *testing.T, cred azcore.TokenCredential) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://vault.azure.net/.default"}})
	if err == nil {
		t.Fatal("GetToken succeeded against a stub that never issues a token")
	}
	return err
}

func TestBootExitCode_AzureTokenEndpointUnreachable(t *testing.T) {
	cred, err := azidentity.NewClientSecretCredential(testTenant, "app", "secret", &azidentity.ClientSecretCredentialOptions{
		ClientOptions:            azcore.ClientOptions{Cloud: cloudAt(closedPortURL(t))},
		DisableInstanceDiscovery: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tokenErr := azureToken(t, cred)
	if got := kekStep(tokenErr); got != exitDependencyDown {
		t.Errorf("token endpoint unreachable: exit %d, want %d (%v)", got, exitDependencyDown, tokenErr)
	}
}

// The production constructor (internal/crypto/azurekms: NewDefaultAzureCredential(nil)),
// configured from the environment the way an edge device is.
func TestBootExitCode_AzureDefaultCredentialUnreachable(t *testing.T) {
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "EnvironmentCredential")
	t.Setenv("AZURE_TENANT_ID", testTenant)
	t.Setenv("AZURE_CLIENT_ID", "app")
	t.Setenv("AZURE_CLIENT_SECRET", "secret")
	t.Setenv("AZURE_AUTHORITY_HOST", closedPortURL(t))
	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{DisableInstanceDiscovery: true})
	if err != nil {
		t.Fatal(err)
	}
	tokenErr := azureToken(t, cred)
	if _, ok := errors.AsType[*azidentity.AuthenticationFailedError](tokenErr); !ok {
		t.Fatalf("premise: want *azidentity.AuthenticationFailedError, got %T: %v", tokenErr, tokenErr)
	}
	if got := kekStep(tokenErr); got != exitDependencyDown {
		t.Errorf("DefaultAzureCredential, token host unreachable: exit %d, want %d (%v)", got, exitDependencyDown, tokenErr)
	}
}

// No credential configured at all is azidentity's credentialUnavailableError,
// not an AuthenticationFailedError: an operator fix.
func TestBootExitCode_AzureNoCredentialConfigured(t *testing.T) {
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "EnvironmentCredential")
	for _, k := range []string{"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERTIFICATE_PATH", "AZURE_USERNAME"} {
		t.Setenv(k, "")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		t.Fatal(err)
	}
	tokenErr := azureToken(t, cred)
	if _, ok := errors.AsType[*azidentity.AuthenticationFailedError](tokenErr); ok {
		t.Fatalf("premise: no credential configured must not be an AuthenticationFailedError: %v", tokenErr)
	}
	if got := kekStep(tokenErr); got != exitOperatorFix {
		t.Errorf("no Azure credential configured: exit %d, want %d (%v)", got, exitOperatorFix, tokenErr)
	}
}

// entraStub answers the tenant discovery document and then the token request
// with status and body.
func entraStub(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/openid-configuration") {
			base := srv.URL + "/" + testTenant
			_, _ = fmt.Fprintf(w, `{"token_endpoint":%q,"authorization_endpoint":%q,"issuer":%q}`,
				base+"/oauth2/v2.0/token", base+"/oauth2/v2.0/authorize", base+"/v2.0")
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestBootExitCode_AzureTokenEndpointAnswers(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   int
	}{
		{"400 invalid_client (wrong secret)", http.StatusBadRequest, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`, exitOperatorFix},
		{"401 unauthorized_client", http.StatusUnauthorized, `{"error":"unauthorized_client","error_description":"AADSTS700016: Application not found."}`, exitOperatorFix},
		{"503 temporarily unavailable", http.StatusServiceUnavailable, `{"error":"temporarily_unavailable"}`, exitDependencyDown},
		{"429 throttled", http.StatusTooManyRequests, `{"error":"temporarily_unavailable"}`, exitDependencyDown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := entraStub(t, tc.status, tc.body)
			cred, err := azidentity.NewClientSecretCredential(testTenant, "app", "secret", &azidentity.ClientSecretCredentialOptions{
				ClientOptions: azcore.ClientOptions{
					Cloud:     cloudAt(srv.URL),
					Transport: srv.Client(),
					Retry:     policy.RetryOptions{MaxRetries: -1},
				},
				DisableInstanceDiscovery: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			tokenErr := azureToken(t, cred)
			if got := kekStep(tokenErr); got != tc.want {
				t.Errorf("exit %d, want %d (%v)", got, tc.want, tokenErr)
			}
		})
	}
}

// failingProvider is a KeyProvider whose KEK always fails with err.
type failingProvider struct {
	name string
	err  error
}

func (p failingProvider) Name() string         { return p.name }
func (p failingProvider) KEK() ([]byte, error) { return nil, p.err }

func TestBootExitCode_FallbackChain(t *testing.T) {
	refused := func(host string) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("dial tcp %s: connect: connection refused", host)}
	}
	denied := &azcore.ResponseError{StatusCode: http.StatusForbidden, ErrorCode: "Forbidden"}
	cases := []struct {
		name    string
		members []keyorixcrypto.KeyProvider
		want    int
	}{
		{"every member unreachable", []keyorixcrypto.KeyProvider{
			failingProvider{"aws-kms", refused("kms.eu-west-1.amazonaws.com:443")},
			failingProvider{"gcp-kms", refused("cloudkms.googleapis.com:443")},
		}, exitDependencyDown},
		// The unreachable member may come back and serve the KEK.
		{"one refused, one unreachable", []keyorixcrypto.KeyProvider{
			failingProvider{"azure-kms", denied},
			failingProvider{"aws-kms", refused("kms.eu-west-1.amazonaws.com:443")},
		}, exitDependencyDown},
		{"every member refused", []keyorixcrypto.KeyProvider{
			failingProvider{"azure-kms", denied},
			failingProvider{"file", errors.New("open /etc/keyorix/kek: no such file or directory")},
		}, exitOperatorFix},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := keyorixcrypto.NewMultiKeyProvider(tc.members)
			if err != nil {
				t.Fatal(err)
			}
			_, kekErr := m.KEK()
			if kekErr == nil {
				t.Fatal("KEK succeeded with every member failing")
			}
			if got := kekStep(kekErr); got != tc.want {
				t.Errorf("exit %d, want %d (%v)", got, tc.want, kekErr)
			}
		})
	}
}
