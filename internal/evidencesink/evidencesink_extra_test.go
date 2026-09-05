package evidencesink

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebhook_RefuseRedirectDirectly exercises the refuseRedirect helper
// directly against a cross-host and https→http-downgrade redirect.
func TestWebhook_RefuseRedirect_CrossHost(t *testing.T) {
	// Because refuseRedirect is unexported but accessible within the package,
	// we test it via the http.Client's CheckRedirect path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			// Redirect to a different host (use the test server's own URL but with a
			// tweaked hostname to look like a cross-host redirect — we can't actually
			// route to a different host in a unit test, but the CheckRedirect fires
			// before the connection is established).
			http.Redirect(w, r, "http://evil.example.com/steal", http.StatusFound) // NOSONAR -- test server intentionally redirects to evil host to verify refuseRedirect refuses it; gosecurity:S5146 false positive
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	wh, err := newWebhook(WebhookConfig{Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)

	err = wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "")
	require.Error(t, err, "a cross-host redirect must be refused")
	assert.Contains(t, err.Error(), "cross-host redirect")
}

// TestWebhook_HTTPSDowngradeRedirectRefused exercises the https→http downgrade
// branch of refuseRedirect.
func TestWebhook_HTTPSDowngradeRedirect_Refused(t *testing.T) {
	// Set up a plain-http server that "looks like" an https redirect target.
	// We use a TLS test server for the primary so the scheme is https.
	primary := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to http (downgrade).
		http.Redirect(w, r, "http://"+r.Host+"/final", http.StatusFound) // NOSONAR -- test handler intentionally issues http redirect to verify refuseRedirect refuses https→http downgrades; gosecurity:S5146 false positive
	}))
	t.Cleanup(primary.Close)

	// Use the TLS client from the test server so the cert is accepted.
	wh := &Webhook{
		cfg:         WebhookConfig{Endpoint: primary.URL},
		client:      primary.Client(),
		baseBackoff: time.Millisecond,
	}
	// Override the client's CheckRedirect to use our function.
	wh.client.CheckRedirect = refuseRedirect

	err := wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "")
	require.Error(t, err, "https→http redirect must be refused")
}

// TestIsLoopbackHost covers the various loopback representations.
func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"192.168.1.1", false},
		{"example.com", false},
		{"169.254.169.254", false},
	}
	for _, c := range cases {
		got := isLoopbackHost(c.host)
		assert.Equalf(t, c.want, got, "isLoopbackHost(%q)", c.host)
	}
}

// TestValidateEndpoint_HTTPLoopback verifies that http:// to a loopback address
// is accepted without AllowPrivateNetworkTarget.
func TestValidateEndpoint_HTTPLoopback(t *testing.T) {
	err := validateEndpoint("http://localhost/evidence", false, false)
	assert.NoError(t, err, "http to loopback must be allowed without AllowPrivateNetworkTarget")

	err = validateEndpoint("http://127.0.0.1/evidence", false, false)
	assert.NoError(t, err, "http to 127.0.0.1 must be allowed without AllowPrivateNetworkTarget")
}

// TestValidateEndpoint_UnknownScheme covers the default (non-https/http) branch.
func TestValidateEndpoint_UnknownScheme(t *testing.T) {
	err := validateEndpoint("ftp://example.com/evidence", false, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must use https")
}

// TestRefuseDisallowedHost_PrivateIP verifies a private literal IP is refused.
func TestRefuseDisallowedHost_PrivateIP(t *testing.T) {
	err := refuseDisallowedHost("10.0.0.1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private/link-local")
}

// TestRefuseDisallowedHost_PublicIP verifies a public literal IP is allowed.
func TestRefuseDisallowedHost_PublicIP(t *testing.T) {
	err := refuseDisallowedHost("203.0.113.5") // TEST-NET-3
	assert.NoError(t, err)
}

// TestRefuseDisallowedHost_UnresolvableHostname verifies an unresolvable hostname
// causes an error so evidence is not silently sent somewhere unknown.
func TestRefuseDisallowedHost_UnresolvableHostname(t *testing.T) {
	orig := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = orig })
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	err := refuseDisallowedHost("totally-invalid-host.invalid")
	require.Error(t, err, "an unresolvable hostname must cause an error")
}

// TestRefuseDisallowedHost_LookupReturnsPrivate verifies a hostname that
// resolves to a private IP is refused.
func TestRefuseDisallowedHost_LookupReturnsPrivate(t *testing.T) {
	orig := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = orig })
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.168.1.100")}}, nil
	}
	err := refuseDisallowedHost("internal.corp")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private/link-local")
}

// TestWebhook_ContextCancelledDuringRetry verifies that a cancelled context
// surfaces a context error rather than exhausting maxAttempts.
func TestWebhook_ContextCancelledDuringRetry(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	wh, err := newWebhook(WebhookConfig{Endpoint: srv.URL}, 50*time.Millisecond)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	err = wh.ForwardEvidence(ctx, "pack.json", []byte(`{}`), "")
	require.Error(t, err, "should error when context is cancelled during retry backoff")
}

// TestObjectStore_LockModeGovernance verifies the governance lock mode is stamped.
func TestObjectStore_LockModeGovernance(t *testing.T) {
	api := &fakeS3{}
	fixed := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	o := &ObjectStore{
		api: api, bucket: "evidence-bkt", prefix: "",
		lockMode: s3types.ObjectLockModeGovernance,
		retain:   30 * 24 * time.Hour,
		now:      func() time.Time { return fixed },
	}

	require.NoError(t, o.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), ""))
	require.NotEmpty(t, api.calls)
	assert.Equal(t, s3types.ObjectLockModeGovernance, api.calls[0].lockMode)
	assert.Contains(t, o.Target(), "lock:governance")
}

// TestObjectStore_BothLockAndLegalHold verifies the Target label includes both marks.
func TestObjectStore_BothLockAndLegalHold(t *testing.T) {
	api := &fakeS3{}
	fixed := time.Now()
	o := &ObjectStore{
		api: api, bucket: "bkt", prefix: "",
		lockMode:  s3types.ObjectLockModeCompliance,
		retain:    7 * 24 * time.Hour,
		legalHold: true,
		now:       func() time.Time { return fixed },
	}

	require.NoError(t, o.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), ""))
	target := o.Target()
	assert.Contains(t, target, "lock:compliance")
	assert.Contains(t, target, "legal-hold")
}

// TestObjectStore_SigPutFailurePropagates verifies that a failure on the second
// PutObject (the signature) is surfaced as an error.
func TestObjectStore_SigPutFailurePropagates(t *testing.T) {
	var callCount int
	api := &conditionalFakeS3{
		fn: func(n int) error {
			if n == 2 {
				return assert.AnError // fail the signature upload
			}
			return nil
		},
	}
	o := &ObjectStore{api: api, bucket: "bkt", prefix: "", now: time.Now}
	err := o.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "sig-value")
	_ = callCount
	require.Error(t, err, "failure on signature PutObject must propagate")
}

// conditionalFakeS3 delegates PutObject to a function that receives the call count.
type conditionalFakeS3 struct {
	calls int
	fn    func(n int) error
}

func (f *conditionalFakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.calls++
	if err := f.fn(f.calls); err != nil {
		return nil, err
	}
	return &s3.PutObjectOutput{}, nil
}

// TestObjectLockMode_GovernanceAndCompliance exercises both valid modes directly.
func TestObjectLockMode_AllCases(t *testing.T) {
	cases := []struct {
		input   string
		want    s3types.ObjectLockMode
		wantErr bool
	}{
		{"", "", false},
		{"governance", s3types.ObjectLockModeGovernance, false},
		{"GOVERNANCE", s3types.ObjectLockModeGovernance, false},
		{"compliance", s3types.ObjectLockModeCompliance, false},
		{"COMPLIANCE", s3types.ObjectLockModeCompliance, false},
		{"invalid", "", true},
	}
	for _, c := range cases {
		got, err := objectLockMode(c.input)
		if c.wantErr {
			require.Errorf(t, err, "objectLockMode(%q)", c.input)
		} else {
			require.NoErrorf(t, err, "objectLockMode(%q)", c.input)
			assert.Equalf(t, c.want, got, "objectLockMode(%q)", c.input)
		}
	}
}

// TestMulti_EmptyForwarders verifies a Multi with no forwarders delivers
// successfully (no errors to aggregate).
func TestMulti_EmptyForwarders(t *testing.T) {
	m := NewMulti()
	err := m.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "")
	assert.NoError(t, err)
	assert.Empty(t, m.Target())
}

// TestMulti_AllFailing verifies all failing targets aggregate their errors.
func TestMulti_AllFailing(t *testing.T) {
	a := &stubForwarder{label: "a", err: assert.AnError}
	b := &stubForwarder{label: "b", err: assert.AnError}
	m := NewMulti(a, b)
	err := m.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "a")
	assert.Contains(t, err.Error(), "b")
}

// TestValidateEndpoint_MalformedURL covers the url.Parse error branch of
// validateEndpoint (previously unreached — every existing test used a
// syntactically valid URL, so only the well-formed path was exercised).
func TestValidateEndpoint_MalformedURL(t *testing.T) {
	err := validateEndpoint("http://[::1", false, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid endpoint")
}

// TestPinnedDialContext_NoAddressesResolved covers the branch where the
// resolver succeeds but returns zero addresses — distinct from a resolution
// error, and previously unreached.
func TestPinnedDialContext_NoAddressesResolved(t *testing.T) {
	orig := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = orig })
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		return nil, nil // resolves successfully but to nothing
	}

	dial, err := pinnedDialContext("empty-answer.evidence.example")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not resolve to any address")
	assert.Nil(t, dial)
}

// TestPinnedDialContext_InvalidDialAddress covers the returned dialer's
// net.SplitHostPort error branch: a dial address without a port must be
// refused with a clear error rather than panicking or dialing garbage.
func TestPinnedDialContext_InvalidDialAddress(t *testing.T) {
	orig := lookupIPAddr
	t.Cleanup(func() { lookupIPAddr = orig })
	lookupIPAddr = func(host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.20")}}, nil
	}

	dial, err := pinnedDialContext("split-host-port.evidence.example")
	require.NoError(t, err)

	_, dialErr := dial(context.Background(), "tcp", "no-port-here")
	require.Error(t, dialErr, "a dial address with no port must be refused")
	assert.Contains(t, dialErr.Error(), "invalid dial address")
}

// TestNewObjectStore_AWSConfigLoadFailurePropagates covers the
// awsconfig.LoadDefaultConfig error branch of NewObjectStore (fail-closed):
// a misconfigured AWS environment (here, an unreadable CA bundle path) must
// surface as a constructor error rather than deferring the failure to the
// first upload.
func TestNewObjectStore_AWSConfigLoadFailurePropagates(t *testing.T) {
	origCABundle, hadCABundle := os.LookupEnv("AWS_CA_BUNDLE")
	require.NoError(t, os.Setenv("AWS_CA_BUNDLE", "/nonexistent/evidencesink-test/ca-bundle.pem"))
	t.Cleanup(func() {
		if hadCABundle {
			_ = os.Setenv("AWS_CA_BUNDLE", origCABundle)
		} else {
			_ = os.Unsetenv("AWS_CA_BUNDLE")
		}
	})

	_, err := NewObjectStore(context.Background(), ObjectStoreConfig{Bucket: "b"})
	require.ErrorContains(t, err, "load AWS config")
}
