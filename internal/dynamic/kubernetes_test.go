package dynamic

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeK8sMinter records what Issue passed and returns a canned token.
type fakeK8sMinter struct {
	token  string
	expiry time.Time
	err    error

	gotNamespace, gotServiceAccount string
	gotAudiences                    []string
	gotExpiration                   time.Duration
}

func (f *fakeK8sMinter) mintToken(_ context.Context, ns, sa string, aud []string, exp time.Duration) (string, time.Time, error) {
	f.gotNamespace, f.gotServiceAccount, f.gotAudiences, f.gotExpiration = ns, sa, aud, exp
	return f.token, f.expiry, f.err
}

func TestKubernetesEngine_Metadata(t *testing.T) {
	e := &KubernetesEngine{}
	assert.Equal(t, "kubernetes", e.BackendType())
	assert.True(t, e.IsEphemeralBackend())
	assert.True(t, e.SupportsNativeExpiry())
}

func TestKubernetesEngine_IssueMintsToken(t *testing.T) {
	exp := time.Now().Add(30 * time.Minute).UTC()
	fake := &fakeK8sMinter{token: "tok-abc", expiry: exp}
	e := &KubernetesEngine{minter: fake}

	cfg := `{"namespace":"app","service_account":"my-app","audiences":["https://svc"]}`
	cred, role, err := e.Issue(context.Background(), cfg, "", 30*time.Minute)
	require.NoError(t, err)

	// Passed through to the minter.
	assert.Equal(t, "app", fake.gotNamespace)
	assert.Equal(t, "my-app", fake.gotServiceAccount)
	assert.Equal(t, []string{"https://svc"}, fake.gotAudiences)
	assert.Equal(t, 30*time.Minute, fake.gotExpiration)

	// Returned as fields (no username/password — an ephemeral token backend).
	assert.Empty(t, cred.Username)
	assert.Empty(t, cred.Password)
	assert.Equal(t, "tok-abc", cred.Fields["token"])
	assert.Equal(t, "app", cred.Fields["namespace"])
	assert.Equal(t, "my-app", cred.Fields["service_account"])
	assert.Equal(t, exp.Format(time.RFC3339), cred.Fields["expiration"])
	assert.Contains(t, role, "keyorix-dyn-", "role name is a lease label only")
}

func TestKubernetesEngine_IssueFloorsExpiration(t *testing.T) {
	fake := &fakeK8sMinter{token: "t"}
	e := &KubernetesEngine{minter: fake}

	// A 1-minute TTL is floored to the Kubernetes 10-minute minimum so the lease TTL
	// matches what the API server will actually mint.
	_, _, err := e.Issue(context.Background(), `{"namespace":"app","service_account":"sa"}`, "", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, k8sMinExpirationSeconds*time.Second, fake.gotExpiration)
}

func TestKubernetesEngine_IssueValidation(t *testing.T) {
	e := &KubernetesEngine{minter: &fakeK8sMinter{token: "t"}}
	cases := map[string]string{
		"not JSON":          "namespace=app",
		"missing namespace": `{"service_account":"sa"}`,
		"missing sa":        `{"namespace":"app"}`,
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := e.Issue(context.Background(), cfg, "", time.Hour)
			require.Error(t, err)
		})
	}
}

func TestKubernetesEngine_IssuePropagatesMintError(t *testing.T) {
	e := &KubernetesEngine{minter: &fakeK8sMinter{err: assert.AnError}}
	_, _, err := e.Issue(context.Background(), `{"namespace":"app","service_account":"sa"}`, "", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request token")
}

func TestKubernetesEngine_RevokeIsNoOpRenewRefused(t *testing.T) {
	e := &KubernetesEngine{}
	require.NoError(t, e.Revoke(context.Background(), "{}", "keyorix-dyn-x"))
	err := e.Renew(context.Background(), "{}", "keyorix-dyn-x", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not renewable")
}

func TestNewRealK8sMinter_ConfigValidation(t *testing.T) {
	// api_server set but no token.
	_, err := newRealK8sMinter(k8sConfig{APIServer: "https://k8s:443", CACert: "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token is required")

	// api_server set but no CA — we must not skip TLS verification.
	_, err = newRealK8sMinter(k8sConfig{APIServer: "https://k8s:443", Token: "t"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca_cert is required")

	// A non-PEM CA is rejected (no certs parsed).
	_, err = newRealK8sMinter(k8sConfig{APIServer: "https://k8s:443", Token: "t", CACert: "not a pem"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates")

	// No api_server and not in-cluster → fail closed (test env has no KUBERNETES_SERVICE_HOST).
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	_, err = newRealK8sMinter(k8sConfig{Namespace: "app", ServiceAccount: "sa"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in-cluster")
}

func TestPathSegment(t *testing.T) {
	assert.Equal(t, "my-app", pathSegment("my-app"))
	for _, bad := range []string{"", "a/b", "a%2e", "a?x", "a#y"} {
		assert.Equal(t, "INVALID", pathSegment(bad), "must reject %q", bad)
	}
}
