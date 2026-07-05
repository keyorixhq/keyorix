package dynamic

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeK8sMinter records what Issue/Revoke passed and returns canned results. It
// implements k8sTokenMinter without touching a real cluster — this is the same
// fake-seam convention every other dynamic-secret engine's tests use (see e.g.
// fakeSTS in awssts_test.go). It proves the engine issues the correct API calls
// with the correct parameters (namespace/name/boundObjectRef), NOT that a real
// Kubernetes API server actually rejects a token after its bound Secret is
// deleted — that would require a live cluster, which this test environment
// doesn't have.
type fakeK8sMinter struct {
	token  string
	expiry time.Time
	err    error

	gotNamespace, gotServiceAccount string
	gotAudiences                    []string
	gotExpiration                   time.Duration
	gotBound                        *boundObjectRef

	createSecretErr   error
	createSecretUID   string
	createdSecretNS   string
	createdSecretName string

	deleteSecretErr    error
	deleteSecretCalled bool
	deletedSecretNS    string
	deletedSecretName  string
}

func (f *fakeK8sMinter) mintToken(_ context.Context, ns, sa string, aud []string, exp time.Duration, bound *boundObjectRef) (string, time.Time, error) {
	f.gotNamespace, f.gotServiceAccount, f.gotAudiences, f.gotExpiration, f.gotBound = ns, sa, aud, exp, bound
	return f.token, f.expiry, f.err
}

func (f *fakeK8sMinter) createBoundSecret(_ context.Context, ns, name string) (string, error) {
	f.createdSecretNS, f.createdSecretName = ns, name
	if f.createSecretErr != nil {
		return "", f.createSecretErr
	}
	if f.createSecretUID == "" {
		return "fake-secret-uid", nil
	}
	return f.createSecretUID, nil
}

func (f *fakeK8sMinter) deleteBoundSecret(_ context.Context, ns, name string) error {
	f.deleteSecretCalled = true
	f.deletedSecretNS, f.deletedSecretName = ns, name
	return f.deleteSecretErr
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
	assert.Nil(t, fake.gotBound, "revocable defaults to false — no boundObjectRef")

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

// --- #97: opt-in bound-token revocation ---

func TestKubernetesEngine_RevocableIssueBindsTokenToPerLeaseSecret(t *testing.T) {
	fake := &fakeK8sMinter{token: "tok", createSecretUID: "secret-uid-123"}
	e := &KubernetesEngine{minter: fake}

	cfg := `{"namespace":"app","service_account":"my-app","revocable":true}`
	_, role, err := e.Issue(context.Background(), cfg, "", time.Hour)
	require.NoError(t, err)

	// The bound Secret is created in the lease's namespace, named after the
	// returned lease label — Revoke later uses that same name to find it again.
	assert.Equal(t, "app", fake.createdSecretNS)
	assert.Equal(t, role, fake.createdSecretName)

	// The TokenRequest carried that Secret's name+uid as spec.boundObjectRef.
	require.NotNil(t, fake.gotBound)
	assert.Equal(t, role, fake.gotBound.Name)
	assert.Equal(t, "secret-uid-123", fake.gotBound.UID)
}

func TestKubernetesEngine_NonRevocableIssueCreatesNoBoundSecret(t *testing.T) {
	fake := &fakeK8sMinter{token: "tok"}
	e := &KubernetesEngine{minter: fake}

	_, _, err := e.Issue(context.Background(), `{"namespace":"app","service_account":"sa"}`, "", time.Hour)
	require.NoError(t, err)
	assert.Empty(t, fake.createdSecretName, "revocable defaults to false — no Secret should be created")
	assert.Nil(t, fake.gotBound)
}

func TestKubernetesEngine_RevocableIssuePropagatesCreateSecretError(t *testing.T) {
	fake := &fakeK8sMinter{token: "tok", createSecretErr: assert.AnError}
	e := &KubernetesEngine{minter: fake}

	_, _, err := e.Issue(context.Background(), `{"namespace":"app","service_account":"sa","revocable":true}`, "", time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create bound secret")
}

func TestKubernetesEngine_RevocableIssueCleansUpSecretOnMintFailure(t *testing.T) {
	fake := &fakeK8sMinter{err: assert.AnError, createSecretUID: "uid-x"}
	e := &KubernetesEngine{minter: fake}

	_, _, err := e.Issue(context.Background(), `{"namespace":"app","service_account":"sa","revocable":true}`, "", time.Hour)
	require.Error(t, err)
	assert.True(t, fake.deleteSecretCalled, "a failed mint must not leave an orphaned bound Secret behind")
	assert.Equal(t, "app", fake.deletedSecretNS)
	assert.Equal(t, fake.createdSecretName, fake.deletedSecretName)
}

func TestKubernetesEngine_RevokeIsNoOpWhenNotRevocable(t *testing.T) {
	fake := &fakeK8sMinter{}
	e := &KubernetesEngine{minter: fake}
	require.NoError(t, e.Revoke(context.Background(), `{"namespace":"app","service_account":"sa"}`, "keyorix-dyn-x"))
	assert.False(t, fake.deleteSecretCalled, "revocable defaults to false — Revoke must not touch the target")
}

func TestKubernetesEngine_RevokeDeletesBoundSecretWhenRevocable(t *testing.T) {
	fake := &fakeK8sMinter{}
	e := &KubernetesEngine{minter: fake}
	err := e.Revoke(context.Background(), `{"namespace":"app","service_account":"sa","revocable":true}`, "keyorix-dyn-x")
	require.NoError(t, err)
	assert.True(t, fake.deleteSecretCalled)
	assert.Equal(t, "app", fake.deletedSecretNS)
	assert.Equal(t, "keyorix-dyn-x", fake.deletedSecretName, "the lease's role name is the bound Secret's name")
}

func TestKubernetesEngine_RevokePropagatesDeleteError(t *testing.T) {
	fake := &fakeK8sMinter{deleteSecretErr: assert.AnError}
	e := &KubernetesEngine{minter: fake}
	err := e.Revoke(context.Background(), `{"namespace":"app","service_account":"sa","revocable":true}`, "keyorix-dyn-x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete bound secret")
}

func TestKubernetesEngine_RevokeRejectsMalformedConfig(t *testing.T) {
	e := &KubernetesEngine{minter: &fakeK8sMinter{}}
	err := e.Revoke(context.Background(), "not-json", "keyorix-dyn-x")
	require.Error(t, err)
}

func TestKubernetesEngine_RevokeInvalidatesCredential(t *testing.T) {
	e := &KubernetesEngine{}
	assert.False(t, e.RevokeInvalidatesCredential(`{"namespace":"app","service_account":"sa"}`), "default (revocable absent) is false")
	assert.False(t, e.RevokeInvalidatesCredential(`{"namespace":"app","service_account":"sa","revocable":false}`))
	assert.True(t, e.RevokeInvalidatesCredential(`{"namespace":"app","service_account":"sa","revocable":true}`))
	assert.False(t, e.RevokeInvalidatesCredential("not-json"), "a malformed config fails closed to false, never overclaims a real revoke")
}

func TestKubernetesEngine_RenewRefused(t *testing.T) {
	e := &KubernetesEngine{}
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
