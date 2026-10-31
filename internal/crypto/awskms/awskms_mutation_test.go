package awskms

// Tests added for the gremlins survivors on internal/crypto/awskms (#3612,
// MUTANT-CRYPTO-1). Each pins an exact boundary rather than "no error".

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateAWSEnv makes the SDK's default config chain hermetic: static dummy
// credentials, a fixed region, no shared files, no IMDS.
func isolateAWSEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent/awskms-test-config.ini")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/awskms-test-creds")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

// describeKeyServer is a loopback stand-in for the KMS endpoint that answers
// every call (DescribeKey) with the given ARN. No traffic leaves the machine.
func describeKeyServer(t *testing.T, arn string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"KeyMetadata":{"Arn":"` + arn + `"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// awskms.go:62 and :66 — the happy path of New: a non-empty key id is accepted
// and the default config loads. The error text distinguishes which guard fired.
func TestNew_SuccessResolvesKeyThroughEndpoint(t *testing.T) {
	skipUnderFIPS140Only(t, "the fixture signs with AWS_SECRET_ACCESS_KEY='secret'; SigV4 keys HMAC with 'AWS4'+secret (10 bytes), under the 112-bit minimum. Real AWS secret keys are 40 characters")
	isolateAWSEnv(t)
	const arn = "arn:aws:kms:us-east-1:123456789012:key/from-describe-key"
	t.Setenv("AWS_ENDPOINT_URL", describeKeyServer(t, arn).URL)

	got, err := New(context.Background(), "alias/test-key", map[string]string{"a": "b"}, true, nil)
	require.NoError(t, err)
	c, ok := got.(*client)
	require.True(t, ok)
	assert.Equal(t, arn, c.keyID, "the resolved ARN, never the alias, is pinned")
	assert.Equal(t, map[string]string{"a": "b"}, c.encCtx)
	assert.True(t, c.allowFallback)
}

// awskms.go:62 — an empty key id is refused before any config/endpoint work, so
// it fails with the key-id message even when an endpoint is reachable.
func TestNew_EmptyKeyIDRefusedBeforeAnyLookup(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("AWS_ENDPOINT_URL", describeKeyServer(t, "arn:aws:kms:us-east-1:1:key/x").URL)

	c, err := New(context.Background(), "", nil, false, nil)
	require.Error(t, err)
	assert.Nil(t, c)
	assert.EqualError(t, err, "aws-kms: kms_key_id is required")
}

// awskms.go:66 — a config load failure is reported as such (not as a later
// DescribeKey failure) and yields no client.
func TestNew_LoadConfigFailureIsWrappedAndNamed(t *testing.T) {
	t.Setenv("AWS_PROFILE", "keyorix-nonexistent-profile-for-test-only")
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent/awskms-test-config.ini")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/awskms-test-creds")

	c, err := New(context.Background(), "alias/test-key", nil, false, nil)
	require.Error(t, err)
	assert.Nil(t, c)
	assert.ErrorContains(t, err, "aws-kms: load AWS config:")
	assert.NotContains(t, err.Error(), "resolve key ARN")
}

// emptyCtxKMS records the inputs the client built.
type emptyCtxKMS struct {
	fakeKMS
	encIn *kms.EncryptInput
	decIn []*kms.DecryptInput
}

func (f *emptyCtxKMS) Encrypt(ctx context.Context, in *kms.EncryptInput, o ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	f.encIn = in
	return f.fakeKMS.Encrypt(ctx, in, o...)
}

func (f *emptyCtxKMS) Decrypt(ctx context.Context, in *kms.DecryptInput, o ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.decIn = append(f.decIn, in)
	return f.fakeKMS.Decrypt(ctx, in, o...)
}

// awskms.go:107 and :144 — an empty (but non-nil) context is "no context": the
// request must carry a nil EncryptionContext, not an empty map that AWS would
// treat as a (different) bound context. The constructor preserves non-nil-ness
// (maps.Clone), so the empty-map input is reachable from config.
func TestEncryptDecrypt_EmptyContextSendsNilEncryptionContext(t *testing.T) {
	for name, encCtx := range map[string]map[string]string{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			f := &emptyCtxKMS{}
			got, err := newClient(context.Background(), f, "k", encCtx, false, nil)
			require.NoError(t, err)

			ct, err := got.Encrypt(context.Background(), []byte("kek"))
			require.NoError(t, err)
			require.NotNil(t, f.encIn)
			assert.Nil(t, f.encIn.EncryptionContext)

			_, err = got.Decrypt(context.Background(), ct)
			require.NoError(t, err)
			require.Len(t, f.decIn, 1)
			assert.Nil(t, f.decIn[0].EncryptionContext)
		})
	}
}

func TestEncryptDecrypt_NonEmptyContextIsSent(t *testing.T) {
	f := &emptyCtxKMS{}
	got, err := newClient(context.Background(), f, "k", map[string]string{"a": "b"}, false, nil)
	require.NoError(t, err)
	ct, err := got.Encrypt(context.Background(), []byte("kek"))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"a": "b"}, f.encIn.EncryptionContext)
	_, err = got.Decrypt(context.Background(), ct)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"a": "b"}, f.decIn[0].EncryptionContext)
}

// awskms.go:137 — the no-context retry needs BOTH the flag and a configured
// context.
func TestContextFallbackEnabled_NeedsFlagAndContext(t *testing.T) {
	cases := []struct {
		name  string
		ctx   map[string]string
		allow bool
		want  bool
	}{
		{"flag without context", nil, true, false},
		{"flag with empty context", map[string]string{}, true, false},
		{"context without flag", map[string]string{"a": "b"}, false, false},
		{"neither", nil, false, false},
		{"flag and context", map[string]string{"a": "b"}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &client{kms: fakeKMS{}, keyID: "k", encCtx: tc.ctx, allowFallback: tc.allow}
			assert.Equal(t, tc.want, c.ContextFallbackEnabled())
		})
	}
}

// With the flag but no context there is nothing to fall back from: a Decrypt
// failure is returned after ONE call, not retried.
func TestDecrypt_FlagWithoutContext_DoesNotRetry(t *testing.T) {
	f := &emptyCtxKMS{}
	c := &client{kms: f, keyID: "k", allowFallback: true}
	_, err := c.Decrypt(context.Background(), []byte("not-a-blob"))
	require.Error(t, err)
	assert.Len(t, f.decIn, 1)
}
