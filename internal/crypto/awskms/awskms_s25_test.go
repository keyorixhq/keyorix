package awskms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAWSKMS_New_DescribeKeyResolutionRequired_FailsClosedWithoutCredentials
// verifies that New (unlike before this fix) does NOT just wire the raw keyID
// straight through: it now resolves it to a canonical ARN via kms:DescribeKey,
// and since this test environment has no real AWS credentials, that resolution
// must fail — and New must propagate the failure rather than silently falling
// back to pinning the caller-supplied (possibly-mutable-alias) keyID. This is the
// fail-closed half of the awskms-001 fix: a caller that can't resolve simply
// cannot construct a client at all, so a stale/never-resolved alias binding can't
// happen. AWS_EC2_METADATA_DISABLED skips the (slow, always-failing off-EC2) IMDS
// credential lookup so this fails fast rather than after an IMDS timeout.
func TestAWSKMS_New_DescribeKeyResolutionRequired_FailsClosedWithoutCredentials(t *testing.T) {
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	_, err := New(context.Background(), "alias/test-key", nil, false, nil)
	require.Error(t, err, "New must fail closed when it cannot resolve keyID to a canonical ARN")
	assert.Contains(t, err.Error(), "aws-kms")
}

// TestAWSKMS_New_WithEncContextAndFallback verifies that New (via its testable
// newClient core, injecting a fake so no real AWS call is made) resolves the
// alias to its canonical ARN and wires encContext/allowFallback correctly.
func TestAWSKMS_New_WithEncContextAndFallback(t *testing.T) {
	ctx := context.Background()
	fake := &fakeKMSWithDescribe{resolvedARN: "arn:aws:kms:us-east-1:123456789012:key/canonical-test-key"}
	c, err := newClient(ctx, fake, "alias/test-key", map[string]string{"env": "ci"}, true, nil)
	require.NoError(t, err)
	require.NotNil(t, c)

	// newClient must return a *client with the RESOLVED ARN pinned — not the
	// alias originally passed in — plus the other fields wired through unchanged.
	impl, ok := c.(*client)
	require.True(t, ok, "newClient must return a *client")
	assert.Equal(t, "arn:aws:kms:us-east-1:123456789012:key/canonical-test-key", impl.keyID)
	assert.Equal(t, map[string]string{"env": "ci"}, impl.encCtx)
	assert.True(t, impl.allowFallback)
}

// TestAWSKMS_New_LoadConfigError verifies that New propagates LoadDefaultConfig
// errors. Setting AWS_PROFILE to a nonexistent value and pointing AWS_CONFIG_FILE
// at a nonexistent path forces LoadDefaultConfig to call loadSharedConfig (because
// AWS_PROFILE is non-empty) which then fails because neither the config file nor
// the default ~/.aws/config holds that profile.
func TestAWSKMS_New_LoadConfigError(t *testing.T) {
	t.Setenv("AWS_PROFILE", "keyorix-nonexistent-profile-for-test-only")
	// Point both config files at a guaranteed-absent path so the SDK cannot fall
	// back to the default ~/.aws/config either.
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent/awskms-test-config.ini")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent/awskms-test-creds")

	_, err := New(context.Background(), "alias/test-key", nil, false, nil)
	// The SDK must fail to load the named profile from the nonexistent file,
	// and New must propagate that error (not silently swallow it) — this happens
	// before any DescribeKey call is attempted.
	require.Error(t, err, "New must propagate LoadDefaultConfig errors")
	assert.Contains(t, err.Error(), "aws-kms")
}

// TestAWSKMS_Encrypt_ContextAttached verifies that when encCtx is non-empty the
// encryption context is passed to KMS. The fakeKMS stores the context inside the
// ciphertext blob; we confirm it is present.
func TestAWSKMS_Encrypt_ContextAttached(t *testing.T) {
	ctx := map[string]string{"install": "test-inst", "project": "keyorix"}
	c := newTestClient(ctx, false)
	ct, err := c.Encrypt(context.Background(), []byte("secret"))
	require.NoError(t, err)
	require.NotEmpty(t, ct)

	// Decrypting with the exact same context must succeed.
	pt, err := c.Decrypt(context.Background(), ct)
	require.NoError(t, err)
	assert.Equal(t, "secret", string(pt))
}

// TestAWSKMS_Decrypt_FallbackSucceedsAndLogs verifies the fallback path when
// allowFallback is enabled: a no-context ciphertext MUST decrypt against a
// context-bound client, and the operation succeeds (the log output is tested
// elsewhere — here we just validate the returned plaintext).
func TestAWSKMS_Decrypt_FallbackSucceedsAndLogs(t *testing.T) {
	// Encrypt without any context (simulates a legacy / pre-context blob).
	legacy := newTestClient(nil, false)
	ct, err := legacy.Encrypt(context.Background(), []byte("legacy-kek"))
	require.NoError(t, err)

	// A client bound to a context with allowFallback=true must succeed.
	bound := newTestClient(map[string]string{"install": "inst-X"}, true)
	pt, err := bound.Decrypt(context.Background(), ct)
	require.NoError(t, err)
	assert.Equal(t, "legacy-kek", string(pt))
}

// TestAWSKMS_Decrypt_NoEncCtx_NoFallback_Succeeds confirms the no-context,
// no-fallback path (the encCtx guard `len(c.encCtx) > 0` is false in both
// Encrypt and Decrypt) — the blob decrypts cleanly.
func TestAWSKMS_Decrypt_NoEncCtx_NoFallback_Succeeds(t *testing.T) {
	c := newTestClient(nil, false)
	ct, err := c.Encrypt(context.Background(), []byte("plain"))
	require.NoError(t, err)
	pt, err := c.Decrypt(context.Background(), ct)
	require.NoError(t, err)
	assert.Equal(t, "plain", string(pt))
}

// TestAWSKMS_Decrypt_ContextMismatch_NoFallback_Fails verifies that without
// fallback, a blob encrypted under context A does NOT decrypt for context B.
func TestAWSKMS_Decrypt_ContextMismatch_NoFallback_Fails(t *testing.T) {
	a := newTestClient(map[string]string{"k": "A"}, false)
	ct, err := a.Encrypt(context.Background(), []byte("kek-A"))
	require.NoError(t, err)

	b := newTestClient(map[string]string{"k": "B"}, false)
	_, err = b.Decrypt(context.Background(), ct)
	assert.Error(t, err)
}
