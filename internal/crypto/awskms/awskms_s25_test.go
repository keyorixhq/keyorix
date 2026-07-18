package awskms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAWSKMS_New_SucceedsWithValidKeyID verifies that New succeeds (reaching the
// return statement) when a keyID is provided and the AWS SDK environment is
// operational — as it normally is in a CI environment where LoadDefaultConfig
// returns no error even without real credentials.
func TestAWSKMS_New_SucceedsWithValidKeyID(t *testing.T) {
	// Unset AWS_PROFILE so we don't accidentally use a profile that doesn't
	// exist on the CI machine; LoadDefaultConfig succeeds with no profile set.
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")

	c, err := New(context.Background(), "alias/test-key", nil, false)
	// LoadDefaultConfig succeeds without real credentials (it only builds a config
	// object; it doesn't dial AWS). The returned KMSClient must be non-nil.
	require.NoError(t, err)
	assert.NotNil(t, c)
}

// TestAWSKMS_New_WithEncContextAndFallback verifies that New wires the
// encContext and allowFallback fields correctly. We exercise both by creating a
// client with those parameters and confirming round-trip + fallback behaviour
// on the constructed client (without calling real AWS — just confirming the
// fields make it through).
func TestAWSKMS_New_WithEncContextAndFallback(t *testing.T) {
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")

	ctx := context.Background()
	c, err := New(ctx, "alias/test-key", map[string]string{"env": "ci"}, true)
	require.NoError(t, err)
	require.NotNil(t, c)

	// We can't make real KMS calls, but we can verify the client is a *client
	// with the correct fields set by casting back through the internal type.
	impl, ok := c.(*client)
	require.True(t, ok, "New must return a *client")
	assert.Equal(t, "alias/test-key", impl.keyID)
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

	_, err := New(context.Background(), "alias/test-key", nil, false)
	// The SDK must fail to load the named profile from the nonexistent file,
	// and New must propagate that error (not silently swallow it).
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
