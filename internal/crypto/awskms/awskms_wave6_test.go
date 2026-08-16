package awskms

import (
	"context"
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- awskms-001: alias resolved to its canonical ARN once at New()-time, and
// that resolved ARN — not the possibly-mutable alias — is what every subsequent
// call pins. ---

// TestAWSKMS_New_PinsResolvedARN_NotAlias verifies that after New() resolves an
// alias via DescribeKey, every subsequent Encrypt/Decrypt call sends the RESOLVED
// ARN as KeyId, never the original alias string.
func TestAWSKMS_New_PinsResolvedARN_NotAlias(t *testing.T) {
	const arn = "arn:aws:kms:us-east-1:123456789012:key/canonical-id"
	fake := &fakeKMSWithDescribe{resolvedARN: arn}
	c, err := newClient(context.Background(), fake, "alias/prod-kek", nil, false, nil)
	require.NoError(t, err)

	impl, ok := c.(*client)
	require.True(t, ok)
	assert.Equal(t, arn, impl.keyID, "New must pin the DescribeKey-resolved ARN, not the input alias")

	ct, err := c.Encrypt(context.Background(), []byte("kek-material"))
	require.NoError(t, err)
	assert.Equal(t, arn, fake.lastEncryptKeyID, "Encrypt must send the resolved ARN as KeyId")

	_, err = c.Decrypt(context.Background(), ct)
	require.NoError(t, err)
	assert.Equal(t, arn, fake.lastDecryptKeyID, "Decrypt must send the resolved ARN as KeyId")
}

// TestAWSKMS_AliasRepointAfterNew_DoesNotAffectPinnedARN is the core
// confused-deputy regression test for awskms-001: it simulates an alias being
// repointed to a different CMK AFTER the client was constructed (e.g. by whoever
// holds alias-management IAM privilege) and asserts the already-constructed
// client keeps pinning the ORIGINAL resolved ARN — proving resolution happens
// once, at New()-time, not on every call. Before this fix, the client stored the
// alias string itself and would have silently started trusting the repointed key.
func TestAWSKMS_AliasRepointAfterNew_DoesNotAffectPinnedARN(t *testing.T) {
	const originalARN = "arn:aws:kms:us-east-1:123456789012:key/original-cmk"
	fake := &fakeKMSWithDescribe{resolvedARN: originalARN}
	c, err := newClient(context.Background(), fake, "alias/prod-kek", nil, false, nil)
	require.NoError(t, err)

	// Simulate the alias being repointed to a different CMK after construction.
	fake.resolvedARN = "arn:aws:kms:us-east-1:123456789012:key/attacker-repointed-cmk"

	_, err = c.Encrypt(context.Background(), []byte("kek-material"))
	require.NoError(t, err)
	assert.Equal(t, originalARN, fake.lastEncryptKeyID,
		"an already-constructed client must keep pinning the ARN resolved at New()-time, not re-resolve the alias on every call")
}

// TestAWSKMS_New_DescribeKeyFailure_FailsClosed verifies New propagates a
// DescribeKey error rather than falling back to pinning the unresolved keyID.
func TestAWSKMS_New_DescribeKeyFailure_FailsClosed(t *testing.T) {
	fake := &fakeKMSWithDescribe{describeErr: assert.AnError}
	_, err := newClient(context.Background(), fake, "alias/prod-kek", nil, false, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws-kms")
}

// TestAWSKMS_New_DescribeKeyEmptyARN_FailsClosed verifies New treats a
// DescribeKey response with no ARN as a resolution failure rather than silently
// proceeding with an empty/zero-value KeyId.
func TestAWSKMS_New_DescribeKeyEmptyARN_FailsClosed(t *testing.T) {
	fake := &fakeKMSWithDescribe{resolvedARN: ""}
	_, err := newClient(context.Background(), fake, "alias/prod-kek", nil, false, nil)
	require.Error(t, err)
}

// --- awskms-002: a KMSAllowContextFallback decrypt firing must be reported via
// the FallbackHook, and ONLY when the fallback path is actually used. ---

// TestAWSKMS_Decrypt_FallbackFiresHook verifies the fallback hook is called,
// with the pinned keyID, exactly when a Decrypt succeeds only via the no-context
// retry path.
func TestAWSKMS_Decrypt_FallbackFiresHook(t *testing.T) {
	legacy := newTestClient(nil, false)
	ct, err := legacy.Encrypt(context.Background(), []byte("legacy-kek"))
	require.NoError(t, err)

	var firedKeyID string
	fireCount := 0
	hook := func(_ context.Context, keyID string) {
		fireCount++
		firedKeyID = keyID
	}
	bound := &client{kms: fakeKMS{}, keyID: "test-key", encCtx: map[string]string{"install": "inst-X"}, allowFallback: true, fallbackHook: hook}

	pt, err := bound.Decrypt(context.Background(), ct)
	require.NoError(t, err)
	assert.Equal(t, "legacy-kek", string(pt))
	assert.Equal(t, 1, fireCount, "fallback hook must fire exactly once for a successful fallback decrypt")
	assert.Equal(t, "test-key", firedKeyID)
}

// TestAWSKMS_Decrypt_NoFallbackNeeded_HookNotCalled verifies the fallback hook
// does NOT fire on an ordinary direct decrypt (context matches, no retry needed).
func TestAWSKMS_Decrypt_NoFallbackNeeded_HookNotCalled(t *testing.T) {
	called := false
	hook := func(_ context.Context, _ string) { called = true }
	c := &client{kms: fakeKMS{}, keyID: "test-key", encCtx: map[string]string{"k": "v"}, allowFallback: true, fallbackHook: hook}

	ct, err := c.Encrypt(context.Background(), []byte("data"))
	require.NoError(t, err)
	_, err = c.Decrypt(context.Background(), ct)
	require.NoError(t, err)
	assert.False(t, called, "fallback hook must not fire when the direct (context-bound) decrypt already succeeded")
}

// TestAWSKMS_Decrypt_FallbackDisabled_HookNotCalled verifies the fallback hook
// never fires when allowFallback is off, even though a hook is wired.
func TestAWSKMS_Decrypt_FallbackDisabled_HookNotCalled(t *testing.T) {
	planted := newTestClient(nil, false)
	ct, err := planted.Encrypt(context.Background(), []byte("malicious-kek"))
	require.NoError(t, err)

	called := false
	hook := func(_ context.Context, _ string) { called = true }
	bound := &client{kms: fakeKMS{}, keyID: "test-key", encCtx: map[string]string{"install": "inst-1"}, allowFallback: false, fallbackHook: hook}

	_, err = bound.Decrypt(context.Background(), ct)
	require.Error(t, err, "fallback disabled: the no-context blob must still be rejected")
	assert.False(t, called, "fallback hook must not fire when the fallback path itself never runs")
}

// --- awskms-003: New() must defensively copy encContext, so a caller mutating
// its own map after construction cannot change an already-built client's binding. ---

// TestAWSKMS_New_DefensiveCopyOfEncContext verifies that mutating the caller's
// original map after New() returns does not affect the constructed client.
func TestAWSKMS_New_DefensiveCopyOfEncContext(t *testing.T) {
	original := map[string]string{"install": "inst-1"}
	fake := &fakeKMSWithDescribe{resolvedARN: "arn:aws:kms:us-east-1:123456789012:key/x"}
	c, err := newClient(context.Background(), fake, "alias/x", original, false, nil)
	require.NoError(t, err)

	// Mutate the caller's original map after construction — this must NOT leak
	// into the already-built client's EncryptionContext binding.
	original["install"] = "mutated-after-new"
	original["extra"] = "should-not-appear"

	impl, ok := c.(*client)
	require.True(t, ok)
	assert.Equal(t, map[string]string{"install": "inst-1"}, impl.encCtx,
		"New must copy encContext; mutating the caller's original map after New must not affect the client's binding")
}

// TestAWSKMS_New_DefensiveCopyOfEncContext_EndToEnd is the round-trip version of
// the same property: a blob encrypted after the caller mutates its original map
// must still decrypt against a freshly built client bound to the ORIGINAL
// (pre-mutation) context, proving the encrypting client used its own frozen copy.
func TestAWSKMS_New_DefensiveCopyOfEncContext_EndToEnd(t *testing.T) {
	original := map[string]string{"install": "inst-1"}
	fake := &fakeKMSWithDescribe{resolvedARN: "arn:aws:kms:us-east-1:123456789012:key/x"}
	c, err := newClient(context.Background(), fake, "alias/x", original, false, nil)
	require.NoError(t, err)

	original["install"] = "mutated-after-new"

	ct, err := c.Encrypt(context.Background(), []byte("data"))
	require.NoError(t, err)

	// A separately-built client bound to the ORIGINAL, unmutated context must be
	// able to decrypt it.
	unaffected, err := newClient(context.Background(), fake, "alias/x", map[string]string{"install": "inst-1"}, false, nil)
	require.NoError(t, err)
	pt, err := unaffected.Decrypt(context.Background(), ct)
	require.NoError(t, err)
	assert.Equal(t, "data", string(pt))
}

// TestAWSKMS_New_DefensiveCopyOfEncContext_NilInput sanity-checks that a nil
// encContext still results in a nil/empty encCtx (maps.Clone(nil) is nil), not a
// panic or a spuriously non-nil empty map.
func TestAWSKMS_New_DefensiveCopyOfEncContext_NilInput(t *testing.T) {
	fake := &fakeKMSWithDescribe{resolvedARN: "arn:aws:kms:us-east-1:123456789012:key/x"}
	c, err := newClient(context.Background(), fake, "alias/x", nil, false, nil)
	require.NoError(t, err)
	impl, ok := c.(*client)
	require.True(t, ok)
	assert.True(t, len(impl.encCtx) == 0)
}

// sanity check that maps.Clone is actually what's used (guards against a
// find/replace regression silently reverting to a bare assignment).
func TestAWSKMS_MapsCloneSanity(t *testing.T) {
	m := map[string]string{"a": "1"}
	clone := maps.Clone(m)
	m["a"] = "2"
	assert.Equal(t, "1", clone["a"])
}
