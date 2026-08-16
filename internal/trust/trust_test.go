package trust

import (
	"crypto/ed25519"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistry_VerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKey()
	require.NoError(t, err)

	r := NewRegistry()
	require.NoError(t, r.Add(PurposeUpdate, "upd-1", pub))

	msg := []byte("manifest bytes")
	sig := ed25519.Sign(priv, msg)
	require.NoError(t, r.Verify(PurposeUpdate, "upd-1", msg, sig))
}

func TestRegistry_FailsClosed(t *testing.T) {
	pub, priv, err := GenerateKey()
	require.NoError(t, err)
	r := NewRegistry()
	require.NoError(t, r.Add(PurposeUpdate, "upd-1", pub))
	msg := []byte("payload")
	sig := ed25519.Sign(priv, msg)

	// No keys for the license purpose at all.
	assert.ErrorIs(t, r.Verify(PurposeLicense, "upd-1", msg, sig), ErrNoKeys)
	// Right purpose, unknown key-id.
	assert.ErrorIs(t, r.Verify(PurposeUpdate, "nope", msg, sig), ErrUnknownKey)
	// Right key, tampered message.
	assert.ErrorIs(t, r.Verify(PurposeUpdate, "upd-1", []byte("tampered"), sig), ErrBadSignature)

	// A different key's signature must not verify against the trusted key.
	_, otherPriv, _ := GenerateKey()
	assert.ErrorIs(t, r.Verify(PurposeUpdate, "upd-1", msg, ed25519.Sign(otherPriv, msg)), ErrBadSignature)
}

func TestRegistry_AddRejectsBadKey(t *testing.T) {
	r := NewRegistry()
	assert.Error(t, r.Add(PurposeUpdate, "k", ed25519.PublicKey([]byte("too short"))))
	pub, _, _ := GenerateKey()
	assert.Error(t, r.Add(PurposeUpdate, "", pub), "empty key-id is rejected")
}

// TestRegistry_AddRejectsKeyReuseAcrossPurposes is the regression test for the documented
// "independent blast radii" guarantee (see the Purpose doc comment): registering the SAME
// ed25519 public key under both PurposeUpdate and PurposeLicense must be refused, because
// without this check a signature valid for one purpose would trivially verify as valid for
// the other too (ed25519 signatures carry no purpose tag of their own).
func TestRegistry_AddRejectsKeyReuseAcrossPurposes(t *testing.T) {
	pub, priv, err := GenerateKey()
	require.NoError(t, err)

	r := NewRegistry()
	require.NoError(t, r.Add(PurposeUpdate, "upd-1", pub))

	// Registering the identical key under a different purpose must be refused.
	err = r.Add(PurposeLicense, "lic-1", pub)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyReusedAcrossPurposes)

	// The registry must not have been mutated by the rejected Add: the license purpose
	// still has no trusted keys at all.
	assert.Empty(t, r.KeyIDs(PurposeLicense))

	// And critically: a signature produced under the update purpose must still fail to
	// verify against the license purpose, because the key was never actually registered
	// there — the exploit this guards against (a cross-purpose signature verifying) never
	// gets the chance to occur.
	msg := []byte("update manifest bytes")
	sig := ed25519.Sign(priv, msg)
	require.NoError(t, r.Verify(PurposeUpdate, "upd-1", msg, sig))
	assert.ErrorIs(t, r.Verify(PurposeLicense, "lic-1", msg, sig), ErrNoKeys)
}

// TestRegistry_AddAllowsSameKeySameePurposeDifferentKeyID confirms the reuse check is scoped
// to cross-PURPOSE reuse only — re-registering the same key under the SAME purpose (e.g. for
// key-id rotation bookkeeping) must still work.
func TestRegistry_AddAllowsSameKeySamePurposeDifferentKeyID(t *testing.T) {
	pub, _, err := GenerateKey()
	require.NoError(t, err)

	r := NewRegistry()
	require.NoError(t, r.Add(PurposeUpdate, "upd-old", pub))
	require.NoError(t, r.Add(PurposeUpdate, "upd-new", pub))
	assert.ElementsMatch(t, []string{"upd-new", "upd-old"}, r.KeyIDs(PurposeUpdate))
}

// TestRegistry_AddLegitimateSinglePurposeUseStillWorks confirms the ordinary, non-reused case
// — a key registered and used consistently for exactly ONE purpose — is unaffected.
func TestRegistry_AddLegitimateSinglePurposeUseStillWorks(t *testing.T) {
	pub, priv, err := GenerateKey()
	require.NoError(t, err)

	r := NewRegistry()
	require.NoError(t, r.Add(PurposeLicense, "lic-2026", pub))

	msg := []byte("license payload")
	sig := ed25519.Sign(priv, msg)
	assert.NoError(t, r.Verify(PurposeLicense, "lic-2026", msg, sig))
}

func TestRegistry_KeyIDsSorted(t *testing.T) {
	pub, _, _ := GenerateKey()
	r := NewRegistry()
	require.NoError(t, r.Add(PurposeUpdate, "b", pub))
	require.NoError(t, r.Add(PurposeUpdate, "a", pub))
	assert.Equal(t, []string{"a", "b"}, r.KeyIDs(PurposeUpdate))
	assert.Empty(t, r.KeyIDs(PurposeLicense))
}

func TestParseKeySpec(t *testing.T) {
	pub, _, _ := GenerateKey()
	spec := "k1=" + EncodePublicKeyBase64(pub)

	parsed, err := parseKeySpec(spec)
	require.NoError(t, err)
	require.Contains(t, parsed, "k1")
	assert.Equal(t, []byte(pub), []byte(parsed["k1"]))

	// Empty spec → empty map (no trust), not an error.
	empty, err := parseKeySpec("")
	require.NoError(t, err)
	assert.Empty(t, empty)

	// Malformed specs are rejected.
	_, err = parseKeySpec("no-equals-sign")
	assert.Error(t, err)
	_, err = parseKeySpec("k=not-base64!!")
	assert.Error(t, err)
	_, err = parseKeySpec("k=YWJj") // valid base64 but wrong key size
	assert.Error(t, err)
}

func TestDefaultRegistry_EmptyByDefaultFailsClosed(t *testing.T) {
	// With no keys embedded (the default in a non-release build), the registry trusts
	// nothing and verification fails closed.
	r, err := DefaultRegistry()
	require.NoError(t, err)
	assert.ErrorIs(t, r.Verify(PurposeUpdate, "any", []byte("m"), []byte("s")), ErrNoKeys)
	assert.ErrorIs(t, r.Verify(PurposeLicense, "any", []byte("m"), []byte("s")), ErrNoKeys)
}

// TestRegistry_ConcurrentAddAndVerify_NoRace is #G63: KeyRegistry.keys is a
// plain map read by Verify/KeyIDs and written by Add, with no synchronization
// of its own before this fix — a future runtime key-rotation caller (this
// package's own doc comment: "the bundle/license phases build on it") racing
// a concurrent verification is a real, unsynchronized map access under
// `go test -race`, not just a theoretical one.
func TestRegistry_ConcurrentAddAndVerify_NoRace(t *testing.T) {
	r := NewRegistry()
	pub, priv, err := GenerateKey()
	require.NoError(t, err)
	msg := []byte("manifest bytes")
	sig := ed25519.Sign(priv, msg)

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			keyID := "key"
			if i%2 == 0 {
				keyID = "other-key"
			}
			_ = r.Add(PurposeUpdate, keyID, pub)
		}(i)
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = r.Verify(PurposeUpdate, "key", msg, sig)
			_ = r.KeyIDs(PurposeUpdate)
		}()
	}
	close(start)
	wg.Wait()
}
