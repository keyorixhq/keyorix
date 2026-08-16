package azurekms

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// TestEncodeDecodeEnvelope_RoundTrip verifies the envelope encodes and decodes symmetrically.
func TestEncodeDecodeEnvelope_RoundTrip(t *testing.T) {
	ct := []byte("fake-ciphertext")
	pt := []byte("fake-plaintext")
	blob, err := encodeEnvelope("v1", ct, pt)
	if err != nil {
		t.Fatalf("encodeEnvelope: %v", err)
	}
	env, ok, err := decodeEnvelope(blob)
	if err != nil {
		t.Fatalf("decodeEnvelope: %v", err)
	}
	if !ok {
		t.Fatal("decodeEnvelope: expected ok=true")
	}
	if env.Version != "v1" {
		t.Errorf("version: got %q, want %q", env.Version, "v1")
	}
	if string(env.Ciphertext) != string(ct) {
		t.Errorf("ciphertext: got %q, want %q", env.Ciphertext, ct)
	}
	if string(env.MAC) != string(versionMAC(pt, "v1")) {
		t.Errorf("mac: got %x, want %x", env.MAC, versionMAC(pt, "v1"))
	}
}

// TestDecodeEnvelope_NoMagicPrefix returns ok=false for a raw (legacy) blob.
func TestDecodeEnvelope_NoMagicPrefix(t *testing.T) {
	_, ok, err := decodeEnvelope([]byte("random-bytes-with-no-magic"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for a blob without the magic prefix")
	}
}

// TestDecodeEnvelope_CorruptJSON returns an error when the JSON after the magic
// prefix is malformed.
func TestDecodeEnvelope_CorruptJSON(t *testing.T) {
	blob := []byte(envelopeMagic + "{not valid json}")
	_, ok, err := decodeEnvelope(blob)
	if err == nil {
		t.Fatal("expected an error for a corrupt JSON envelope")
	}
	if ok {
		t.Fatal("expected ok=false for a corrupt envelope")
	}
}

// fakeKeysNoKID returns a WrapKey response with a nil KID so the fallback
// (no version-pinning) path inside Encrypt is exercised.
type fakeKeysNoKID struct {
	inner *fakeKeys
}

func (f *fakeKeysNoKID) WrapKey(ctx context.Context, name string, version string, params azkeys.KeyOperationParameters, opts *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	res, err := f.inner.WrapKey(ctx, name, version, params, opts)
	if err != nil {
		return azkeys.WrapKeyResponse{}, err
	}
	// Force a nil KID to trigger the "unexpected" fallback inside Encrypt.
	res.KID = nil
	return res, nil
}

func (f *fakeKeysNoKID) UnwrapKey(ctx context.Context, name string, version string, params azkeys.KeyOperationParameters, opts *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	return f.inner.UnwrapKey(ctx, name, version, params, opts)
}

// TestAzureKMS_EncryptNilKIDFallback verifies that when Azure returns a nil KID
// the result is still usable (the raw wrap output is returned, not an error).
func TestAzureKMS_EncryptNilKIDFallback(t *testing.T) {
	fk := &fakeKeys{currentVersion: "v1"}
	c := &client{keys: &fakeKeysNoKID{inner: fk}, keyName: "kek", keyVersion: ""}

	ct, err := c.Encrypt(context.Background(), []byte("kek-material"))
	if err != nil {
		t.Fatalf("Encrypt with nil KID must not error: %v", err)
	}
	// The returned blob must NOT have the version-pinning prefix (fallback path).
	_, ok, err := decodeEnvelope(ct)
	if err != nil {
		t.Fatalf("decodeEnvelope on fallback blob: %v", err)
	}
	if ok {
		t.Error("fallback blob must not have the version-pinning envelope prefix")
	}
}

// fakeKeysEmptyKIDVersion returns a WrapKey response whose KID has no version component.
type fakeKeysEmptyVersion struct{}

func (f fakeKeysEmptyVersion) WrapKey(_ context.Context, name string, version string, params azkeys.KeyOperationParameters, _ *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	// Encode the plaintext directly so Decrypt can see it.
	b, _ := json.Marshal(fakeWrapped{Version: "", Plaintext: params.Value})
	kid := azkeys.ID(fmt.Sprintf("https://vault.vault.azure.net/keys/%s/", name))
	return azkeys.WrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{KID: &kid, Result: b}}, nil
}

func (f fakeKeysEmptyVersion) UnwrapKey(_ context.Context, _ string, version string, params azkeys.KeyOperationParameters, _ *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	var w fakeWrapped
	if err := json.Unmarshal(params.Value, &w); err != nil {
		return azkeys.UnwrapKeyResponse{}, err
	}
	// Accept any version for this fake.
	return azkeys.UnwrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: w.Plaintext}}, nil
}

// TestAzureKMS_EncryptEmptyKIDVersionFallback mirrors TestAzureKMS_EncryptNilKIDFallback
// but using a KID that parses to an empty version string.
func TestAzureKMS_EncryptEmptyKIDVersionFallback(t *testing.T) {
	c := &client{keys: fakeKeysEmptyVersion{}, keyName: "kek", keyVersion: ""}
	ct, err := c.Encrypt(context.Background(), []byte("kek-material"))
	if err != nil {
		t.Fatalf("Encrypt must not error when KID version is empty: %v", err)
	}
	// A blob from the fallback path must not carry the version-pinning prefix.
	_, ok, _ := decodeEnvelope(ct)
	if ok {
		t.Error("fallback blob must not have the version-pinning envelope prefix")
	}
}

// TestAzureKMS_DecryptCorruptEnvelope verifies Decrypt returns an error when the
// envelope magic is present but the JSON body is corrupt.
func TestAzureKMS_DecryptCorruptEnvelope(t *testing.T) {
	fk := &fakeKeys{currentVersion: "v1"}
	c := newTestClient(fk, "")

	corruptBlob := []byte(envelopeMagic + "{bad json}")
	_, err := c.Decrypt(context.Background(), corruptBlob)
	if err == nil {
		t.Fatal("expected an error when the envelope is corrupt")
	}
}

// TestParseKeyID_AdditionalCases covers path forms not already tested.
func TestParseKeyID_AdditionalCases(t *testing.T) {
	// A path of exactly /keys (no name segment) must be rejected.
	_, _, _, err := parseKeyID("https://vault.vault.azure.net/keys/")
	if err == nil {
		t.Fatal("expected error for /keys/ with empty name")
	}

	// A valid URL with only two path parts (no trailing version).
	vault, name, version, err := parseKeyID("https://myvault.vault.azure.net/keys/mykey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vault != "https://myvault.vault.azure.net" {
		t.Errorf("vault: %q", vault)
	}
	if name != "mykey" {
		t.Errorf("name: %q", name)
	}
	if version != "" {
		t.Errorf("expected empty version, got %q", version)
	}
}
