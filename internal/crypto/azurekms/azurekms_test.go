package azurekms

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeKeys models Azure Key Vault's WrapKey/UnwrapKey semantics closely enough
// to exercise rotation: each version has distinct key material, so a blob
// wrapped under version A can only be unwrapped by requesting version A
// specifically — requesting "" (current) or a different version fails once
// "current" no longer points at A. currentVersion mutates to simulate rotation.
type fakeKeys struct {
	currentVersion string
}

type fakeWrapped struct {
	Version   string `json:"version"`
	Plaintext []byte `json:"plaintext"`
}

func (f *fakeKeys) resolve(version string) string {
	if version == "" {
		return f.currentVersion
	}
	return version
}

func (f *fakeKeys) WrapKey(_ context.Context, name string, version string, params azkeys.KeyOperationParameters, _ *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	v := f.resolve(version)
	body, err := json.Marshal(fakeWrapped{Version: v, Plaintext: params.Value})
	if err != nil {
		return azkeys.WrapKeyResponse{}, err
	}
	kid := azkeys.ID(fmt.Sprintf("https://vault.vault.azure.net/keys/%s/%s", name, v))
	return azkeys.WrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{KID: &kid, Result: body}}, nil
}

func (f *fakeKeys) UnwrapKey(_ context.Context, _ string, version string, params azkeys.KeyOperationParameters, _ *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	v := f.resolve(version)
	var w fakeWrapped
	if err := json.Unmarshal(params.Value, &w); err != nil {
		return azkeys.UnwrapKeyResponse{}, err
	}
	if w.Version != v {
		return azkeys.UnwrapKeyResponse{}, fmt.Errorf("fake unwrap: blob wrapped under version %q, request targeted %q (key rotated?)", w.Version, v)
	}
	return azkeys.UnwrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: w.Plaintext}}, nil
}

func newTestClient(keys *fakeKeys, keyVersion string) *client {
	return &client{keys: keys, keyName: "kek", keyVersion: keyVersion}
}

func TestAzureKMS_EncryptPinsVersionAndSurvivesRotation(t *testing.T) {
	fk := &fakeKeys{currentVersion: "v1"}
	c := newTestClient(fk, "") // unversioned kms_key_id — the documented default usage

	ct, err := c.Encrypt(context.Background(), []byte("kek-material"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Simulate Azure's own recommended auto-rotation policy advancing "current"
	// to a new version between the Encrypt call and the next server restart.
	fk.currentVersion = "v2"

	pt, err := c.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("decrypt must target the pinned version (v1), survived rotation to v2: %v", err)
	}
	if string(pt) != "kek-material" {
		t.Fatalf("round-trip got %q", pt)
	}
}

func TestAzureKMS_WithoutPinningWouldFailAfterRotation(t *testing.T) {
	// Sanity check that the fake actually models rotation breakage — i.e. that
	// the previous (unpinned) behavior really would have broken, so the pinning
	// fix in the test above is meaningfully exercised.
	fk := &fakeKeys{currentVersion: "v1"}
	res, err := fk.WrapKey(context.Background(), "kek", "", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(wrapAlgorithm),
		Value:     []byte("kek-material"),
	}, nil)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	fk.currentVersion = "v2"
	if _, err := fk.UnwrapKey(context.Background(), "kek", "", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(wrapAlgorithm),
		Value:     res.Result,
	}, nil); err == nil {
		t.Fatal("expected unwrap targeting \"current\" after rotation to fail against a pre-rotation blob")
	}
}

func TestAzureKMS_LegacyUnpinnedBlobStillDecrypts(t *testing.T) {
	// Legacy data: wrapped by the pre-fix Encrypt, which returned the raw wrap
	// result with no version-pinning envelope. As long as the key has not been
	// rotated since, it must still decrypt via the old "current"/configured-
	// version resolution.
	fk := &fakeKeys{currentVersion: "v1"}
	legacy, err := fk.WrapKey(context.Background(), "kek", "", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(wrapAlgorithm),
		Value:     []byte("legacy-kek"),
	}, nil)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	c := newTestClient(fk, "") // unversioned config, matching the legacy deployment
	pt, err := c.Decrypt(context.Background(), legacy.Result)
	if err != nil {
		t.Fatalf("legacy unpinned blob must still decrypt: %v", err)
	}
	if string(pt) != "legacy-kek" {
		t.Fatalf("got %q", pt)
	}
}

func TestAzureKMS_LegacyExplicitlyVersionedBlobStillDecrypts(t *testing.T) {
	// A pre-fix deployment that had already worked around this class of issue by
	// pinning kms_key_id itself to an explicit version must be unaffected.
	fk := &fakeKeys{currentVersion: "v3"}
	legacy, err := fk.WrapKey(context.Background(), "kek", "v3", azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(wrapAlgorithm),
		Value:     []byte("legacy-kek"),
	}, nil)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	c := newTestClient(fk, "v3")
	pt, err := c.Decrypt(context.Background(), legacy.Result)
	if err != nil {
		t.Fatalf("legacy explicitly-versioned blob must still decrypt: %v", err)
	}
	if string(pt) != "legacy-kek" {
		t.Fatalf("got %q", pt)
	}
}

func TestAzureKMS_EncryptDecryptRoundTrip(t *testing.T) {
	fk := &fakeKeys{currentVersion: "v1"}
	c := newTestClient(fk, "")
	ct, err := c.Encrypt(context.Background(), []byte("hello"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := c.Decrypt(context.Background(), ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(pt) != "hello" {
		t.Fatalf("got %q", pt)
	}
}

// TestValidateKeyVaultHost is the G48 regression for the "never validated at
// all" half of the finding: before this fix, kms_key_id's host was not
// checked against anything — a redirected or misconfigured value could send
// DefaultAzureCredential's live bearer token anywhere. Covers the
// detection_idea's explicit ask: a non-Azure-Key-Vault host must be rejected
// outright, in addition to scheme and the recognized sovereign-cloud domains.
func TestValidateKeyVaultHost(t *testing.T) {
	tests := []struct {
		name     string
		vaultURL string
		wantErr  bool
		errMatch string
	}{
		{name: "public cloud", vaultURL: "https://myvault.vault.azure.net"},
		{name: "china sovereign cloud", vaultURL: "https://myvault.vault.azure.cn"},
		{name: "us gov sovereign cloud", vaultURL: "https://myvault.vault.usgovcloudapi.net"},
		{name: "germany sovereign cloud (legacy)", vaultURL: "https://myvault.vault.microsoftazure.de"},
		{name: "managed hsm", vaultURL: "https://myhsm.managedhsm.azure.net"},
		{
			name: "non-Key-Vault host is rejected outright", vaultURL: "https://attacker.example",
			wantErr: true, errMatch: "not a recognized Azure Key Vault",
		},
		{
			name:     "a host merely containing the suffix as a substring is rejected",
			vaultURL: "https://vault.azure.net.attacker.example", wantErr: true,
			errMatch: "not a recognized Azure Key Vault",
		},
		{
			name:     "http scheme is rejected even for an otherwise-valid host",
			vaultURL: "http://myvault.vault.azure.net", wantErr: true,
			errMatch: "must use https",
		},
		{name: "bare suffix with no vault name is rejected", vaultURL: "https://vault.azure.net", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeyVaultHost(tt.vaultURL)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMatch != "" {
					assert.Contains(t, err.Error(), tt.errMatch)
				}
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestAzureKMSTransport_DialTimeRefusesPrivateAddress is the G48 regression
// for the dial-time half of the fix: azureKMSTransport must re-resolve and
// refuse a private/link-local address at actual connection time, not just
// rely on validateKeyVaultHost's construction-time string check (which
// performs no DNS resolution at all, so it can't itself catch a hostname
// that merely resolves to an internal address). This is the property that
// stops a DNS-rebinding attacker: even a hostname that LOOKS like a
// legitimate Key Vault endpoint must not be dialed if it resolves to an
// internal address.
func TestAzureKMSTransport_DialTimeRefusesPrivateAddress(t *testing.T) {
	origResolve := azureKMSResolve
	defer func() { azureKMSResolve = origResolve }()

	azureKMSResolve = func(_ context.Context, host string) ([]net.IPAddr, error) {
		require.Equal(t, "rebind.vault.azure.net", host)
		return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
	}

	tr, ok := azureKMSTransport.Transport.(*http.Transport)
	require.True(t, ok)
	_, err := tr.DialContext(context.Background(), "tcp", "rebind.vault.azure.net:443")
	require.Error(t, err, "a Key Vault hostname resolving to a private/link-local address must be refused at dial time")
	assert.Contains(t, err.Error(), "disallowed address")
}

// TestAzureKMSTransport_DialTimeAllowsPublicAddress is the control case for
// the above: a normal public resolution must be allowed PAST the SSRF check
// (any failure must be a real network error, e.g. connection refused —
// nothing is actually listening — never the "disallowed address" refusal).
func TestAzureKMSTransport_DialTimeAllowsPublicAddress(t *testing.T) {
	origResolve := azureKMSResolve
	defer func() { azureKMSResolve = origResolve }()

	azureKMSResolve = func(_ context.Context, _ string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.9")}}, nil
	}
	tr, ok := azureKMSTransport.Transport.(*http.Transport)
	require.True(t, ok)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := tr.DialContext(ctx, "tcp", "myvault.vault.azure.net:443")
	require.Error(t, err, "nothing is actually listening on the TEST-NET-3 address, so the dial itself fails")
	assert.NotContains(t, err.Error(), "disallowed address", "the failure must be a real network error, not the SSRF guard — proving the public address was permitted past validation")
}

func TestNew_RejectsNonKeyVaultHost(t *testing.T) {
	_, err := New(context.Background(), "https://attacker.example/keys/kek")
	require.Error(t, err, "New must reject a kms_key_id whose host is not a recognized Key Vault endpoint, before ever touching credentials/network")
	assert.Contains(t, err.Error(), "not a recognized Azure Key Vault")
}

// fakePermissiveKeys always returns the same plaintext from UnwrapKey
// regardless of the version requested — modeling a rogue/misbehaving
// component sitting between this client and Key Vault (or an SDK bug) that
// does not itself enforce that the requested version matches what the
// ciphertext was actually wrapped under. Used to prove that the envelope's
// own MAC — not just Key Vault's/the fake's version-consistency enforcement
// — is what refuses a Version field tampered independently of the
// ciphertext (G77 member 1).
type fakePermissiveKeys struct {
	plaintext []byte
}

func (f fakePermissiveKeys) WrapKey(_ context.Context, _ string, _ string, _ azkeys.KeyOperationParameters, _ *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	return azkeys.WrapKeyResponse{}, fmt.Errorf("fakePermissiveKeys: WrapKey not implemented")
}

func (f fakePermissiveKeys) UnwrapKey(_ context.Context, _ string, _ string, _ azkeys.KeyOperationParameters, _ *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	return azkeys.UnwrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: f.plaintext}}, nil
}

// TestAzureKMS_DecryptRefusesTamperedVersion is the G77 member-1 regression:
// the version-pinning envelope's Version field must be bound to the
// ciphertext it travels with, so tampering it independently is detected
// rather than silently trusted as key-selection metadata.
func TestAzureKMS_DecryptRefusesTamperedVersion(t *testing.T) {
	secret := []byte("real-secret-kek-material")
	blob, err := encodeEnvelope("v1", []byte("original-ciphertext"), secret)
	require.NoError(t, err)

	// Tamper Version independently of Ciphertext — exactly the finding's
	// scenario: someone able to modify the on-disk blob rewrites the version
	// tag. They cannot recompute a matching MAC because it's keyed on secret,
	// which is never persisted anywhere (it only ever exists in Key Vault and
	// transiently in process memory).
	env, ok, err := decodeEnvelope(blob)
	require.NoError(t, err)
	require.True(t, ok)
	env.Version = "v2-attacker-chosen"
	tamperedBody, err := json.Marshal(env)
	require.NoError(t, err)
	tamperedBlob := append([]byte(envelopeMagic), tamperedBody...)

	// Even in the worst case — UnwrapKey with the tampered version still
	// "succeeds" (a rogue component in front of Key Vault, or a permissive
	// SDK/mock that doesn't itself enforce the version/ciphertext binding)
	// and returns the true plaintext — Decrypt must still refuse: the MAC was
	// computed over the ORIGINAL version and won't match one recomputed over
	// the tampered version.
	c := &client{keys: fakePermissiveKeys{plaintext: secret}, keyName: "kek", keyVersion: ""}
	_, err = c.Decrypt(context.Background(), tamperedBlob)
	require.Error(t, err, "Decrypt must refuse an envelope whose Version was tampered independently of the ciphertext/MAC")
	assert.Contains(t, err.Error(), "integrity check")
}

// fakeKeysWrongKID returns a WrapKey response whose KID names a DIFFERENT key
// than the one requested — modeling an SDK bug, a Key Vault misconfiguration,
// or an untrusted component sitting in front of Key Vault.
type fakeKeysWrongKID struct{}

func (f fakeKeysWrongKID) WrapKey(_ context.Context, _ string, _ string, params azkeys.KeyOperationParameters, _ *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error) {
	kid := azkeys.ID("https://vault.vault.azure.net/keys/some-other-key/v1")
	return azkeys.WrapKeyResponse{KeyOperationResult: azkeys.KeyOperationResult{KID: &kid, Result: params.Value}}, nil
}

func (f fakeKeysWrongKID) UnwrapKey(_ context.Context, _ string, _ string, _ azkeys.KeyOperationParameters, _ *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error) {
	return azkeys.UnwrapKeyResponse{}, fmt.Errorf("fakeKeysWrongKID: UnwrapKey not implemented")
}

// TestAzureKMS_EncryptRefusesMismatchedKID is the G77 member-2 regression:
// Encrypt must not trust the wrap response's KID without checking it names
// the configured key — a mismatch must be refused, not silently pinned.
func TestAzureKMS_EncryptRefusesMismatchedKID(t *testing.T) {
	c := &client{keys: fakeKeysWrongKID{}, keyName: "kek", keyVersion: ""}
	_, err := c.Encrypt(context.Background(), []byte("kek-material"))
	require.Error(t, err, "Encrypt must refuse a wrap response whose KID names a different key than configured")
	assert.Contains(t, err.Error(), "some-other-key")
	assert.Contains(t, err.Error(), "kek")
}

func TestParseKeyID(t *testing.T) {
	tests := []struct {
		name                             string
		keyID                            string
		wantVault, wantName, wantVersion string
		wantErr                          bool
	}{
		{
			name:        "versioned",
			keyID:       "https://myvault.vault.azure.net/keys/kek/abc123",
			wantVault:   "https://myvault.vault.azure.net",
			wantName:    "kek",
			wantVersion: "abc123",
		},
		{
			name:      "unversioned uses latest",
			keyID:     "https://myvault.vault.azure.net/keys/kek",
			wantVault: "https://myvault.vault.azure.net",
			wantName:  "kek",
		},
		{
			name:      "trailing slash",
			keyID:     "https://myvault.vault.azure.net/keys/kek/",
			wantVault: "https://myvault.vault.azure.net",
			wantName:  "kek",
		},
		{name: "missing scheme/host", keyID: "/keys/kek/v1", wantErr: true},
		{name: "not a keys path", keyID: "https://myvault.vault.azure.net/secrets/foo", wantErr: true},
		{name: "missing key name", keyID: "https://myvault.vault.azure.net/keys", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vault, name, version, err := parseKeyID(tt.keyID)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got vault=%q name=%q version=%q", vault, name, version)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if vault != tt.wantVault || name != tt.wantName || version != tt.wantVersion {
				t.Fatalf("got (%q,%q,%q), want (%q,%q,%q)", vault, name, version, tt.wantVault, tt.wantName, tt.wantVersion)
			}
		})
	}
}
