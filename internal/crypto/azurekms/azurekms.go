// Package azurekms implements crypto.KMSClient against Azure Key Vault (ADR-041).
// Like the awskms and gcpkms packages, it is the only place the Azure Key Vault
// SDK is imported, so internal/crypto stays cloud-SDK-free. Credentials come from
// DefaultAzureCredential (env vars, managed identity, workload identity), never
// from Keyorix config.
//
// Envelope encryption uses the vault key's wrapKey/unwrapKey operations
// (RSA-OAEP-256): the 32-byte KEK is wrapped by the vault key and only the wrapped
// blob is stored on disk.
//
// Unlike AWS/GCP KMS, an Azure Key Vault key wrap/unwrap operation targets a
// specific key VERSION, and an unversioned kms_key_id resolves to whatever
// version is "current" at call time (docs/adr-041-kms-key-provider.md). Routine
// key rotation therefore changes what "current" means between the Encrypt call
// (at first run) and a later Decrypt call (at every subsequent restart) — the new
// version cannot unwrap ciphertext produced by the old one. To make this immune
// to rotation, Encrypt captures the exact key version Azure actually used (from
// the response KID, which is always fully versioned, and which Encrypt checks
// names the configured key before trusting it) and embeds it in the returned
// blob behind a magic prefix, alongside a MAC binding that version to the
// unwrapped plaintext (see envelope's doc comment) so the version can't be
// rewritten independently of the ciphertext it travels with. Decrypt recognizes
// that prefix and targets the pinned version instead of "current". Ciphertext
// wrapped before this change (no prefix) still decrypts via the old
// "current"/configured-version resolution — see decodeEnvelope.
package azurekms

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	keyorixcrypto "github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/netutil"
)

// wrapAlgorithm is the asymmetric wrap algorithm used to envelope the KEK. RSA
// keys are the common Key Vault case; the same algorithm is used for unwrap.
var wrapAlgorithm = azkeys.EncryptionAlgorithmRSAOAEP256

// envelopeMagic prefixes a version-pinned wrapped blob (see package doc). Raw
// Key Vault wrap output is uniformly-random ciphertext bytes, so the chance a
// legacy (pre-fix) blob collides with this ASCII prefix is negligible — well
// below the chance of guessing the wrapping key itself.
const envelopeMagic = "keyorix-azkms-v1:"

// envelope carries the exact key version a KEK was wrapped under, alongside the
// wrap result, so Decrypt can always target that version rather than "current".
//
// MAC binds Version to the plaintext that Ciphertext actually unwraps to: it is
// HMAC-SHA256(key=plaintext KEK, message=Version), computed once at Encrypt time
// while the plaintext is available and re-checked at Decrypt time against the
// plaintext Key Vault just returned. Version alone is otherwise unauthenticated
// metadata — nothing ties it to the ciphertext it travels with in the same
// on-disk blob, so anyone able to modify the blob could rewrite Version
// independently of Ciphertext. A plain (unkeyed) checksum wouldn't help: an
// attacker with write access to the blob can already read Ciphertext from that
// same blob and recompute a checksum to match any Version they choose. Keying
// the MAC on the recovered plaintext instead works because that plaintext is
// never persisted anywhere — it exists only in Key Vault and briefly in this
// process's memory — so a storage-only attacker (or a rogue component sitting
// in front of Key Vault fabricating an UnwrapKey response) cannot compute a
// matching MAC without already knowing it. MAC is empty for envelopes written
// before this field existed (see decodeEnvelope); Decrypt only enforces it when
// present, so already-encrypted-and-stored DEKs keep decrypting unchanged.
type envelope struct {
	Version    string `json:"version"`
	Ciphertext []byte `json:"ciphertext"`
	MAC        []byte `json:"mac,omitempty"`
}

// versionMAC computes the HMAC binding an envelope's Version to the plaintext
// its Ciphertext unwraps to (see envelope's doc comment).
func versionMAC(plaintext []byte, version string) []byte {
	h := hmac.New(sha256.New, plaintext)
	h.Write([]byte(version))
	return h.Sum(nil)
}

// encodeEnvelope prepends the magic prefix to a JSON-encoded envelope. plaintext
// is the KEK material ciphertext wraps — used only to derive MAC, never stored.
func encodeEnvelope(version string, ciphertext, plaintext []byte) ([]byte, error) {
	body, err := json.Marshal(envelope{Version: version, Ciphertext: ciphertext, MAC: versionMAC(plaintext, version)})
	if err != nil {
		return nil, fmt.Errorf("azure-kms: encode envelope: %w", err)
	}
	return append([]byte(envelopeMagic), body...), nil
}

// decodeEnvelope reports whether blob is a version-pinned envelope produced by
// encodeEnvelope. Blobs without the magic prefix are legacy (or explicitly
// versioned pre-fix) wrap output and must be decrypted with the client's
// configured/"current" version instead.
func decodeEnvelope(blob []byte) (env envelope, ok bool, err error) {
	if !bytes.HasPrefix(blob, []byte(envelopeMagic)) {
		return envelope{}, false, nil
	}
	if err := json.Unmarshal(blob[len(envelopeMagic):], &env); err != nil {
		return envelope{}, false, fmt.Errorf("azure-kms: corrupt version-pinned envelope: %w", err)
	}
	return env, true, nil
}

// azureKeysAPI is the slice of the Key Vault keys client this package uses — an
// interface seam so the SDK stays contained here and version-pinning behavior is
// unit-testable with a fake that models rotation (a wrap tied to version V fails
// to unwrap once "current" moves to a different version).
type azureKeysAPI interface {
	WrapKey(ctx context.Context, name string, version string, parameters azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error)
	UnwrapKey(ctx context.Context, name string, version string, parameters azkeys.KeyOperationParameters, options *azkeys.UnwrapKeyOptions) (azkeys.UnwrapKeyResponse, error)
}

type client struct {
	keys       azureKeysAPI
	keyName    string
	keyVersion string // "" = latest version
}

// azureKeyVaultHostSuffixes lists the domain suffixes Azure Key Vault and
// Managed HSM endpoints use across the public cloud and every sovereign cloud
// (China, US Government, Germany). kms_key_id's host must end in one of
// these — otherwise a misconfigured, redirected, or attacker-influenced
// kms_key_id would send DefaultAzureCredential's live bearer token (attached
// to every WrapKey/UnwrapKey call) to an arbitrary host, exfiltrating it.
// Before this check, kms_key_id's host was never validated at all — not even
// once — unlike every other SSRF-relevant host in this codebase.
var azureKeyVaultHostSuffixes = []string{
	".vault.azure.net",         // public cloud
	".vault.azure.cn",          // Azure China (Mooncake)
	".vault.usgovcloudapi.net", // Azure US Government
	".vault.microsoftazure.de", // Azure Germany (legacy sovereign cloud)
	".managedhsm.azure.net",
	".managedhsm.azure.cn",
	".managedhsm.usgovcloudapi.net",
}

// validateKeyVaultHost rejects a vaultURL (as split out by parseKeyID) that
// isn't https, or whose host doesn't look like a real Azure Key Vault /
// Managed HSM endpoint. This is the construction-time half of the guard —
// azureKMSTransport below re-validates on every actual connection.
func validateKeyVaultHost(vaultURL string) error {
	u, err := url.Parse(vaultURL)
	if err != nil {
		return fmt.Errorf("azure-kms: invalid vault URL %q: %w", vaultURL, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("azure-kms: vault URL %q must use https", vaultURL)
	}
	host := strings.ToLower(u.Hostname())
	for _, suffix := range azureKeyVaultHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return nil
		}
	}
	return fmt.Errorf("azure-kms: kms_key_id host %q is not a recognized Azure Key Vault or Managed HSM endpoint", u.Hostname())
}

// azureKMSResolve resolves a Key Vault hostname to its IP addresses — a var
// (like evidencesink/notifychan's identically-shaped lookupIPAddr) so tests
// can substitute a fake resolver to simulate a DNS-rebinding target without a
// real DNS query.
var azureKMSResolve netutil.Resolver = netutil.DefaultResolver

// azureKMSTransport dial-time-validates every Key Vault request against
// netutil.IsPrivateOrLinkLocal (loopback included — a Key Vault endpoint has
// no legitimate reason to resolve anywhere on the Keyorix host's own private
// network), so a DNS-rebinding attacker cannot bypass validateKeyVaultHost's
// one-time, construction-time check: the resolved address is re-checked on
// every connection and the specific validated IP is dialed directly, never
// the hostname again.
var azureKMSTransport = &http.Client{
	Transport: &http.Transport{
		DialContext: (&netutil.Dialer{
			Disallow: netutil.IsPrivateOrLinkLocal,
			Resolve:  func(ctx context.Context, host string) ([]net.IPAddr, error) { return azureKMSResolve(ctx, host) },
		}).DialContext,
	},
}

// New builds an Azure-Key-Vault-backed crypto.KMSClient. keyID is the full key
// identifier URL (https://{vault}.vault.azure.net/keys/{name}[/{version}]); an
// omitted version uses the key's current version.
func New(_ context.Context, keyID string) (keyorixcrypto.KMSClient, error) {
	if keyID == "" {
		return nil, fmt.Errorf("azure-kms: kms_key_id (key identifier URL) is required")
	}
	vaultURL, name, version, err := parseKeyID(keyID)
	if err != nil {
		return nil, err
	}
	if err := validateKeyVaultHost(vaultURL); err != nil {
		return nil, err
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure-kms: default credential: %w", err)
	}
	c, err := azkeys.NewClient(vaultURL, cred, &azkeys.ClientOptions{
		ClientOptions: policy.ClientOptions{Transport: azureKMSTransport},
	})
	if err != nil {
		return nil, fmt.Errorf("azure-kms: create client: %w", err)
	}
	return &client{keys: c, keyName: name, keyVersion: version}, nil
}

// parseKeyID splits an Azure Key Vault key identifier URL into the vault URL, key
// name, and (optional) key version. Accepts both versioned and unversioned forms.
func parseKeyID(keyID string) (vaultURL, name, version string, err error) {
	u, err := url.Parse(keyID)
	if err != nil {
		return "", "", "", fmt.Errorf("azure-kms: invalid kms_key_id %q: %w", keyID, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", "", "", fmt.Errorf("azure-kms: kms_key_id must be a key identifier URL (https://{vault}.vault.azure.net/keys/{name}[/{version}]), got %q", keyID)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || parts[0] != "keys" || parts[1] == "" {
		return "", "", "", fmt.Errorf("azure-kms: kms_key_id path must be /keys/{name}[/{version}], got %q", u.Path)
	}
	vaultURL = u.Scheme + "://" + u.Host
	name = parts[1]
	if len(parts) >= 3 {
		version = parts[2]
	}
	return vaultURL, name, version, nil
}

func (c *client) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	res, err := c.keys.WrapKey(ctx, c.keyName, c.keyVersion, azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(wrapAlgorithm),
		Value:     plaintext,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azure-kms: wrap key: %w", err)
	}
	// res.KID is the fully-versioned key identifier Azure actually used, even
	// when the request (c.keyVersion) was unversioned/"current". Pin it into the
	// returned blob so a later Decrypt targets this exact version and is immune
	// to the key being rotated to a new "current" version in the meantime.
	//
	// res.KID is untrusted key-selection metadata, not just a version hint: it
	// names both a key and a version. Before trusting either, confirm the KID
	// actually names the key we asked Key Vault to wrap under (c.keyName) —
	// reusing parseKeyID, the same defensive URL parser already used for the
	// user-supplied kms_key_id. A KID naming a different key (an SDK bug, a
	// Key Vault misconfiguration, or an untrusted component sitting in front
	// of Key Vault) must never be silently pinned as if it were ours: that
	// would record the KEK as wrapped under the wrong key and point every
	// future Decrypt at it.
	var version string
	if res.KID != nil {
		_, kidName, kidVersion, perr := parseKeyID(string(*res.KID))
		if perr != nil {
			return nil, fmt.Errorf("azure-kms: wrap response KID %q is not a valid key identifier: %w", string(*res.KID), perr)
		}
		if kidName != c.keyName {
			return nil, fmt.Errorf("azure-kms: wrap response KID names key %q, configured key is %q — refusing to pin a version for a different key", kidName, c.keyName)
		}
		version = kidVersion
	}
	if version == "" {
		// Unexpected (Key Vault always returns a versioned KID), but fail safe by
		// falling back to the legacy, unpinned blob rather than erroring out.
		return res.Result, nil
	}
	return encodeEnvelope(version, res.Result, plaintext)
}

func (c *client) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	version := c.keyVersion
	wrapped := ciphertext
	env, pinned, err := decodeEnvelope(ciphertext)
	if err != nil {
		return nil, err
	}
	if pinned {
		version = env.Version
		wrapped = env.Ciphertext
	}
	res, err := c.keys.UnwrapKey(ctx, c.keyName, version, azkeys.KeyOperationParameters{
		Algorithm: to.Ptr(wrapAlgorithm),
		Value:     wrapped,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azure-kms: unwrap key: %w", err)
	}
	// Envelopes written before the MAC field existed carry none (env.MAC is
	// nil) — only enforce the check when a MAC is actually present, so those
	// already-encrypted-and-stored DEKs keep decrypting exactly as before.
	if pinned && len(env.MAC) > 0 {
		if !hmac.Equal(versionMAC(res.Result, env.Version), env.MAC) {
			return nil, fmt.Errorf("azure-kms: version-pinned envelope failed integrity check: Version does not match the recovered key material — the envelope may have been tampered with")
		}
	}
	return res.Result, nil
}
