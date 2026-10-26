package cryptoinventory

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Inputs is everything Build needs, gathered by the caller from configuration and
// storage. It holds locations and non-secret identifiers only: file paths, an
// environment variable NAME (never its value), a KMS key ID, issuer URLs.
type Inputs struct {
	EncryptionEnabled bool
	// KeyProvider is storage.encryption.key_provider.type ("" = password).
	KeyProvider string
	// KeyProviderRef is a non-secret locator for the provider: a file path, an
	// env var name, a KMS key ID, a TPM device. For "exec" pass argv[0] only.
	KeyProviderRef    string
	FallbackProviders []string
	DEKPath           string
	DEKCreatedAt      *time.Time
	TLS               []TLSInput
	Recovery          *RecoveryInput
	WebAuthnEnabled   bool
	WebAuthnRPID      string
	OIDCIssuers       []string
}

// TLSInput is one TLS listener's certificate configuration.
type TLSInput struct {
	Name     string // "http", "grpc"
	CertFile string
	KeyFile  string // recorded as a location only; never opened
	AutoCert bool
}

// RecoveryInput is the admin recovery key's stored metadata (never the key or its hash).
type RecoveryInput struct {
	KeyVersion int
	CreatedAt  time.Time
	RotatedAt  *time.Time
}

// Build assembles and scores the inventory. An invalid policy falls back to the
// defaults and says so in Warnings.
func Build(in Inputs, p Policy, now time.Time) Inventory {
	inv := Inventory{GeneratedAt: now.UTC(), Warnings: []string{}, Notes: []string{}}
	if err := p.Validate(); err != nil {
		inv.Warnings = append(inv.Warnings, fmt.Sprintf("invalid quantum-risk policy (%v): defaults used", err))
		p = DefaultPolicy()
	}
	inv.Policy = p

	var assets []Asset
	if in.EncryptionEnabled {
		assets = append(assets, kekAsset(in), dekAsset(in))
		assets = append(assets, derivedKeyAssets()...)
	} else {
		inv.Warnings = append(inv.Warnings,
			"encryption is disabled: secrets are stored as plaintext, so there is no KEK, DEK or derived signing key to inventory")
	}
	if in.Recovery != nil {
		assets = append(assets, recoveryAsset(in.Recovery))
	}
	for _, t := range in.TLS {
		a, warn := tlsAsset(t)
		assets = append(assets, a)
		if warn != "" {
			inv.Warnings = append(inv.Warnings, warn)
		}
	}
	if in.WebAuthnEnabled {
		assets = append(assets, webAuthnAsset(in.WebAuthnRPID))
	}
	for i, iss := range in.OIDCIssuers {
		assets = append(assets, oidcAsset(i, iss))
	}
	inv.Notes = append(inv.Notes,
		"Keyorix signs no JWTs of its own: sessions are opaque tokens stored hashed. JWT keys listed are external issuers' verification keys.")

	for i := range assets {
		assets[i].Risk = p.Assess(assets[i], now)
	}
	sort.SliceStable(assets, func(i, j int) bool {
		if assets[i].Risk.Score != assets[j].Risk.Score {
			return assets[i].Risk.Score > assets[j].Risk.Score
		}
		return assets[i].ID < assets[j].ID
	})
	inv.Assets = assets
	for _, a := range assets {
		inv.Summary.Total++
		switch a.Risk.Level {
		case LevelHigh:
			inv.Summary.High++
		case LevelMedium:
			inv.Summary.Medium++
		default:
			inv.Summary.Low++
		}
		if a.Risk.QuantumVulnerable {
			inv.Summary.QuantumVulnerable++
		}
	}
	return inv
}

func kekAsset(in Inputs) Asset {
	a := Asset{ID: "kek", Name: "Key encryption key (KEK)", Class: ClassKEK,
		Primitive: "ae", Algorithm: "AES-256-GCM", KeySizeBits: 256}
	ref := in.KeyProviderRef
	switch in.KeyProvider {
	case "", "password":
		a.Primitive, a.Algorithm = "kdf", "PBKDF2-HMAC-SHA256"
		a.Storage = "not stored: derived at start-up from the master passphrase and an on-disk salt"
	case "file":
		a.Storage = "file: " + ref
	case "env":
		a.Storage = "environment variable " + ref
	case "exec":
		a.Storage = "output of resolver command " + ref
	case "shamir":
		a.Storage = "Shamir K-of-N shares (files/environment), reconstructed in memory only"
	case "tpm":
		a.Storage = "TPM 2.0 sealed blob (device " + ref + ")"
	case "aws-kms", "gcp-kms":
		a.Storage = "KMS-wrapped blob on disk; wrapping key " + ref
		a.Notes = "assumes a symmetric (AES-256) KMS key"
	case "azure-kms":
		a.Primitive, a.Algorithm = "pke", "RSA-OAEP-256"
		a.KeySizeBits, a.Asymmetric = 0, true
		a.Storage = "KMS-wrapped blob on disk; wrapping key " + ref
		a.Notes = "the KEK is wrapped with an RSA Key Vault key (size set in Key Vault, not visible here): a stored wrapped KEK is exposed to harvest-now-decrypt-later"
	default:
		a.Algorithm, a.KeySizeBits = "unknown", 0
		a.Storage = "unrecognised key provider " + in.KeyProvider
	}
	if len(in.FallbackProviders) > 0 {
		a.Notes = strings.TrimSpace(a.Notes + " fallback providers: " + strings.Join(in.FallbackProviders, ", "))
	}
	return a
}

func dekAsset(in Inputs) Asset {
	path := in.DEKPath
	if path == "" {
		path = "dek.key"
	}
	a := Asset{ID: "dek", Name: "Data encryption key (DEK)", Class: ClassDEK,
		Primitive: "ae", Algorithm: "AES-256-GCM", KeySizeBits: 256, CreatedAt: in.DEKCreatedAt,
		Storage: "file " + path + ", wrapped with AES-256-GCM under the KEK"}
	if in.DEKCreatedAt != nil {
		a.Notes = "created_at is the key file's last-modified time (creation or last rotation)"
	}
	return a
}

// derivedKeyAssets are the three HMAC keys HKDF-derived from the KEK. They exist
// in memory only.
func derivedKeyAssets() []Asset {
	mk := func(id, name string, c Class, use string) Asset {
		return Asset{ID: id, Name: name, Class: c, Primitive: "mac", Algorithm: "HMAC-SHA256", KeySizeBits: 256,
			Storage: "memory only: HKDF-SHA256 derived from the KEK, never persisted",
			Notes:   use}
	}
	return []Asset{
		mk("audit-checkpoint-hmac", "Audit checkpoint HMAC key", ClassAuditHMACKey, "signs audit-chain checkpoints (ADR-029)"),
		mk("evidence-hmac", "Compliance evidence signing key", ClassSigningKey, "signs exported compliance evidence packs"),
		mk("backup-manifest-hmac", "Backup manifest signing key", ClassSigningKey, "signs backup manifests"),
	}
}

func recoveryAsset(r *RecoveryInput) Asset {
	created := r.CreatedAt.UTC()
	a := Asset{ID: "recovery-key", Name: "Admin recovery key verifier", Class: ClassRecoveryKey,
		Primitive: "hash", Algorithm: "SHA-256", KeySizeBits: 260, CreatedAt: &created,
		Storage: "database: SHA-256 verifier only; the 260-bit key is shown once and held offline by the operator",
		Notes:   fmt.Sprintf("key version %d", r.KeyVersion)}
	if r.RotatedAt != nil {
		a.Notes += ", rotated " + r.RotatedAt.UTC().Format("2006-01-02")
	}
	return a
}

func tlsAsset(t TLSInput) (Asset, string) {
	name := t.Name
	if name == "" {
		name = "tls"
	}
	a := Asset{ID: "tls." + name, Name: "TLS certificate (" + name + ")", Class: ClassTLSCertificate,
		Primitive: "signature", Asymmetric: true}
	if t.AutoCert {
		a.Algorithm, a.KeySizeBits = "ECDSA-P256", 256
		a.AssumedLifetimeDays = 90
		a.Storage = "ACME (autocert) cache; certificate and key issued and renewed automatically"
		a.Notes = "algorithm is autocert's default; the issued certificate is not read"
		return a, ""
	}
	a.Storage = "certificate " + t.CertFile + "; private key " + t.KeyFile
	info, err := LoadCertificateInfo(t.CertFile)
	if err != nil {
		a.Algorithm = "unknown"
		a.Asymmetric = false // unclassifiable: scored by the fail-closed rule
		a.Notes = "certificate could not be read: " + err.Error()
		return a, fmt.Sprintf("TLS certificate %q could not be inspected: %v", name, err)
	}
	a.Algorithm, a.KeySizeBits = info.KeyAlgorithm, info.KeySizeBits
	nb, na := info.NotBefore, info.NotAfter
	a.CreatedAt, a.ExpiresAt = &nb, &na
	a.Certificate = &info
	a.Notes = "signed with " + info.SignatureAlgorithm
	return a, ""
}

func webAuthnAsset(rpID string) Asset {
	return Asset{ID: "webauthn-passkeys", Name: "WebAuthn passkey public keys", Class: ClassWebAuthn,
		Primitive: "signature", Algorithm: "COSE ES256/RS256/EdDSA (per credential)", Asymmetric: true,
		Storage: "database: each credential's public key and signature counter",
		Notes: "relying party " + rpID + "; private keys stay on the authenticator. " +
			"Per-credential algorithms are not enumerated yet; all accepted COSE algorithms are classical."}
}

func oidcAsset(i int, issuer string) Asset {
	return Asset{ID: fmt.Sprintf("oidc-jwks.%d", i), Name: "OIDC issuer JWT verification keys", Class: ClassJWTKey,
		Primitive: "signature", Algorithm: "RS256/ES256/PS256 family (JWKS)", Asymmetric: true,
		AssumedLifetimeDays: 365,
		Storage:             "fetched from the issuer's JWKS endpoint " + issuer + " (public keys only)",
		Notes:               "verification only; the issuer holds the private keys and controls the migration"}
}
