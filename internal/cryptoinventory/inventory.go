package cryptoinventory

import (
	"errors"
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
	SAML              []SAMLInput
	Database          *DatabaseTLSInput
	Backup            *BackupInput
}

// SAMLInput is one SAML provider's IdP metadata (public: entity, endpoints and
// signing certificates). MetadataErr is set instead when it could not be read.
type SAMLInput struct {
	Name        string
	Metadata    []byte
	MetadataErr string
}

// DatabaseTLSInput is the PostgreSQL connection's TLS material, as locations only.
type DatabaseTLSInput struct {
	SSLMode string
	// RootCertFile is the CA bundle file; RootCertSystem means the OS trust store
	// (nothing to read).
	RootCertFile   string
	RootCertSystem bool
	// ClientCertFile / ClientKeyFile come from the DSN's sslcert / sslkey. The key
	// is recorded as a location only and never opened.
	ClientCertFile string
	ClientKeyFile  string
}

// BackupInput describes what protects a backup archive.
type BackupInput struct {
	// EncryptionEnabled is storage.encryption.enabled: when off, the archive's
	// secret values are plaintext.
	EncryptionEnabled bool
}

// maxCABundleCerts bounds how many CA certificates one bundle file contributes.
const maxCABundleCerts = 16

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
	for _, sp := range in.SAML {
		sa, warns := samlAssets(sp)
		assets = append(assets, sa...)
		inv.Warnings = append(inv.Warnings, warns...)
	}
	if in.Database != nil {
		da, warns := databaseTLSAssets(*in.Database)
		assets = append(assets, da...)
		inv.Warnings = append(inv.Warnings, warns...)
	}
	if in.Backup != nil {
		assets = append(assets, backupAsset(*in.Backup))
		if !in.Backup.EncryptionEnabled {
			inv.Warnings = append(inv.Warnings,
				"encryption is disabled: backup archives carry secret values as plaintext (the archive container is never encrypted either way)")
		}
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

// certAsset is the shared shape of a certificate-backed asset.
func certAsset(id, name string, class Class, ci CertInfo) Asset {
	nb, na := ci.NotBefore, ci.NotAfter
	return Asset{ID: id, Name: name, Class: class, Primitive: "signature", Asymmetric: true,
		Algorithm: ci.KeyAlgorithm, KeySizeBits: ci.KeySizeBits, CreatedAt: &nb, ExpiresAt: &na,
		Certificate: &ci, Notes: "signed with " + ci.SignatureAlgorithm}
}

// unreadableCertAsset records a certificate that could not be inspected. It is
// scored by the fail-closed rule for an unclassifiable algorithm.
func unreadableCertAsset(id, name string, class Class, storage string, err error) Asset {
	return Asset{ID: id, Name: name, Class: class, Primitive: "signature", Algorithm: "unknown",
		Storage: storage, Notes: "certificate could not be read: " + err.Error()}
}

// samlAssets inventories the IdP signing certificates Keyorix trusts for one
// SAML provider. Keyorix holds no SAML signing key of its own.
func samlAssets(sp SAMLInput) ([]Asset, []string) {
	id := "saml." + sp.Name
	name := "SAML IdP signing certificate (" + sp.Name + ")"
	storage := "IdP metadata of SSO provider " + sp.Name + " (public certificate only)"
	var cause error
	if sp.MetadataErr != "" {
		cause = errors.New(sp.MetadataErr)
	}
	var infos []CertInfo
	if cause == nil {
		infos, cause = SAMLSigningCertificates(sp.Metadata)
	}
	if cause != nil {
		return []Asset{unreadableCertAsset(id, name, ClassSAMLCertificate, storage, cause)},
			[]string{fmt.Sprintf("SAML provider %q signing certificates could not be inspected: %v", sp.Name, cause)}
	}
	assets := make([]Asset, 0, len(infos))
	for i, ci := range infos {
		a := certAsset(fmt.Sprintf("%s.%d", id, i), name, ClassSAMLCertificate, ci)
		a.Storage = storage
		a.Notes += "; verification only, the IdP holds the private key and controls the migration"
		assets = append(assets, a)
	}
	return assets, nil
}

// databaseTLSAssets inventories the PostgreSQL client certificate and the CA
// bundle that verifies the server.
func databaseTLSAssets(d DatabaseTLSInput) ([]Asset, []string) {
	var assets []Asset
	var warns []string
	if d.ClientCertFile != "" {
		storage := "certificate " + d.ClientCertFile
		if d.ClientKeyFile != "" {
			storage += "; private key " + d.ClientKeyFile
		}
		const id, name = "database-tls.client", "Database TLS client certificate"
		infos, err := LoadCertificates(d.ClientCertFile, 1)
		if err != nil {
			assets = append(assets, unreadableCertAsset(id, name, ClassDatabaseTLSCert, storage, err))
			warns = append(warns, fmt.Sprintf("database TLS client certificate could not be inspected: %v", err))
		} else {
			a := certAsset(id, name, ClassDatabaseTLSCert, infos[0])
			a.Storage = storage
			assets = append(assets, a)
		}
	}
	switch {
	case d.RootCertSystem:
		// the OS trust store is not a file Keyorix can read
	case d.RootCertFile != "":
		const name = "Database TLS CA certificate"
		storage := "CA bundle " + d.RootCertFile
		infos, err := LoadCertificates(d.RootCertFile, maxCABundleCerts)
		if err != nil {
			assets = append(assets, unreadableCertAsset("database-tls.ca.0", name, ClassDatabaseTLSCert, storage, err))
			warns = append(warns, fmt.Sprintf("database TLS CA certificate could not be inspected: %v", err))
			break
		}
		for i, ci := range infos {
			a := certAsset(fmt.Sprintf("database-tls.ca.%d", i), name, ClassDatabaseTLSCert, ci)
			a.Storage = storage
			assets = append(assets, a)
		}
	}
	return assets, warns
}

// backupAsset describes the protection of a backup archive. The archive is a
// tar+gzip container that is not encrypted as a whole: secret values travel as
// the AES-256-GCM ciphertext already stored, the DEK travels wrapped under the
// KEK, and the manifest is HMAC-signed (see the backup-manifest-hmac asset).
func backupAsset(b BackupInput) Asset {
	a := Asset{ID: "backup-archive", Name: "Backup archive encryption", Class: ClassBackupEncryption,
		Primitive: "ae", Algorithm: "AES-256-GCM", KeySizeBits: 256,
		Storage: "backup archive (tar+gzip): secret values as stored ciphertext, DEK wrapped under the KEK, no archive-level encryption",
		Notes:   "confidentiality rests on the KEK, which is never written into the archive; the manifest is HMAC-signed"}
	if !b.EncryptionEnabled {
		a.Algorithm, a.KeySizeBits, a.Primitive = "none", 0, "unknown"
		a.Notes = "encryption is disabled, so the archive carries secret values as plaintext"
	}
	return a
}
