// Package cryptoinventory builds a metadata-only inventory of every key and
// certificate Keyorix holds or depends on (KEK, DEK, recovery key, TLS
// certificates, derived signing/HMAC keys, WebAuthn and OIDC verification keys),
// scores each for quantum exposure, and exports it as a CycloneDX 1.6 CBOM
// (cryptographic bill of materials).
//
// The package never reads, holds or emits key material. Its inputs are
// configuration, file locations, and the public certificate block of a TLS
// certificate file; its outputs are algorithm names, sizes, dates and storage
// descriptions. R&D prototype (RD-CBOM-1); see docs/design-crypto-inventory.md.
package cryptoinventory

import "time"

// Class is the kind of key or certificate an Asset describes.
type Class string

// Asset classes.
const (
	ClassKEK            Class = "kek"
	ClassDEK            Class = "dek"
	ClassRecoveryKey    Class = "recovery-key"
	ClassTLSCertificate Class = "tls-certificate"
	ClassSigningKey     Class = "signing-key"
	ClassJWTKey         Class = "jwt-key"
	ClassWebAuthn       Class = "webauthn"
	ClassAuditHMACKey   Class = "audit-hmac-key"
)

// Risk levels.
const (
	LevelLow    = "low"
	LevelMedium = "medium"
	LevelHigh   = "high"
)

// CertInfo is the public, parsed description of an X.509 certificate.
type CertInfo struct {
	SubjectName        string    `json:"subject_name"`
	IssuerName         string    `json:"issuer_name"`
	KeyAlgorithm       string    `json:"key_algorithm"`
	KeySizeBits        int       `json:"key_size_bits"`
	Curve              string    `json:"curve,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
}

// Risk is the quantum-exposure assessment of one asset.
type Risk struct {
	Score             int      `json:"score"`
	Level             string   `json:"level"`
	QuantumVulnerable bool     `json:"quantum_vulnerable"`
	Reasons           []string `json:"reasons"`
}

// Asset describes one key or certificate. It carries metadata only; there is
// deliberately no field that could hold key bytes.
type Asset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Class       Class  `json:"class"`
	Primitive   string `json:"primitive"` // CycloneDX algorithm primitive (ae, mac, kdf, signature, hash, pke, ...)
	Algorithm   string `json:"algorithm"`
	KeySizeBits int    `json:"key_size_bits"`
	// Asymmetric marks public-key algorithms; PostQuantum marks PQ or hybrid ones.
	Asymmetric  bool       `json:"asymmetric"`
	PostQuantum bool       `json:"post_quantum"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	// AssumedLifetimeDays stands in for ExpiresAt when the real expiry is unknown
	// but the rotation cadence is (e.g. an ACME certificate, an IdP JWKS key).
	// Zero means "no expiry": the policy's UnboundedLifetimeYears applies.
	AssumedLifetimeDays int       `json:"assumed_lifetime_days,omitempty"`
	Storage             string    `json:"storage"`
	Notes               string    `json:"notes,omitempty"`
	Certificate         *CertInfo `json:"certificate,omitempty"`
	Risk                Risk      `json:"risk"`
}

// Summary aggregates an Inventory.
type Summary struct {
	Total             int `json:"total"`
	High              int `json:"high"`
	Medium            int `json:"medium"`
	Low               int `json:"low"`
	QuantumVulnerable int `json:"quantum_vulnerable"`
}

// Inventory is the full result of Build.
type Inventory struct {
	GeneratedAt time.Time `json:"generated_at"`
	Policy      Policy    `json:"policy"`
	Assets      []Asset   `json:"assets"`
	Summary     Summary   `json:"summary"`
	// Warnings lists everything that was skipped or could not be assessed, so a
	// gap in the inventory is visible rather than silent.
	Warnings []string `json:"warnings"`
	// Notes records key classes that do not apply to this deployment and why.
	Notes []string `json:"notes"`
}
