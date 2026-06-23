// certificate.go — certificate inspection (ADR-054). For a secret whose value is an
// X.509 certificate, InspectCertificate parses it and returns the certificate's
// PUBLIC metadata (subject, issuer, validity window, SANs, …) so an operator can see
// PKI hygiene — chiefly when a cert actually expires, independent of any manually-set
// Expiration field. It never returns the certificate's value or any private key, and
// it does NOT count against the secret's max_reads (reading public certificate
// metadata is not value consumption). Each inspection is audited.
package core

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// EventSecretCertificateInspected is audited when a certificate's metadata is read.
const EventSecretCertificateInspected = "secret.certificate_inspected" // #nosec G101 -- audit event type, not a credential

// CertificateInfo is the public metadata extracted from an X.509 certificate. It
// deliberately excludes the certificate value itself and any private key.
type CertificateInfo struct {
	SecretID           uint      `json:"secret_id"`
	SecretName         string    `json:"secret_name"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DaysUntilExpiry    int       `json:"days_until_expiry"` // negative once expired
	IsExpired          bool      `json:"is_expired"`
	IsCA               bool      `json:"is_ca"`
	SelfSigned         bool      `json:"self_signed"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
}

// InspectCertificate decrypts the secret's current value, parses the leaf X.509
// certificate, and returns its public metadata. actorID is the inspecting principal.
// Authorization (scoped secrets.read) is enforced at the transport layer, mirroring
// the other per-secret read endpoints.
func (c *KeyorixCore) InspectCertificate(ctx context.Context, actorID, secretID uint) (*CertificateInfo, error) {
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: secret %d not found", i18n.T("ErrorNotFound", nil), secretID)
	}
	// A suspended secret is frozen for incident response; don't decrypt it.
	if secret.Status == SecretStatusSuspended {
		return nil, fmt.Errorf("secret is suspended")
	}

	version, err := c.storage.GetLatestSecretVersion(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorVersionNotFound", nil), err)
	}

	// Decrypt WITHOUT touching the max-reads counter — inspecting public certificate
	// metadata is not a value read. (readVersionValue is the counting path; this is
	// deliberately the non-counting sibling.)
	value := version.EncryptedValue
	if c.encryption != nil {
		value, err = c.encryption.RetrieveSecret(version.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to read secret value: %w", err)
		}
	}

	cert, err := parseLeafCertificate(value)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret value is not a parseable X.509 certificate")
	}

	now := c.now()
	info := &CertificateInfo{
		SecretID:           secretID,
		SecretName:         secret.Name,
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DaysUntilExpiry:    int(cert.NotAfter.Sub(now).Hours() / 24),
		IsExpired:          now.After(cert.NotAfter),
		IsCA:               cert.IsCA,
		SelfSigned:         cert.Subject.String() == cert.Issuer.String(),
		DNSNames:           cert.DNSNames,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
	}

	// Cache the parsed expiry so the compliance posture can report certificate hygiene
	// without decrypting on the read path (ADR-056). Best-effort — a cache failure must
	// not fail the inspection.
	_ = c.storage.SetSecretCertNotAfter(ctx, secretID, &cert.NotAfter)

	sid := secretID
	c.writeAuditEvent(ctx, EventSecretCertificateInspected, actorPtr(actorID), &sid,
		fmt.Sprintf("inspected certificate %q (issuer %q, expires %s)", secret.Name, info.Issuer, info.NotAfter.UTC().Format("2006-01-02")))
	return info, nil
}

// parseLeafCertificate extracts the first X.509 certificate from a value that may be
// PEM (one or more blocks, possibly alongside a private key) or raw DER. Only
// CERTIFICATE blocks are considered — a PRIVATE KEY block is never parsed or returned.
func parseLeafCertificate(value []byte) (*x509.Certificate, error) {
	rest := value
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		rest = remainder
	}
	// Not PEM (or no CERTIFICATE block) — try raw DER.
	return x509.ParseCertificate(value)
}
