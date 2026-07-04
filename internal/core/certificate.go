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
	"github.com/keyorixhq/keyorix/internal/storage/models"
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
// Authorization is enforced here via EnforceSecretReadPermission — the same
// ownership/share-aware permission check every other per-secret value-derived read
// goes through — on top of whatever project-scoped secrets.read the transport layer
// already required. Holding project-wide secrets.read is not enough on its own: the
// actor must also own the secret or hold an active share on it.
func (c *KeyorixCore) InspectCertificate(ctx context.Context, actorID, secretID uint) (*CertificateInfo, error) {
	if _, err := c.EnforceSecretReadPermission(ctx, secretID, actorID); err != nil {
		return nil, err
	}
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

// certificateSecretType is the SecretNode.Type that marks a certificate-typed secret,
// whose leaf-expiry is cached in CertNotAfter for the certificate-hygiene posture (ADR-056).
const certificateSecretType = "certificate"

// refreshCertNotAfterCache updates the cached leaf-certificate expiry (CertNotAfter,
// ADR-056) for a certificate-typed secret from a known plaintext value — used after a
// rotation so the certificate-hygiene posture reflects the new certificate immediately,
// without waiting for the next expiry scan. A parseable certificate refreshes the cached
// date; a value that is not a certificate (e.g. the secret was rotated to a non-cert
// value) clears the now-stale date. A no-op for non-certificate secrets. Best-effort: a
// cache write failure never fails the caller, mirroring InspectCertificate's cache write.
func (c *KeyorixCore) refreshCertNotAfterCache(ctx context.Context, secret *models.SecretNode, value []byte) {
	if secret == nil || secret.Type != certificateSecretType {
		return
	}
	if cert, err := parseLeafCertificate(value); err == nil {
		_ = c.storage.SetSecretCertNotAfter(ctx, secret.ID, &cert.NotAfter)
	} else {
		_ = c.storage.SetSecretCertNotAfter(ctx, secret.ID, nil)
	}
}

// maxCertBlocks bounds how many CERTIFICATE blocks we parse from a single value, so a
// pathological PEM (the body is already capped at MaxBodyBytes) can't burn CPU.
const maxCertBlocks = 64

// parseLeafCertificate extracts the leaf X.509 certificate from a value that may be
// PEM (one or more blocks, possibly alongside a private key) or raw DER. Only
// CERTIFICATE blocks are considered — a PRIVATE KEY block is never parsed or returned.
//
// It does NOT trust block order. PEM chains are routinely stored leaf-last (a CA
// bundle, or a root/intermediate pasted ahead of the serving cert), so returning the
// FIRST block would let a long-lived CA's NotAfter mask a short-lived leaf and
// silently defeat the ADR-055/056 expiry monitor; an unparseable first block would
// likewise hide a valid leaf behind it. Instead it parses every CERTIFICATE block,
// skips the ones that don't parse, and selects the leaf via selectLeafCertificate.
func parseLeafCertificate(value []byte) (*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := value
	sawPEMBlock := false
	// Bound by ATTEMPTS, not by len(certs): a PEM value that's mostly non-CERTIFICATE
	// blocks (e.g. PRIVATE KEY) or unparseable CERTIFICATE blocks never grows certs,
	// so gating on len(certs) doesn't actually cap the number of pem.Decode/
	// x509.ParseCertificate calls — the CPU-bounding this constant exists for.
	for attempts := 0; attempts < maxCertBlocks; attempts++ {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEMBlock = true
		rest = remainder
		if block.Type != "CERTIFICATE" {
			continue
		}
		// Skip an unparseable CERTIFICATE block rather than aborting — a corrupt block
		// must not hide a valid (possibly soon-expiring) leaf elsewhere in the value.
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}
	if !sawPEMBlock {
		// Not PEM — try raw DER (a single certificate).
		return x509.ParseCertificate(value)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no parseable X.509 certificate found")
	}
	return selectLeafCertificate(certs), nil
}

// selectLeafCertificate picks the certificate the expiry/hygiene control should key
// off: the soonest-expiring END-ENTITY (non-CA) certificate, so a chain that stores a
// long-lived CA/intermediate ahead of a short-lived leaf can't hide the leaf's
// expiry. Falls back to the soonest-expiring certificate overall when every block is a
// CA. Order-independent by construction.
func selectLeafCertificate(certs []*x509.Certificate) *x509.Certificate {
	var chosen *x509.Certificate
	for _, cert := range certs {
		if cert.IsCA {
			continue
		}
		if chosen == nil || cert.NotAfter.Before(chosen.NotAfter) {
			chosen = cert
		}
	}
	if chosen != nil {
		return chosen
	}
	// All blocks are CAs — still pick the soonest-expiring so the control fails safe.
	chosen = certs[0]
	for _, cert := range certs[1:] {
		if cert.NotAfter.Before(chosen.NotAfter) {
			chosen = cert
		}
	}
	return chosen
}
