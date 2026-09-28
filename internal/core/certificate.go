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
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/certparse"
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
	// #G09: previously only checked suspended status, independently
	// reimplementing a subset of the guard bundle every other value
	// disclosure enforces — a caller could inspect a certificate outside its
	// configured access-schedule window, or without the classification-
	// restricted step-up/approval a value read of the same secret would
	// require. enforceSecretReadGuards covers expiration/suspended/
	// classification-gate/schedule; it deliberately does NOT include
	// max-reads, since decrypting to inspect PUBLIC certificate metadata is
	// still not value consumption (see the package doc above) — that one
	// exemption remains intentional, only the other guards were a gap.
	if err := c.enforceSecretReadGuards(ctx, secret, actorID); err != nil {
		return nil, err
	}

	version, err := c.storage.GetLatestSecretVersion(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorVersionNotFound", nil), err)
	}

	// Decrypt WITHOUT touching the max-reads counter — inspecting public certificate
	// metadata is not a value read. (readVersionValue is the counting path; this is
	// deliberately the non-counting sibling.)
	value, err := c.decryptVersionValue(secret, version)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret value: %w", err)
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
		SelfSigned:         isSelfSigned(cert),
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

// isSelfSigned reports whether cert's signature cryptographically validates against
// cert's OWN public key — the actual definition of self-signed: the certificate was
// signed by the private key corresponding to its own subject public key.
//
// #CORE-CERT-003: this replaces a prior `cert.Subject.String() == cert.Issuer.String()`
// comparison, which only compared the RENDERED RDN strings. That heuristic was
// spoofable in both directions: a certificate manually constructed with reordered or
// otherwise mismatched RDN attribute encoding could evade the check despite being
// genuinely self-signed, and — the more consequential direction, since this field feeds
// an operator-facing PKI-hygiene signal per ADR-054/056 — a CA-issued certificate whose
// Issuer happens to render identically to its Subject (matching CN/org by coincidence,
// or a crafted cert) would be misreported as self-signed even though a different key
// signed it, producing a false sense of assurance.
//
// cert.CheckSignatureFrom(cert) is deliberately NOT used here: it additionally enforces
// RFC 5280 CA constraints (BasicConstraints/KeyUsage) on the "parent" argument, which is
// cert itself in a self-check. Those constraints reject the common case of a self-signed
// LEAF certificate (IsCA: false — most self-signed TLS/service certs never set the CA
// bit), which would make a genuinely self-signed leaf spuriously report as NOT
// self-signed. cert.CheckSignature verifies the raw TBS-certificate signature against
// cert's own public key directly, with no CA/BasicConstraints/KeyUsage involved — the
// right primitive for "did this certificate sign itself."
//
// An error (e.g. an unsupported/weak signature algorithm the stdlib refuses to verify)
// means self-signed status cannot be cryptographically confirmed. We fail closed to
// false (not self-signed) rather than assume it is: the whole point of this field is an
// accurate hygiene signal, and an unverified claim of "self-signed" would itself be a
// false assurance.
func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// maxCertBlocks is certparse.MaxCertBlocks — certificate_test.go's own exactness
// regression test (TestParseLeafCertificate_AttemptBound) pins against it.
const maxCertBlocks = certparse.MaxCertBlocks

// parseLeafCertificate extracts the leaf X.509 certificate from a value that may be
// PEM (one or more blocks, possibly alongside a private key) or raw DER. Only
// CERTIFICATE blocks are considered — a PRIVATE KEY block is never parsed or returned.
//
// It does NOT trust block order. PEM chains are routinely stored leaf-last (a CA
// bundle, or a root/intermediate pasted ahead of the serving cert), so returning the
// FIRST block would let a long-lived CA's NotAfter mask a short-lived leaf and
// silently defeat the ADR-055/056 expiry monitor; an unparseable first block would
// likewise hide a valid leaf behind it. Instead it parses every CERTIFICATE block,
// skips the ones that don't parse, and selects the leaf via certparse.SelectLeafCertificate.
// Thin wrapper over certparse.ParseLeafCertificate (internal/core/certparse), moved there so
// this logic can be fuzzed cheaply as a leaf package — see that package's doc.go.
func parseLeafCertificate(value []byte) (*x509.Certificate, error) {
	return certparse.ParseLeafCertificate(value)
}
