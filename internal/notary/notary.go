// Package notary anchors a message to an external authority that returns an
// independent, signed proof the message existed at a point in time — so a proof
// the running server cannot forge or backdate. Keyorix uses it to anchor audit
// checkpoints (ADR-029): the on-box checkpoint is HMAC-signed with a DEK-derived
// key, which detects truncation/rewrite by a database actor, but an attacker who
// also holds the DEK could forge it. An external RFC 3161 timestamp over the same
// checkpoint binds it to a third party's clock and signing key, which that
// attacker does not control — strengthening the tamper-evidence story for ISO
// 27001 / SOC 2 / eIDAS.
//
// The Notary interface keeps the anchoring backend pluggable (and fake-able in
// tests); RFC3161 is the first implementation.
package notary

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

// Receipt is an external authority's proof over an anchored message.
type Receipt struct {
	Token    []byte    // opaque proof (an RFC 3161 TimeStampToken, DER)
	Time     time.Time // the time the authority asserts the message existed at
	Provider string    // identifies the authority, e.g. "rfc3161:https://freetsa.org/tsr"
}

// Notary anchors a message with an external authority and returns a Receipt. The
// message is the raw bytes being anchored (the backend hashes it as needed); the
// caller passes the SAME bytes to VerifyReceipt later.
type Notary interface {
	Anchor(ctx context.Context, message []byte) (*Receipt, error)
	// Provider identifies the configured authority (for logging / receipt tagging).
	Provider() string
}

// VerifyReceipt re-checks an RFC 3161 receipt token against the original message.
// It (1) verifies the token's signature chains to one of the configured TSA roots
// with the time-stamping extended key usage — so a self-signed or otherwise
// untrusted issuer is rejected; (2) confirms the token's hashed message equals
// SHA-256(message), binding the receipt to exactly this message; and (3) returns
// the authority's asserted time.
//
// roots is REQUIRED: without a trust anchor a token's issuer cannot be trusted, so
// an attacker who can write the checkpoint row (the very actor the anchor defends
// against) could mint a self-signed token over the same bytes. A nil roots
// therefore fails closed rather than asserting an unverifiable proof.
func VerifyReceipt(roots *x509.CertPool, message, token []byte) (_ time.Time, err error) {
	if roots == nil {
		return time.Time{}, fmt.Errorf("notary: no TSA trust anchor configured — cannot verify receipt issuer")
	}
	if len(token) == 0 {
		return time.Time{}, fmt.Errorf("notary: empty receipt token")
	}
	// digitorus/pkcs7 panics on certain malformed BER inputs instead of returning
	// an error (index out of range in ber.go:readObject, found by fuzz rig).
	// Convert any such panic to an error so VerifyReceipt never panics itself.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("notary: parser panic on malformed token: %v", r)
		}
	}()
	ts, err := timestamp.Parse(token)
	if err != nil {
		return time.Time{}, fmt.Errorf("notary: invalid timestamp token: %w", err)
	}
	want := sha256.Sum256(message)
	if !bytes.Equal(ts.HashedMessage, want[:]) {
		return time.Time{}, fmt.Errorf("notary: receipt does not bind this message (timestamped digest differs)")
	}
	// Chain-verify the token's signer to a configured root with the time-stamping
	// EKU. timestamp.Parse only checks the signature is internally consistent (it
	// uses an empty trust store), so this is the step that establishes the issuer
	// is a trusted TSA and not an attacker's self-signed cert.
	p7, err := pkcs7.Parse(token)
	if err != nil {
		return time.Time{}, fmt.Errorf("notary: parse token for chain verification: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, c := range p7.Certificates {
		intermediates.AddCert(c)
	}
	if err := p7.VerifyWithOpts(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		// Verify the chain AS OF the timestamp's asserted time, not time.Now(): an
		// RFC 3161 timestamp must remain verifiable AFTER the TSA's signing cert
		// expires — that durability is the whole point of trusted timestamping.
		// Verifying against now would make every anchor unverifiable once its TSA
		// cert lapsed (and is itself the more correct check: was the issuer trusted
		// when it signed?).
		CurrentTime: ts.Time,
	}); err != nil {
		return time.Time{}, fmt.Errorf("notary: receipt issuer not trusted: %w", err)
	}
	return ts.Time, nil
}
