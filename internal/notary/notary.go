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
	"crypto"
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
// untrusted issuer is rejected; (2) confirms the token declares a SHA-256
// message-imprint algorithm and that its hashed message equals SHA-256(message),
// binding the receipt to exactly this message and this algorithm; and (3) returns
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
	// The token declares its own message-imprint hash algorithm (digitorus/timestamp
	// resolves the ASN.1 OID into ts.HashAlgorithm and already rejects unrecognized
	// OIDs at Parse time). We only ever compute a SHA-256 digest of message below, so
	// confirm the token actually claims SHA-256 (OID 2.16.840.1.101.3.4.2.1) before
	// comparing bytes — otherwise a token declaring a different algorithm (e.g.
	// SHA-1) but happening to carry a HashedMessage of the same length as a SHA-256
	// digest would pass a raw byte comparison even though it was never validated
	// against that algorithm. digitorus/timestamp does not itself check that
	// HashedMessage's length matches the declared algorithm's output size, so this
	// check is the only thing tying the comparison to the algorithm the token claims.
	if ts.HashAlgorithm != crypto.SHA256 {
		return time.Time{}, fmt.Errorf("notary: receipt uses unsupported message-imprint hash algorithm %v (want SHA-256)", ts.HashAlgorithm)
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
	// #notary-findings-2's residual (scoped down, documented rather than built): this
	// chain check does NOT perform CRL/OCSP revocation checking of the TSA cert
	// chain — neither Go's x509.Verify nor digitorus/pkcs7's VerifyWithOpts (which is
	// a thin wrapper around it, confirmed by reading both vendored sources) expose
	// any revocation hook to wire into, so there is no small change available here;
	// a real one means shipping an OCSP client or a CRL fetch+cache path, plus a
	// fail-open-vs-fail-closed policy for a network call sitting inside a signature-
	// verification path — all of that is disproportionate to this being a low-
	// severity, defense-in-depth gap on a niche feature (checkpoint anchoring) with a
	// narrow window (only matters if the configured TSA's signing key is later
	// compromised AND the malicious token also carries a ts.Time predating the real
	// revocation date, since verification is deliberately pinned to the token's own
	// claimed time — see below). If this needs closing later, prefer OCSP stapling
	// or a periodically-refreshed CRL cache over a synchronous fetch per verify call.
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
