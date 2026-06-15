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
	"fmt"
	"time"

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

// VerifyReceipt re-checks an RFC 3161 receipt token against the original message:
// it parses (and signature-validates) the token, confirms the token's hashed
// message equals SHA-256(message) — so the receipt is bound to exactly this
// message — and returns the authority's asserted time. A parse/signature failure
// or a digest mismatch is an error: the receipt does not prove this message.
func VerifyReceipt(message, token []byte) (time.Time, error) {
	if len(token) == 0 {
		return time.Time{}, fmt.Errorf("notary: empty receipt token")
	}
	ts, err := timestamp.Parse(token)
	if err != nil {
		return time.Time{}, fmt.Errorf("notary: invalid timestamp token: %w", err)
	}
	want := sha256.Sum256(message)
	if !bytes.Equal(ts.HashedMessage, want[:]) {
		return time.Time{}, fmt.Errorf("notary: receipt does not bind this message (timestamped digest differs)")
	}
	return ts.Time, nil
}
