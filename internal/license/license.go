// Package license implements Keyorix's offline license validation (ADR-065, ADR-062
// Phase 2). A license is a compact, signed token — base64url(payload).base64url(sig) — that
// a deployment validates locally against an ed25519 public key embedded at build time
// (trust.PurposeLicense). There is no phone-home.
//
// The enforcement posture is deliberately the INVERSE of update bundles. Bundles are
// fail-CLOSED: an unverifiable bundle must never be trusted. A license is fail-SAFE: a
// missing, expired, or invalid license must never deny access to existing secrets or stop
// the server — availability is itself a security property for a secrets manager, and a
// license lapse must not brick production. So `Evaluate` never errors out; it degrades to
// the community baseline (no commercial features) with a reason the caller surfaces as an
// admin warning + audit event. Enforcement gates commercial features only.
package license

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/trust"
)

// expiringSoonWindow is how long before not_after a still-valid license is flagged
// "expiring soon" so operators can renew ahead of a lapse.
const expiringSoonWindow = 30 * 24 * time.Hour

// License is the signed payload. Features are commercial-feature keys this license grants.
type License struct {
	Licensee     string    `json:"licensee"`
	Plan         string    `json:"plan"`
	Features     []string  `json:"features"`
	IssuedAt     time.Time `json:"issued_at"`
	NotAfter     time.Time `json:"not_after"`
	DeploymentID string    `json:"deployment_id,omitempty"`
	MaxSeats     int       `json:"max_seats,omitempty"`
	KeyID        string    `json:"key_id"`
}

// State is the evaluated license state. Only Active and ExpiringSoon grant features.
type State string

const (
	StateActive       State = "active"        // valid, in date
	StateExpiringSoon State = "expiring_soon" // valid and feature-granting, but near/just past expiry (within grace)
	StateExpired      State = "expired"       // past not_after + grace → baseline
	StateInvalid      State = "invalid"       // unparseable / bad signature / deployment mismatch → baseline
	StateNone         State = "none"          // no license installed → baseline
)

// Status is the result of evaluating a token. Features is the EFFECTIVE feature set —
// empty (community baseline) whenever the state is not feature-granting.
type Status struct {
	State        State
	Licensee     string
	Plan         string
	Features     []string
	NotAfter     time.Time
	DeploymentID string
	MaxSeats     int
	Reason       string // why degraded (for admin warning + audit); empty when Active
}

// Grants reports whether the license currently grants commercial features.
func (s Status) Grants() bool {
	return s.State == StateActive || s.State == StateExpiringSoon
}

// HasFeature reports whether feature f is granted right now. It is the single gate the rest
// of the server should call; it is false for every feature under a degraded license.
func (s Status) HasFeature(f string) bool {
	if !s.Grants() {
		return false
	}
	for _, x := range s.Features {
		if x == f {
			return true
		}
	}
	return false
}

// Issue marshals and signs a license into a compact token. Issuance-side only (the private
// key is the offline license-signing secret; it never ships).
func Issue(lic License, priv ed25519.PrivateKey) (string, error) {
	if strings.TrimSpace(lic.KeyID) == "" {
		return "", fmt.Errorf("license: key-id is required")
	}
	if strings.TrimSpace(lic.Licensee) == "" {
		return "", fmt.Errorf("license: licensee is required")
	}
	if lic.NotAfter.IsZero() {
		return "", fmt.Errorf("license: not_after is required")
	}
	payload, err := json.Marshal(&lic)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return enc(payload) + "." + enc(sig), nil
}

// parseToken splits and decodes a token into its raw payload bytes, signature, and the
// parsed License. It does not verify the signature.
func parseToken(token string) (payload, sig []byte, lic *License, err error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, nil, nil, fmt.Errorf("license: malformed token (want payload.sig)")
	}
	payload, err = dec(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("license: decode payload: %w", err)
	}
	sig, err = dec(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("license: decode signature: %w", err)
	}
	var l License
	if err := json.Unmarshal(payload, &l); err != nil {
		return nil, nil, nil, fmt.Errorf("license: parse payload: %w", err)
	}
	return payload, sig, &l, nil
}

// Evaluate validates a token offline and returns the effective Status. It NEVER returns an
// error: every failure mode (no token, bad signature, expiry, deployment mismatch) degrades
// to the community baseline with a Reason — the caller surfaces that as an admin warning and
// an audit event, but the server keeps running. deploymentID, when non-empty on both sides,
// must match (anti-copy binding). grace is the post-expiry tolerance window.
func Evaluate(token string, reg *trust.KeyRegistry, deploymentID string, now time.Time, grace time.Duration) Status {
	if strings.TrimSpace(token) == "" {
		return Status{State: StateNone, Reason: "no license installed — running the community baseline"}
	}
	payload, sig, lic, err := parseToken(token)
	if err != nil {
		return Status{State: StateInvalid, Reason: err.Error()}
	}
	if strings.TrimSpace(lic.KeyID) == "" {
		return Status{State: StateInvalid, Reason: "license has no key-id"}
	}
	// Verify against the embedded, pinned license key for this key-id. A forged key-id is
	// not in the registry, so this fails — and degrades, not denies.
	if err := reg.Verify(trust.PurposeLicense, lic.KeyID, payload, sig); err != nil {
		return Status{State: StateInvalid, Reason: "signature: " + err.Error()}
	}

	base := Status{
		Licensee:     lic.Licensee,
		Plan:         lic.Plan,
		NotAfter:     lic.NotAfter,
		DeploymentID: lic.DeploymentID,
		MaxSeats:     lic.MaxSeats,
	}

	// Anti-copy binding: a license bound to a deployment must not grant features on another.
	// Mismatch degrades (warn + audit), it does not shut anything down.
	if lic.DeploymentID != "" && deploymentID != "" && lic.DeploymentID != deploymentID {
		base.State = StateInvalid
		base.Reason = fmt.Sprintf("license is bound to deployment %q, not this deployment", lic.DeploymentID)
		return base
	}

	switch {
	case now.After(lic.NotAfter.Add(grace)):
		base.State = StateExpired
		base.Reason = fmt.Sprintf("license expired on %s — running the community baseline", lic.NotAfter.UTC().Format(time.RFC3339))
		return base
	case now.After(lic.NotAfter):
		// Past expiry but within grace: keep features (fail-safe) and warn loudly.
		base.State = StateExpiringSoon
		base.Features = lic.Features
		base.Reason = fmt.Sprintf("license expired on %s and is in its grace period — renew now", lic.NotAfter.UTC().Format(time.RFC3339))
		return base
	case now.After(lic.NotAfter.Add(-expiringSoonWindow)):
		base.State = StateExpiringSoon
		base.Features = lic.Features
		base.Reason = fmt.Sprintf("license expires on %s — renew soon", lic.NotAfter.UTC().Format(time.RFC3339))
		return base
	default:
		base.State = StateActive
		base.Features = lic.Features
		return base
	}
}

// --- helpers ---

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func dec(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
}

// ParsePrivateKeyPEM decodes a PKCS#8 PEM (as written by `keyorix trust keygen`) into an
// ed25519 license-signing key.
func ParsePrivateKeyPEM(b []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("license: no PEM block in signing key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("license: parse signing key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("license: signing key is not ed25519 (%T)", key)
	}
	return priv, nil
}
