// Package jwtdiff is diffkit Instance A: a differential oracle over the JWT
// verification decision. It compares github.com/golang-jwt/jwt/v5 against an
// INDEPENDENT, spec-derived reference verifier written on the Go standard library
// only (RFC 7515 JWS + RFC 7519 JWT), on attacker-controlled tokens with varying
// algorithm and key shapes (none, RS/HS confusion, wrong key, expired, nbf, aud
// arrays, signature tamper, kid).
//
// WHY A STDLIB REFERENCE AND NOT lestrrat-go/jwx: jwx was the intended second
// implementation, but it is unavailable offline in this environment (only the
// module metadata is cached, not the source zip). Rather than drop the instance,
// the second implementation is an independent verifier built from the spec on the
// standard library. It is a genuinely independent decision — the GOAL's framing —
// and is clearly labelled as such; it is NOT a jwx stand-in. See
// .scratch/kd-REPORT.md §0.
//
// WHAT THE ORACLE VERIFIES: that golang-jwt and the reference verifier reach the
// SAME accept/reject decision for a token verified under a PINNED config
// (expected algorithm family + the one genuine key + a required audience + a
// fixed clock, mirroring internal/core/sso.go verifyIDToken), and — when both
// accept — agree on the extracted subject (the `sub` claim).
//
// WHAT IT DOES NOT VERIFY:
//   - That either library is correct in absolute terms; a shared blind spot is
//     invisible to a differential oracle.
//   - Encryption (JWE), key resolution by `kid`/JWKS (the config pins ONE key),
//     `iss` checking beyond presence, `azp`, `nonce`, or `typ`/`crit` header
//     policy — those are verifyIDToken's job on top of this core decision.
//   - Any claim beyond sub/exp/nbf/aud; the reference verifier enforces exactly
//     the subset documented here, matched to the golang-jwt parser options used.
package jwtdiff

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keyorixhq/keyorix/fuzz/diffkit"
)

const perImplTimeout = 5 * time.Second

// input bundles the token string with the pinned verifier config. Both
// implementations receive the identical input.
type input struct {
	token string
	cfg   verifyConfig
}

// --- Impl 1: golang-jwt/jwt/v5 ------------------------------------------------

type golangJWT struct{}

func (golangJWT) Name() string { return "golang-jwt" }

func (golangJWT) Run(_ context.Context, in *input) (string, error) {
	cfg := in.cfg
	keyfunc := func(t *jwt.Token) (any, error) {
		switch cfg.expectedAlg {
		case "RS256":
			return cfg.rsaPub, nil
		case "ES256":
			return cfg.ecPub, nil
		case "HS256":
			return cfg.hmacKey, nil
		default:
			return nil, fmt.Errorf("unsupported expected alg %q", cfg.expectedAlg)
		}
	}
	tok, err := jwt.Parse(in.token, keyfunc,
		jwt.WithValidMethods([]string{cfg.expectedAlg}),
		jwt.WithExpirationRequired(),
		jwt.WithAudience(cfg.aud),
		jwt.WithTimeFunc(func() time.Time { return cfg.now }),
	)
	if err != nil {
		return "", err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("claims not MapClaims")
	}
	sub, _ := claims["sub"].(string)
	return sub, nil
}

// --- Impl 2: independent stdlib reference verifier ----------------------------

type refImpl struct{}

func (refImpl) Name() string { return "stdlib-ref" }

func (refImpl) Run(_ context.Context, in *input) (string, error) {
	cfg := in.cfg
	parts := strings.Split(in.token, ".")
	if len(parts) != 3 {
		return "", errors.New("not three segments")
	}
	hdrJSON, err := b64.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("header b64: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := strictJSON(hdrJSON, &hdr); err != nil {
		return "", fmt.Errorf("header json: %w", err)
	}
	// Algorithm pinning: reject none and any mismatch against the expected family.
	if hdr.Alg != cfg.expectedAlg {
		return "", fmt.Errorf("alg %q != expected %q", hdr.Alg, cfg.expectedAlg)
	}

	signingInput := parts[0] + "." + parts[1]
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("sig b64: %w", err)
	}
	if err := verifySig(cfg, signingInput, sig); err != nil {
		return "", err
	}

	payloadJSON, err := b64.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("payload b64: %w", err)
	}
	var claims map[string]any
	if err := strictJSON(payloadJSON, &claims); err != nil {
		return "", fmt.Errorf("payload json: %w", err)
	}

	nowSec := float64(cfg.now.Unix())
	// exp: required, numeric, not in the past.
	expv, ok := claims["exp"]
	if !ok {
		return "", errors.New("exp required")
	}
	exp, ok := expv.(float64)
	if !ok {
		return "", errors.New("exp not numeric")
	}
	if nowSec > exp {
		return "", errors.New("token expired")
	}
	// nbf: optional; if present must be numeric and not in the future.
	if nbfv, ok := claims["nbf"]; ok {
		nbf, ok := nbfv.(float64)
		if !ok {
			return "", errors.New("nbf not numeric")
		}
		if nowSec < nbf {
			return "", errors.New("token not yet valid")
		}
	}
	// aud: required; must contain the expected audience.
	if !audContains(claims["aud"], cfg.aud) {
		return "", errors.New("audience mismatch")
	}

	sub, _ := claims["sub"].(string)
	return sub, nil
}

func verifySig(cfg verifyConfig, signingInput string, sig []byte) error {
	h := sha256.Sum256([]byte(signingInput))
	switch cfg.expectedAlg {
	case "HS256":
		m := hmac.New(sha256.New, cfg.hmacKey)
		m.Write([]byte(signingInput))
		if !hmac.Equal(sig, m.Sum(nil)) {
			return errors.New("HS256 signature invalid")
		}
		return nil
	case "RS256":
		if err := rsa.VerifyPKCS1v15(cfg.rsaPub, crypto.SHA256, h[:], sig); err != nil {
			return fmt.Errorf("RS256 signature invalid: %w", err)
		}
		return nil
	case "ES256":
		if len(sig) != 64 {
			return errors.New("ES256 signature not 64 bytes")
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(cfg.ecPub, h[:], r, s) {
			return errors.New("ES256 signature invalid")
		}
		return nil
	default:
		return fmt.Errorf("unsupported alg %q", cfg.expectedAlg)
	}
}

// audContains reports whether the aud claim (a string or an array of strings)
// contains want. A missing or wrong-typed aud is not a match.
func audContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// strictJSON decodes exactly one JSON value and rejects trailing data, matching
// encoding/json's one-value contract that golang-jwt also relies on.
func strictJSON(data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing JSON")
	}
	return nil
}

// --- Comparator ---------------------------------------------------------------

func decide(o diffkit.Outcome[string]) diffkit.Verdict {
	v := diffkit.DecideFrom(o)
	if o.Decision == diffkit.DecisionAccept {
		v.Subject = o.Value
	}
	return v
}

// documentedDiffs starts empty by design: a row is added only after a divergence
// is triaged and understood, so the table can never pre-swallow a real finding.
var documentedDiffs []diffkit.DocumentedDiff

// NewComparator builds the Comparator comparing golang-jwt against the stdlib
// reference verifier.
func NewComparator() diffkit.Comparator[*input, string] {
	return diffkit.Comparator[*input, string]{
		Impls:   []diffkit.Impl[*input, string]{golangJWT{}, refImpl{}},
		Timeout: perImplTimeout,
		Decide:  decide,
		Diffs:   documentedDiffs,
	}
}
