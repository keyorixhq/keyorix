package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// ShamirKeyProvider reconstructs the KEK from K-of-N Shamir shares (ADR-038): no
// single custodian holds the key. Each configured source — a file path or an
// environment variable — carries one share (hex or base64 of the raw share bytes,
// as emitted by `keyorix encryption shamir-split`). At KEK() time it reads the
// supplied shares (the operator provides at least the threshold many) and combines
// them; the result must be exactly KEKSize bytes or the unseal fails closed (too
// few / wrong shares reconstruct garbage rather than the real key).
type ShamirKeyProvider struct {
	shareFiles []string
	shareEnv   []string
}

// NewShamirKeyProvider builds a provider from share file paths and/or env var names.
func NewShamirKeyProvider(shareFiles, shareEnv []string) *ShamirKeyProvider {
	return &ShamirKeyProvider{shareFiles: shareFiles, shareEnv: shareEnv}
}

func (p *ShamirKeyProvider) Name() string { return "shamir" }

func (p *ShamirKeyProvider) KEK() ([]byte, error) {
	var shares [][]byte
	for _, path := range p.shareFiles {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path) // #nosec G304 -- operator-configured trusted share path
		if err != nil {
			return nil, fmt.Errorf("shamir key provider: read share %s: %w", path, err)
		}
		share, err := decodeShare(bytes.TrimSpace(data))
		if err != nil {
			return nil, fmt.Errorf("shamir key provider: share %s: %w", path, err)
		}
		shares = append(shares, share)
	}
	for _, envVar := range p.shareEnv {
		if envVar == "" {
			continue
		}
		val := os.Getenv(envVar)
		if val == "" {
			return nil, fmt.Errorf("shamir key provider: env var %s is not set or empty", envVar)
		}
		share, err := decodeShare([]byte(val))
		if err != nil {
			return nil, fmt.Errorf("shamir key provider: env var %s: %w", envVar, err)
		}
		shares = append(shares, share)
	}

	if len(shares) < 2 {
		return nil, fmt.Errorf("shamir key provider: need at least 2 shares (the configured threshold), got %d", len(shares))
	}
	kek, err := Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("shamir key provider: %w", err)
	}
	// A wrong/insufficient set of shares yields a wrong-length or simply incorrect
	// key; the size check catches the length case, and an incorrect 32-byte key
	// fails closed downstream when it cannot unwrap the DEK.
	return validateKEK(kek, "shamir")
}

// decodeShare accepts a Shamir share as raw bytes, hex, or base64 and returns the
// raw share bytes. Shares are KEKSize+1 bytes (a 1-byte x-coordinate), so unlike a
// KEK they are not a fixed-length match — decode by trying hex then base64, else
// treat the input as already-raw.
func decodeShare(material []byte) ([]byte, error) {
	s := strings.TrimSpace(string(material))
	if s == "" {
		return nil, fmt.Errorf("empty share")
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) >= 2 {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) >= 2 {
			return b, nil
		}
	}
	if len(material) >= 2 {
		return material, nil
	}
	return nil, fmt.Errorf("share must be raw bytes, hex, or base64 (at least 2 bytes)")
}
