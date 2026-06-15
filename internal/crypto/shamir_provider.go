package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// kekShareMagic frames a KEK before splitting so a reconstruction can be checked:
// it precedes the embedded threshold and the KEK bytes in the split payload. A
// reconstruction from too-few/wrong shares yields garbage whose first bytes will
// not equal the magic, so combineKEK rejects it — making sub-threshold unseal
// fail closed even on a FRESH install (where there is no existing wrapped DEK to
// fail against). The byte after the magic carries the threshold K so the provider
// can enforce that at least K shares were actually supplied.
const kekShareMagic = "KXK1"

// kekFrameLen is the framed-payload length: magic + 1 threshold byte + KEK.
const kekFrameLen = len(kekShareMagic) + 1 + KEKSize

// SplitKEK frames a 32-byte KEK (magic ‖ threshold ‖ KEK) and Shamir-splits it into
// parts shares with the given threshold. Reconstructing with combineKEK then both
// recovers the KEK and verifies enough correct shares were combined.
func SplitKEK(kek []byte, parts, threshold int) ([][]byte, error) {
	if len(kek) != KEKSize {
		return nil, fmt.Errorf("shamir: KEK must be %d bytes, got %d", KEKSize, len(kek))
	}
	if threshold < 2 || threshold > 255 {
		return nil, fmt.Errorf("shamir: threshold must be between 2 and 255, got %d", threshold)
	}
	payload := make([]byte, 0, kekFrameLen)
	payload = append(payload, kekShareMagic...)
	payload = append(payload, byte(threshold))
	payload = append(payload, kek...)
	return Split(payload, parts, threshold)
}

// combineKEK reconstructs a KEK from shares produced by SplitKEK. It fails closed
// when the magic does not match (too few or incorrect shares were combined) or
// when fewer than the embedded threshold shares were supplied.
func combineKEK(shares [][]byte) ([]byte, error) {
	payload, err := Combine(shares)
	if err != nil {
		return nil, err
	}
	if len(payload) != kekFrameLen || string(payload[:len(kekShareMagic)]) != kekShareMagic {
		return nil, fmt.Errorf("shamir: insufficient or incorrect shares — the reconstructed key failed its integrity check (supply at least the threshold many correct shares)")
	}
	threshold := int(payload[len(kekShareMagic)])
	if len(shares) < threshold {
		return nil, fmt.Errorf("shamir: %d shares supplied but the split requires %d (threshold)", len(shares), threshold)
	}
	return validateKEK(payload[len(kekShareMagic)+1:], "shamir")
}

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
		return nil, fmt.Errorf("shamir key provider: need at least 2 shares, got %d", len(shares))
	}
	// combineKEK enforces the embedded threshold and verifies the framing magic, so
	// a sub-threshold or wrong set of shares fails closed here — including on a fresh
	// install, where there is no existing wrapped DEK for a wrong KEK to fail against.
	kek, err := combineKEK(shares)
	if err != nil {
		return nil, fmt.Errorf("shamir key provider: %w", err)
	}
	return kek, nil
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
