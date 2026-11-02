package auditverify

import (
	"crypto/fips140"
	"errors"
	"fmt"
)

// ErrCheckpointKeyTooShort is wrapped by Verify's refusal of an operator-supplied
// checkpoint key shorter than MinKEKLen under GODEBUG=fips140=only. Go's FIPS
// 140-only mode panics on an HMAC key under 112 bits, so such a key cannot be
// checked at all there; it is a usage error, not a verdict. Every real checkpoint
// key is 32 bytes (HKDF-SHA256 output).
var ErrCheckpointKeyTooShort = errors.New("checkpoint key too short")

// checkpointKeyFIPSEnforced is fips140.Enforced, a variable so the default-mode
// tests can drive the refusal.
var checkpointKeyFIPSEnforced = fips140.Enforced

// checkCheckpointKeyLens refuses, under FIPS enforcement, a non-empty
// CheckpointKey or PreviousCheckpointKeys entry shorter than MinKEKLen. An
// empty key still means "no key supplied". Outside that mode every key is
// accepted, and a wrong one is reported "not authenticated", as before.
func checkCheckpointKeyLens(opts Options) error {
	if !checkpointKeyFIPSEnforced() {
		return nil
	}
	check := func(which string, key []byte) error {
		if n := len(key); n > 0 && n < MinKEKLen {
			return fmt.Errorf("%w: %s is %d bytes; GODEBUG=fips140=only cannot check an HMAC key under MinKEKLen (%d bytes, 112 bits), and every real checkpoint key is 32 bytes: check the key file",
				ErrCheckpointKeyTooShort, which, n, MinKEKLen)
		}
		return nil
	}
	if err := check("the checkpoint key", opts.CheckpointKey); err != nil {
		return err
	}
	for i, k := range opts.PreviousCheckpointKeys {
		if err := check(fmt.Sprintf("previous checkpoint key #%d", i+1), k); err != nil {
			return err
		}
	}
	return nil
}
