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
// accepted, and a wrong one is reported "not authenticated", as before;
// CheckpointKeyLenWarnings reports a short one there.
func checkCheckpointKeyLens(opts Options) error {
	if !checkpointKeyFIPSEnforced() {
		return nil
	}
	if short := shortCheckpointKeys(opts); len(short) > 0 {
		return fmt.Errorf("%w: %s is %d bytes; GODEBUG=fips140=only cannot check an HMAC key under MinKEKLen (%d bytes, 112 bits), and every real checkpoint key is 32 bytes: check the key file",
			ErrCheckpointKeyTooShort, short[0].which, short[0].n, MinKEKLen)
	}
	return nil
}

// CheckpointKeyLenWarnings returns one line per non-empty key in opts shorter
// than MinKEKLen, naming only its length, for verify-audit to print before it
// runs. The key is still used. It returns nil under GODEBUG=fips140=only, where
// Verify refuses such a key instead.
func CheckpointKeyLenWarnings(opts Options) []string {
	if checkpointKeyFIPSEnforced() {
		return nil
	}
	var warnings []string
	for _, s := range shortCheckpointKeys(opts) {
		warnings = append(warnings, fmt.Sprintf("WARNING: %s is %d bytes, shorter than MinKEKLen (%d bytes, 112 bits). It is still used, but every real checkpoint key is 32 bytes and GODEBUG=fips140=only refuses this one: check the key file",
			s.which, s.n, MinKEKLen))
	}
	return warnings
}

// shortCheckpointKey is one supplied key below MinKEKLen; never the key itself.
type shortCheckpointKey struct {
	which string
	n     int
}

// shortCheckpointKeys lists the non-empty keys in opts shorter than MinKEKLen,
// the current key first.
func shortCheckpointKeys(opts Options) []shortCheckpointKey {
	var short []shortCheckpointKey
	add := func(which string, key []byte) {
		if n := len(key); n > 0 && n < MinKEKLen {
			short = append(short, shortCheckpointKey{which: which, n: n})
		}
	}
	add("the checkpoint key", opts.CheckpointKey)
	for i, k := range opts.PreviousCheckpointKeys {
		add(fmt.Sprintf("previous checkpoint key #%d", i+1), k)
	}
	return short
}
