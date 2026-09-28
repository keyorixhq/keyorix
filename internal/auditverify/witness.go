package auditverify

import (
	"fmt"
	"os"
	"path/filepath"
)

// AuditHighWaterWitnessFileName is the host-local witness file
// design-b3-backup-v2.md §6.3's rollback protection compares an archive's
// recorded high-water mark against. Sibling to the database file, never a
// backup archive tar member and never listed in internal/keyfiles.Registry —
// it must survive being overwritten by whatever `admin restore` writes, or
// comparing an old archive against its own (also-old) embedded state would
// prove nothing (see this const's callers' own doc comments for the full
// reasoning).
const AuditHighWaterWitnessFileName = ".audit-highwater-witness"

// WitnessPath returns the witness-file path for a database at dbPath:
// sibling to it, in the same directory. Both the live server (writing the
// witness as the real audit trail advances) and `admin backup`/`admin
// restore` (reading/writing it around a restore) must resolve this
// identically, so this is the single, shared definition of that
// convention — do not recompute it inline elsewhere.
func WitnessPath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), AuditHighWaterWitnessFileName)
}

// ReadWitness reads and parses the witness file at path. found=false (with a
// nil error) is the legitimate "no witness yet" state — a fresh host, or one
// that has never advanced the audit high-water mark — not an error condition;
// callers must treat it as "nothing to compare against," never as "assume
// zero and refuse." A witness file that EXISTS but fails to parse IS
// surfaced as an error (unlike absence): something wrote garbage there, and
// silently treating a corrupted witness as absent would let a rollback-
// protection bypass hide behind "just delete/corrupt the witness file,"
// exactly the class of gap this mechanism exists to close.
func ReadWitness(path string) (cp *Checkpoint, sig string, found bool, err error) {
	data, err := os.ReadFile(path) // #nosec G304 -- caller-resolved sibling-of-DB path, not archive/request input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", false, nil
		}
		return nil, "", false, fmt.Errorf("read witness file %q: %w", path, err)
	}
	parsedCP, parsedSig, ok := ParseHighWater(string(data))
	if !ok {
		return nil, "", false, fmt.Errorf("witness file %q exists but does not parse as a high-water mark — "+
			"it may be corrupted or tampered with; do not treat this as if no witness existed", path)
	}
	return parsedCP, parsedSig, true, nil
}

// WriteWitnessIfHigher atomically writes encodedValue (the same
// auditHighWaterValue-encoded string internal/core persists to
// system_metadata — this package's ParseHighWater already knows that exact
// format) to path, but ONLY if its ChainedEvents exceeds whatever is already
// recorded there (or nothing is recorded yet). Mirrors
// internal/core.advanceAuditHighWater's own "never lower the mark"
// invariant — the witness must never regress, or a later restore could be
// tricked into comparing against an artificially-lowered reference. Returns
// wrote=false (no error) when the existing witness is already at least as
// high; this is the expected, silent no-op case on every routine call, not a
// failure.
//
// A malformed encodedValue never reaches disk (fails before any write) — a
// caller passing a value this package's own ParseHighWater cannot round-trip
// indicates a caller bug, not something to persist and let a later reader
// choke on.
func WriteWitnessIfHigher(path, encodedValue string) (wrote bool, err error) {
	newCP, _, ok := ParseHighWater(encodedValue)
	if !ok {
		return false, fmt.Errorf("witness value does not parse as a high-water mark, refusing to write it: %q", encodedValue)
	}

	existingCP, _, found, err := ReadWitness(path)
	if err != nil {
		return false, err
	}
	if found && existingCP.ChainedEvents >= newCP.ChainedEvents {
		return false, nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return false, fmt.Errorf("create witness directory %q: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return false, fmt.Errorf("create temp witness file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) //nolint:errcheck // no-op once renamed into place below

	if _, err := tmp.WriteString(encodedValue); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("write temp witness file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("fsync temp witness file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close temp witness file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		return false, fmt.Errorf("set witness file mode: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return false, fmt.Errorf("rename witness file into place: %w", err)
	}
	return true, nil
}
