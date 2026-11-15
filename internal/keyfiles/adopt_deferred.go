package keyfiles

// adopt_deferred.go — warn-and-adopt (#2900 criterion 4) for a set that has no
// manifest AND a rotation staging file ("<key file>.pending"), #2424.
//
// Without a manifest nothing records what an interrupted rotation was about to
// write, so a staging file is the only sign of it, and two states look alike:
// rotate-kek stopped before it changed the active set (old salt + old DEK,
// coherent, kek.salt.pending is garbage) or between its DEK and salt renames
// (old salt + NEW DEK, which no passphrase opens). Adopting at that point would
// record whichever it is as generation 1, and in the second state the fix (the
// salt staging file renamed into place) would then be refused at the next boot
// as a file from another generation. So boot does not adopt such a set before
// the key manager has opened it: AdoptProvenKeySet runs after a successful
// Initialize, an authenticated unwrap of the DEK under the on-disk KEK, which
// is the proof the active files belong together.

import (
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
)

// deferAdoption records in res that the manifest-less set st was not adopted
// because of its staging files, with the warning that says what to do.
func deferAdoption(st *KeySetState, enc *config.EncryptionConfig, baseDir string, res *ReconcileResult) {
	res.AdoptionDeferred = true
	saltPending := ""
	if enc.SaltPath != "" {
		if clean, err := SafePath("KEK salt", enc.SaltPath); err == nil {
			saltPending = resolve(baseDir, clean) + ".pending"
		}
	}
	backup := ""
	for _, l := range st.Leftovers {
		if l == saltPending {
			backup = fmt.Sprintf(" While %s exists, `admin backup` refuses (#4105).", l)
		}
	}
	res.Warnings = append(res.Warnings, fmt.Sprintf(
		"no key-set manifest, and rotation staging files are present (%s): an interrupted key rotation may have "+
			"replaced some active key files but not the others, so the current files are recorded in a new manifest "+
			"only once this start has opened them. If the start fails to unwrap the DEK, the rotation stopped between "+
			"its renames: follow \"Interrupted rotate-kek or migrate-provider\" in docs/operator/key-rotation-runbook.md, "+
			"and never delete a DEK's .pending file by hand.%s",
		strings.Join(st.Leftovers, ", "), backup))
}

// AdoptProvenKeySet adopts a complete set that has no manifest (or an
// unparseable one) as generation 1, like ReconcileKeySet does for a set
// without staging files. Call it only after the active set has been proved to
// open (a successful Initialize) and while holding the exclusive key lock;
// ReconcileKeySet's AdoptionDeferred says when. A set that has gained a
// manifest in between (DEK-rotation recovery committed one), a fresh set, or a
// set that is no longer consistent is left alone: nothing is adopted and
// InspectKeySet's refusal, if any, is returned.
func AdoptProvenKeySet(enc *config.EncryptionConfig, baseDir string, fs ManifestFS) (*ReconcileResult, error) {
	st, err := InspectKeySet(enc, baseDir)
	if err != nil {
		return nil, err
	}
	res := &ReconcileResult{}
	if st.Fresh || st.Manifest != nil {
		return res, nil
	}
	required, err := RequiredKeyFilePaths(enc, baseDir)
	if err != nil {
		return nil, err
	}
	note := "; adopted after this start opened the active set"
	if len(st.Leftovers) > 0 {
		note += fmt.Sprintf(", the staging files (%s) left out", strings.Join(st.Leftovers, ", "))
	}
	if err := adoptWholeSet(st, required, fs.withDefaults(), res, note); err != nil {
		return nil, err
	}
	return res, nil
}
