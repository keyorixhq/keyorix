package keyfiles

import (
	"fmt"
	"slices"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
)

// StaleSaltPendingCandidate decides, without writing anything and without a
// passphrase, whether the KEK salt's staging file is a candidate for
// `admin encryption clear-stale-salt-pending` (#4105). It returns:
//
//   - "", nil: there is no salt staging file (nothing to do);
//   - path, nil: the salt staging file is present, no DEK staging file is, and
//     the key-set manifest does not need it (nothing staged, or a staged
//     operation abandoned before it changed the active set). The caller must
//     still prove that the active set opens without it, by unwrapping the DEK
//     under the active KEK (the proof AdoptProvenKeySet relies on), before it
//     removes the file;
//   - "", error: a refusal naming why the file must stay.
//
// The caller must hold the exclusive key lock, so no rotation writes between
// this decision and the removal. A DEK's staging file is never a candidate: it
// can be the only copy of the new DEK.
func StaleSaltPendingCandidate(enc *config.EncryptionConfig, baseDir string) (string, error) {
	pending, err := PendingRotationFiles(enc, baseDir)
	if err != nil {
		return "", fmt.Errorf("could not check the key directory for rotation staging files: %w", err)
	}
	salt := ""
	var dek []string
	for _, p := range pending {
		if p.Salt {
			salt = p.Path
		} else {
			dek = append(dek, p.Path)
		}
	}
	if len(dek) > 0 {
		return "", fmt.Errorf("%s is present: an interrupted DEK operation may need it, and it can be the only copy of the "+
			"new DEK, so nothing is removed while it exists. Start the server once so boot recovery promotes or discards it "+
			"(it is never deleted by hand), then run this command again", strings.Join(dek, ", "))
	}
	if salt == "" {
		return "", nil
	}
	st, err := InspectKeySet(enc, baseDir)
	if err != nil {
		return "", fmt.Errorf("the key set is refused, so %s is left in place: %w", salt, err)
	}
	if st.Fresh {
		return "", fmt.Errorf("no active key files are present, so nothing proves %s unused; it is left in place", salt)
	}
	if !slices.Contains(st.Leftovers, salt) {
		// PendingRotationFiles and InspectKeySet resolve the same configured
		// path; a disagreement means one of them changed, so fail closed.
		return "", fmt.Errorf("%s is not among the key set's staging files (%s); it is left in place",
			salt, strings.Join(st.Leftovers, ", "))
	}
	switch st.Intent {
	case IntentFinishable, IntentCompleted:
		return "", fmt.Errorf("the key-set manifest %s records an interrupted %s (%s) that boot has not settled, so %s may "+
			"be the salt it needs: start the server once (after an interrupted rotate-kek, with the NEW passphrase if the "+
			"start asks for it), then run this command again",
			st.ManifestPath, st.Manifest.Next.Operation, st.Intent, salt)
	}
	return salt, nil
}
