// consistency.go — the boot-time key-file-set consistency check (ADR-112,
// follow-up from #2400). #2400 made a single RESTORE operation atomic: every
// file in the key-material set it installs is either all written or none
// are. What it does not (and cannot) catch is a set assembled across
// MULTIPLE operations — a second, partial restore; a manually copied-in
// file; one file restored from an older backup than its neighbors. This
// file adds the missing boot-time check for exactly that.
package keyfiles

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// keySetMtimeTolerance is how far apart two "KEK-establishing" files'
// modification times may be before VerifyKeySetConsistency treats the set as
// mixed from different generations/backups. Generous on purpose: every
// legitimate path that writes more than one of these files together
// (first-boot generation: ensureSaltExists/ensureWrappedDEKExists; KEK
// passphrase rotation: commitNewKEKFiles; a backup restore: #2400's own
// writeRestoredFileSet) writes them within the same operation, seconds
// apart at most. A gap measured in HOURS is never produced by any of those
// paths; it is the signature of files copied in from two different backups,
// or one restore followed much later by a second, partial one.
const keySetMtimeTolerance = 24 * time.Hour

// RequiredKeyFilePaths returns every on-disk key-material path enc's config
// requires to exist as a consistent set: the salt, the DEK, and (for the
// primary provider and each fallback, one level — matching Registry's own
// documented choice) the KMS/TPM wrapped-key blob and Shamir share files.
//
// Unlike Registry (registry.go), which only includes an OPTIONAL file (the
// .pending rotation-staging siblings) when it is CURRENTLY present, every
// path this function returns is unconditional: it names what the config
// says MUST exist, regardless of whether it currently does.
// VerifyKeySetConsistency needs exactly that distinction to tell "a
// legitimately-absent optional file" apart from "a required file missing
// from an otherwise-present set" — Registry's own return value can't make
// that distinction once an optional file has already been filtered out.
func RequiredKeyFilePaths(enc *config.EncryptionConfig, baseDir string) ([]string, error) {
	if enc == nil {
		return nil, nil
	}
	var paths []string
	seen := make(map[string]bool)
	add := func(label, path string) error {
		if path == "" {
			return nil
		}
		clean, err := SafePath(label, path)
		if err != nil {
			return err
		}
		full := resolve(baseDir, clean)
		if seen[full] {
			return nil
		}
		seen[full] = true
		paths = append(paths, full)
		return nil
	}
	if err := add("KEK salt", enc.SaltPath); err != nil {
		return nil, err
	}
	if err := add("DEK", enc.DEKPath); err != nil {
		return nil, err
	}
	providers := make([]config.KeyProviderConfig, 0, 1+len(enc.KeyProvider.Fallbacks))
	providers = append(providers, enc.KeyProvider)
	providers = append(providers, enc.KeyProvider.Fallbacks...)
	for i := range providers {
		kp := &providers[i]
		if writeCapableProviderTypes[kp.Type] {
			if err := add(kp.Type+" wrapped KEK", kp.WrappedKeyPath); err != nil {
				return nil, err
			}
		}
		if kp.Type == "shamir" {
			for j, share := range kp.ShamirShareFiles {
				if err := add(fmt.Sprintf("shamir share file [%d]", j), share); err != nil {
					return nil, err
				}
			}
		}
	}
	return paths, nil
}

// requiredKeyEstablishingPaths is RequiredKeyFilePaths minus the resolved DEK
// path — the subset VerifyKeySetConsistency's mtime check applies to. The DEK
// is deliberately excluded: RotateDEKWithSweep re-wraps it under the SAME
// KEK on its own, independent schedule (ADR-046 scheduled rotation, or a
// manual `keyorix encryption rotate-dek`) without touching the salt or any
// wrapped-KEK/Shamir-share file at all, so comparing the DEK's mtime against
// those would misfire on every ordinary rotation older than
// keySetMtimeTolerance. The salt, wrapped-KEK blob, and Shamir shares, by
// contrast, are only ever established together (first boot, KEK passphrase
// rotation, or a restore) and have no legitimate reason to drift apart.
func requiredKeyEstablishingPaths(enc *config.EncryptionConfig, baseDir string) ([]string, error) {
	all, err := RequiredKeyFilePaths(enc, baseDir)
	if err != nil {
		return nil, err
	}
	dekFull := ""
	if enc.DEKPath != "" {
		if clean, cerr := SafePath("DEK", enc.DEKPath); cerr == nil {
			dekFull = resolve(baseDir, clean)
		}
	}
	paths := make([]string, 0, len(all))
	for _, p := range all {
		if p != dekFull {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// VerifyKeySetConsistency is the boot-time key-file-set consistency check:
// the installed key files must either ALL be present (an already-
// provisioned deployment) or ALL be absent (a fresh install, about to
// generate them) — never a PARTIAL set, which no legitimate provisioning
// path produces and can only mean an incomplete restore, a manually deleted
// file, or files assembled from different backups. Among a fully-present
// set, every KEK-establishing file's (salt, wrapped-KEK blob, Shamir shares
// — see requiredKeyEstablishingPaths) modification time must fall within
// keySetMtimeTolerance of the oldest one's.
//
// Both checks fail closed, with every file path named — the ADR's own
// wording ("fail closed with a clear message naming the files"). Called
// unconditionally at boot (server/main.go), not gated behind
// security.enable_file_permission_check: a partial or mixed-generation key
// set is not a "weaker but working" state the way that flag's other checks
// guard — it is already broken, just not yet in a way that has surfaced.
func VerifyKeySetConsistency(enc *config.EncryptionConfig, baseDir string) error {
	if enc == nil {
		return nil
	}
	paths, err := RequiredKeyFilePaths(enc, baseDir)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return nil
	}

	infos := make(map[string]os.FileInfo, len(paths))
	var present, missing []string
	for _, p := range paths {
		info, statErr := os.Stat(p)
		if statErr != nil {
			missing = append(missing, p)
			continue
		}
		present = append(present, p)
		infos[p] = info
	}

	if len(missing) > 0 && len(present) > 0 {
		sort.Strings(present)
		sort.Strings(missing)
		return fmt.Errorf(
			"key material is an incomplete set: present (%s); missing (%s) — this is not a state any "+
				"provisioning path produces; restore the full set from one backup, or remove the partial "+
				"files and let first-boot generation recreate them",
			strings.Join(present, ", "), strings.Join(missing, ", "))
	}
	if len(present) == 0 {
		return nil // fresh install — first-boot generation will create these shortly
	}

	establishing, err := requiredKeyEstablishingPaths(enc, baseDir)
	if err != nil {
		return err
	}
	var oldestPath string
	var oldest time.Time
	for _, p := range establishing {
		info, ok := infos[p]
		if !ok {
			continue // not in the fully-present set checked above (shouldn't happen; defensive)
		}
		if oldest.IsZero() || info.ModTime().Before(oldest) {
			oldest = info.ModTime()
			oldestPath = p
		}
	}
	if oldestPath == "" {
		return nil // nothing to compare (e.g. only a DEK is configured, no salt/wrapped-key/shares)
	}
	var mismatched []string
	for _, p := range establishing {
		info, ok := infos[p]
		if !ok {
			continue
		}
		if gap := info.ModTime().Sub(oldest); gap > keySetMtimeTolerance {
			mismatched = append(mismatched, fmt.Sprintf("%s (modified %s, %s after %s)",
				p, info.ModTime().Format(time.RFC3339), gap.Round(time.Minute), oldestPath))
		}
	}
	if len(mismatched) > 0 {
		sort.Strings(mismatched)
		return fmt.Errorf(
			"key material set looks mixed from different generations: %s — if these files genuinely "+
				"belong together (e.g. a slow or manual provisioning step), this is a false positive; "+
				"otherwise restore the full set from a single backup",
			strings.Join(mismatched, "; "))
	}
	return nil
}
