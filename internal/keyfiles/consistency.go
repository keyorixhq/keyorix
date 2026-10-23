// consistency.go — the boot-time key-file-set consistency check (ADR-112,
// follow-up from #2400, completed by #2900). #2400 made a single RESTORE
// operation stage its whole file set before installing any of it. What it
// does not (and cannot) catch is a set assembled across MULTIPLE operations —
// a second, partial restore; a manually copied-in file; one file restored
// from an older backup than its neighbors. This file is the boot-time check
// for exactly that: presence/absence from os.Stat, generation membership from
// the key-set manifest (manifest.go).
package keyfiles

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
)

// allProviders returns the primary key provider followed by its fallbacks.
// It deliberately appends without a precomputed capacity: a `1+len(...)`
// size computation feeding make() is flagged by CodeQL as a possible
// allocation-size overflow, and the saving is irrelevant for a handful of
// providers.
func allProviders(enc *config.EncryptionConfig) []config.KeyProviderConfig {
	providers := []config.KeyProviderConfig{enc.KeyProvider}
	return append(providers, enc.KeyProvider.Fallbacks...)
}

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
	providers := allProviders(enc)
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

// KeySetFile is one present required key file as boot sees it.
type KeySetFile struct {
	Path string // full path
	Key  string // its name in the manifest
	// Recorded: the manifest has an entry for it. MatchesRecorded: its content
	// hashes to that entry. MatchesStaged: it hashes to the staged intent's
	// hash for it (an operation that replaced it but did not commit).
	Recorded, MatchesRecorded, MatchesStaged bool
	Entry                                    ManifestEntry
}

// KeySetState is what InspectKeySet found.
type KeySetState struct {
	ManifestPath string
	// Fresh: no required file exists (a first boot is about to create them).
	Fresh bool
	// Manifest is nil when ManifestErr is set (it wraps ErrManifestMissing or
	// ErrManifestInvalid).
	Manifest    *Manifest
	ManifestErr error
	Files       []KeySetFile
}

// InspectKeySet reads the key set enc describes and classifies every present
// required file against the manifest, without writing anything and without a
// passphrase. It returns an error — the boot refusal — for a set no
// legitimate operation leaves behind:
//
//   - a PARTIAL set: some required files present, some missing. Decidable
//     from os.Stat alone, and unaffected by how the files got there.
//   - a MIXED set: a present file whose content matches neither its recorded
//     hash nor a staged one. The file comes from a different generation than
//     the manifest describes (restored from another backup, copied in, or
//     rewritten by a tool that does not maintain the manifest), whatever its
//     mtime — cp, install, docker cp and kubectl cp all stamp the current time,
//     which is why the mtime heuristic this replaces could not see it.
//
// A leftover "*.pending" rotation-staging file is never part of the required
// set (RequiredKeyFilePaths does not add one), so it cannot make a set
// partial.
func InspectKeySet(enc *config.EncryptionConfig, baseDir string) (*KeySetState, error) {
	if enc == nil {
		return &KeySetState{Fresh: true}, nil
	}
	paths, err := RequiredKeyFilePaths(enc, baseDir)
	if err != nil {
		return nil, err
	}
	manifestPath, err := ManifestPath(enc, baseDir)
	if err != nil {
		return nil, err
	}
	st := &KeySetState{ManifestPath: manifestPath}
	if len(paths) == 0 {
		st.Fresh = true
		return st, nil
	}

	var present, missing []string
	for _, p := range paths {
		if _, statErr := os.Stat(p); statErr != nil {
			missing = append(missing, p)
			continue
		}
		present = append(present, p)
	}
	if len(missing) > 0 && len(present) > 0 {
		sort.Strings(present)
		sort.Strings(missing)
		return nil, fmt.Errorf(
			"key material is an incomplete set: present (%s); missing (%s) — this is not a state any "+
				"provisioning path produces; restore the full set from one backup, or remove the partial "+
				"files and let first-boot generation recreate them",
			strings.Join(present, ", "), strings.Join(missing, ", "))
	}
	if len(present) == 0 {
		st.Fresh = true // first-boot generation will create these shortly
		return st, nil
	}

	m, err := LoadManifest(manifestPath)
	if err != nil {
		st.ManifestErr = err
		return st, nil
	}
	st.Manifest = m

	mdir := filepath.Dir(manifestPath)
	var foreign []string
	for _, p := range present {
		h, herr := hashKeyFile(p)
		if herr != nil {
			return nil, fmt.Errorf("key material %s cannot be read to check it against the key-set manifest: %w", p, herr)
		}
		f := KeySetFile{Path: p, Key: manifestKey(mdir, p)}
		f.Entry, f.Recorded = m.Files[f.Key]
		f.MatchesRecorded = f.Recorded && f.Entry.SHA256 == h
		if m.Next != nil {
			f.MatchesStaged = m.Next.Files[f.Key] == h
		}
		if f.Recorded && !f.MatchesRecorded && !f.MatchesStaged {
			foreign = append(foreign, fmt.Sprintf("%s (recorded by %s at generation %d)", p, f.Entry.Operation, f.Entry.Generation))
		}
		st.Files = append(st.Files, f)
	}
	if len(foreign) > 0 {
		sort.Strings(foreign)
		return nil, fmt.Errorf(
			"key material does not match the key-set manifest %s: %s — these files come from a different "+
				"generation than the rest of the set (for example restored or copied from another backup); "+
				"restore the whole set from one backup with `keyorix-server admin restore`, which records a new "+
				"manifest. If you replaced them deliberately with a tool that does not maintain the manifest "+
				"(an older keyorix-server binary, see docs/UPGRADING.md), remove %s and the next start adopts "+
				"the current files with a warning and an audit event",
			manifestPath, strings.Join(foreign, "; "), manifestPath)
	}
	return st, nil
}

// VerifyKeySetConsistency is the boot-time key-file-set consistency check:
// InspectKeySet's refusals, nothing written. Called unconditionally at boot
// (server/main.go's bootRefusals), before initializeEncryption can generate
// anything, and not gated behind security.enable_file_permission_check: a
// partial or mixed key set is not a "weaker but working" state the way that
// flag's other checks guard — it is already broken, just not yet in a way
// that has surfaced. Every message names the files, as ADR-112 asks.
func VerifyKeySetConsistency(enc *config.EncryptionConfig, baseDir string) error {
	_, err := InspectKeySet(enc, baseDir)
	return err
}

// IsManifestMissing reports whether st found no manifest at all (as opposed
// to an unparseable one).
func (st *KeySetState) IsManifestMissing() bool {
	return st != nil && errors.Is(st.ManifestErr, ErrManifestMissing)
}
