package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// ErrInstallStateReset means the external install-state record (see
// readExternalInstallState below) remembers a previously-installed version for this
// destDir, but destDir itself shows no trace of one — the same signature
// readInstalledVersion's own #111 fix already catches for a marker-only deletion, except
// here the ENTIRE destDir (marker included) was removed.
//
// readInstalledVersion's #111 fix closes one path to resetting the no-downgrade gate:
// deleting only the marker file while other staged component files remain is detected
// (destDirHasContent still sees the leftover files) and refused. It does not close the
// other, equally trivial path: deleting the WHOLE destDir. destDirHasContent returns
// false for both a directory that never existed and one that existed and was wiped —
// there is no way to tell them apart by looking only inside destDir, because the marker
// that would normally say "something was here" lives in the very directory being wiped.
// A first-install check that only ever looks inside destDir cannot, even in principle,
// distinguish "nothing has ever been staged here" from "something was staged here and
// then removed" — the evidence for the second case has to live somewhere else.
//
// This external record is that somewhere else: a second copy of the installed version,
// written to a fixed location outside destDir (see externalStateBaseDir) every time
// Extract/ExtractAllowingStateReset succeeds. An actor who can rm -rf destDir cannot, by
// that action alone, also erase this external record — deleting destDir no longer resets
// the gate to "first install" with zero signal; it now produces a detectable mismatch
// that has to be explicitly resolved (see ExtractAllowingStateReset).
var ErrInstallStateReset = errors.New("bundle: external install-state record exists for this destination, but destDir shows no trace of a prior install")

// installStateDirEnvOverride lets an operator (or a test) pin the external install-state
// directory explicitly, taking priority over the XDG/home-directory defaults below. This
// matters when no $HOME is available at all (e.g. a minimal service-account container
// running scheduled imports) and when an operator wants the record kept somewhere more
// deliberately separated from --dest than their own home directory.
const installStateDirEnvOverride = "KEYORIX_BUNDLE_STATE_DIR"

// installStateDisabledValue is a distinguished installStateDirEnvOverride value that
// explicitly opts out of external install-state tracking, degrading to the internal-marker-
// only protection that existed before this record (documented, not silent). This is
// distinct from simply leaving the variable unset, which instead falls through to the
// XDG_CONFIG_HOME / $HOME/.keyorix defaults below — an unset override must not be
// mistakable for "disabled" given those defaults usually do resolve to somewhere real.
const installStateDisabledValue = "-"

// externalStateBaseDir resolves the directory external install-state records are kept
// in, mirroring the precedent already established for the CLI's own config file
// (internal/cli/config.getDefaultCLIConfigPath): an explicit override, then
// XDG_CONFIG_HOME, then $HOME/.keyorix, then "" (unresolvable). It deliberately never
// falls back to a shared/world-writable temp directory: the entire point is a location
// that is NOT simply "one more thing inside (or trivially alongside) the operator-
// supplied, potentially more widely writable --dest staging directory."
//
// An unresolvable result ("") is not itself an error — see readExternalInstallState /
// writeExternalInstallState — it degrades to the internal-marker-only protection that
// existed before this record, which is documented, not silent.
func externalStateBaseDir() string {
	if v := strings.TrimSpace(os.Getenv(installStateDirEnvOverride)); v != "" {
		if v == installStateDisabledValue {
			return ""
		}
		return filepath.Join(v, "bundle-installs")
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "keyorix", "bundle-installs")
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".keyorix", "bundle-installs")
	}
	return ""
}

// externalStateRecord is the on-disk shape of one external install-state record.
type externalStateRecord struct {
	DestDir string `json:"dest_dir"`
	Version string `json:"version"`
}

// externalStatePath returns the path the external install-state record for destDir would
// live at, or "" if no external base directory is resolvable (see externalStateBaseDir).
// It is keyed by the SHA-256 of destDir's absolute, cleaned form so distinct destinations
// never collide and the record's filename never embeds a raw filesystem path.
func externalStatePath(destDir string) (string, error) {
	base := externalStateBaseDir()
	if base == "" {
		return "", nil
	}
	abs, err := filepath.Abs(destDir)
	if err != nil {
		return "", fmt.Errorf("bundle: resolve destination for install-state key: %w", err)
	}
	sum := sha256.Sum256([]byte(filepath.Clean(abs)))
	return filepath.Join(base, hex.EncodeToString(sum[:])+".json"), nil
}

// readExternalInstallState reads the external install-state record for destDir. ok is
// false when no external directory is resolvable, or none exists yet for this destDir —
// both are unremarkable (external tracking is new, or this destination has simply never
// been recorded before). A present-but-corrupt/unreadable record fails closed, the same
// posture readInstalledVersion already takes for the internal marker.
func readExternalInstallState(destDir string) (version string, ok bool, err error) {
	path, err := externalStatePath(destDir)
	if err != nil {
		return "", false, err
	}
	if path == "" {
		return "", false, nil
	}
	base, name := filepath.Dir(path), filepath.Base(path)
	// If the external state directory itself doesn't exist yet, there is certainly no
	// record in it — return the ordinary "nothing recorded" result without ever calling
	// securefiles.SafeReadFile. This sidesteps a real quirk beyond just avoiding a
	// pointless syscall: SafeReadFile's containment check (isPathInsideBase) resolves
	// symlinks on baseDir only when baseDir itself already exists; when it doesn't, the
	// check falls back to resolving the target's longest EXISTING ancestor instead (e.g.
	// this base dir's own parent, which does exist) — on a platform where that ancestor
	// sits behind a symlink (macOS: /var -> /private/var), the two resolve to different
	// prefixes and SafeReadFile spuriously reports "outside of" the very base directory it
	// was just joined from. Guaranteeing base exists before ever calling SafeReadFile
	// (both here and in writeExternalInstallState's mkdirAllNoSymlink call) avoids the
	// mismatch entirely instead of working around it after the fact.
	if fi, statErr := os.Stat(base); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("bundle: check external install-state directory: %w", statErr)
	} else if !fi.IsDir() {
		return "", false, fmt.Errorf("bundle: external install-state path %q exists and is not a directory", base)
	}
	b, err := securefiles.SafeReadFile(base, name)
	if err != nil {
		// securefiles.SafeReadFile's underlying open walks through several layers of
		// fmt.Errorf("...: %w", ...) wrapping (secureOpenBeneath's own "open base
		// directory" / per-component errors) before reaching the raw ENOENT — plain
		// os.IsNotExist does not unwrap arbitrary %w chains (it only recognizes
		// *PathError/*LinkError/*SyscallError directly), so it would misreport "no
		// record yet" as a hard read error here. errors.Is walks the full chain and
		// syscall.Errno implements Is(fs.ErrNotExist), so this correctly recognizes
		// "the bundle-installs directory, or the record file in it, doesn't exist yet"
		// as the ordinary, unremarkable case it is.
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("bundle: read external install-state record: %w", err)
	}
	var rec externalStateRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return "", false, fmt.Errorf("bundle: parse external install-state record %q: %w", path, err)
	}
	if strings.TrimSpace(rec.Version) == "" {
		return "", false, fmt.Errorf("bundle: external install-state record %q has no version", path)
	}
	return strings.TrimSpace(rec.Version), true, nil
}

// writeExternalInstallState persists version as the external install-state record for
// destDir. A non-resolvable external directory (externalStateBaseDir returning "") is not
// an error — the write is silently skipped, and protection degrades to the internal
// marker alone, exactly as it existed before this record was introduced.
func writeExternalInstallState(destDir, version string) error {
	path, err := externalStatePath(destDir)
	if err != nil {
		return err
	}
	if path == "" {
		return nil
	}
	base, name := filepath.Dir(path), filepath.Base(path)
	if err := mkdirAllNoSymlink(base, base); err != nil {
		return fmt.Errorf("bundle: create external install-state directory: %w", err)
	}
	abs, err := filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("bundle: resolve destination for install-state record: %w", err)
	}
	rec := externalStateRecord{DestDir: filepath.Clean(abs), Version: version}
	b, err := json.Marshal(&rec)
	if err != nil {
		return err
	}
	if err := securefiles.SecureWriteFileSync(base, name, b, 0o600); err != nil {
		return fmt.Errorf("bundle: write external install-state record: %w", err)
	}
	return nil
}

// reconcileInstallState is the single point where the internal marker (readInstalledVersion,
// living inside destDir) and the external install-state record (readExternalInstallState,
// living outside it) are compared. It is the function both Extract's own no-downgrade gate
// (resolveIdempotentInstall) and the CLI's pre-flight check (PersistedInstalledVersion)
// call, so the same rule applies everywhere destDir's install state is consulted, not just
// at one of the two call sites.
//
//   - Internal error (an unreadable marker, or "content but no marker" — #111): returned
//     verbatim. The external record only ever ADDS a check on top of this one; it never
//     loosens it.
//   - Both present and agreeing: return that version, anchored (the ordinary case for
//     every import after the first).
//   - Internal present, external absent: accepted as-is (a marker predating this feature,
//     or a destination whose external directory only just became resolvable) — not
//     suspicious. writeExternalInstallState backfills the external record on the next
//     successful import.
//   - Internal present, external present, but DISAGREEING: destDir's own marker was
//     edited in place to claim an older installed version (a variant #111's "content but
//     no marker" check cannot see, since the marker is still present — just wrong).
//     Refused unless acknowledgeReset is true, in which case the internal value is
//     trusted (it reflects what destDir actually, physically holds) and CheckUpgrade
//     still runs against it — acknowledging a reset does not disable the downgrade check.
//   - Internal absent, external present: destDir looks like a fresh/first install, but the
//     external record remembers otherwise — the wiped-destDir attack this whole mechanism
//     exists to catch. Refused (ErrInstallStateReset) unless acknowledgeReset is true, in
//     which case this is treated as a genuine first install (no anchor).
//   - Neither present: an ordinary, unremarkable first install.
func reconcileInstallState(destDir string, acknowledgeReset bool) (version string, ok bool, err error) {
	intVersion, intOk, err := readInstalledVersion(destDir)
	if err != nil {
		return "", false, err
	}
	extVersion, extOk, err := readExternalInstallState(destDir)
	if err != nil {
		return "", false, err
	}

	switch {
	case intOk && extOk:
		if intVersion == extVersion {
			return intVersion, true, nil
		}
		if acknowledgeReset {
			return intVersion, true, nil
		}
		return "", false, fmt.Errorf(
			"%w: destination marker at %q records %q but the external install-state record says %q — "+
				"one of the two disagrees with the other (possible tampering, or a partially-applied "+
				"manual fix); if this destination's install state was intentionally reset, re-run with "+
				"the reset explicitly acknowledged",
			ErrInstallStateReset, destDir, intVersion, extVersion)
	case intOk && !extOk:
		return intVersion, true, nil
	case !intOk && extOk:
		if acknowledgeReset {
			return "", false, nil
		}
		return "", false, fmt.Errorf(
			"%w: external install-state record says %q was previously imported into %q, but the "+
				"destination itself shows no trace of it — this is exactly what deleting the whole "+
				"destination (instead of just its marker file) would produce; if this destination's "+
				"install state was intentionally reset (e.g. deliberately cleared for a fresh start), "+
				"re-run with the reset explicitly acknowledged, otherwise treat this as a possible "+
				"downgrade attempt and investigate before proceeding",
			ErrInstallStateReset, extVersion, destDir)
	default:
		return "", false, nil
	}
}
