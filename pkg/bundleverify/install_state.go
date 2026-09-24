package bundleverify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrInstallStateReset means the external install-state record (see
// readExternalInstallState below) remembers a previously-installed version for this
// destDir, but destDir itself shows no trace of one — the same signature
// readInstalledVersion's own fix already catches for a marker-only deletion, except here
// the ENTIRE destDir (marker included) was removed.
//
// This external record is a second copy of the installed version, written to a fixed
// location outside destDir (see externalStateBaseDir) every time Extract/
// ExtractAllowingStateReset succeeds. An actor who can rm -rf destDir cannot, by that
// action alone, also erase this external record — deleting destDir no longer resets the
// gate to "first install" with zero signal; it now produces a detectable mismatch that has
// to be explicitly resolved (see ExtractAllowingStateReset).
var ErrInstallStateReset = errors.New("bundle: external install-state record exists for this destination, but destDir shows no trace of a prior install")

// installStateDirEnvOverride lets an operator (or a test) pin the external install-state
// directory explicitly, taking priority over the XDG/home-directory defaults below.
const installStateDirEnvOverride = "KEYORIX_BUNDLE_STATE_DIR"

// installStateDisabledValue is a distinguished installStateDirEnvOverride value that
// explicitly opts out of external install-state tracking, degrading to the internal-marker-
// only protection that existed before this record (documented, not silent).
const installStateDisabledValue = "-"

// externalStateBaseDir resolves the directory external install-state records are kept in:
// an explicit override, then XDG_CONFIG_HOME, then $HOME/.keyorix, then "" (unresolvable).
// It deliberately never falls back to a shared/world-writable temp directory.
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
// live at, or "" if no external base directory is resolvable. It is keyed by the SHA-256
// of destDir's absolute, cleaned form so distinct destinations never collide and the
// record's filename never embeds a raw filesystem path.
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
// false when no external directory is resolvable, or none exists yet for this destDir. A
// present-but-corrupt/unreadable record fails closed, the same posture readInstalledVersion
// already takes for the internal marker.
func readExternalInstallState(destDir string) (version string, ok bool, err error) {
	path, err := externalStatePath(destDir)
	if err != nil {
		return "", false, err
	}
	if path == "" {
		return "", false, nil
	}
	base, name := filepath.Dir(path), filepath.Base(path)
	if fi, statErr := os.Stat(base); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("bundle: check external install-state directory: %w", statErr)
	} else if !fi.IsDir() {
		return "", false, fmt.Errorf("bundle: external install-state path %q exists and is not a directory", base)
	}
	b, err := readFileNoFollow(base, name)
	if err != nil {
		if os.IsNotExist(err) {
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
// an error — the write is silently skipped, and protection degrades to the internal marker
// alone, exactly as it existed before this record was introduced.
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
	if err := writeFileNoFollow(base, name, b, 0o600); err != nil {
		return fmt.Errorf("bundle: write external install-state record: %w", err)
	}
	return nil
}

// reconcileInstallState is the single point where the internal marker (readInstalledVersion,
// living inside destDir) and the external install-state record (readExternalInstallState,
// living outside it) are compared. See install_state_test.go / bundleverify_test.go for the
// full case matrix (both present+agreeing, internal-only, external-only, disagreeing).
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
