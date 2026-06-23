// Package bundle implements Keyorix's air-gapped update bundles (ADR-064, ADR-062
// Phase 1a). A bundle is a single gzip-compressed tar carrying a versioned set of release
// artifacts (images, charts, CRDs, binaries, migrations) plus a signed manifest that pins
// every component by sha256. An air-gapped operator carries the file across the gap and
// verifies it offline against an embedded, pinned ed25519 public key — so trust follows a
// pinned chain (the key never travels with the bundle), not a self-described signature.
//
// This package is the cryptographic and structural core: build a manifest, sign it, write
// the bundle, verify it (signature first, then every component digest, fail closed), and
// Extract it — staging the verified components to disk, gated on no-downgrade, atomically.
// It deliberately stops at staging: loading images into an internal registry and running
// the Helm upgrade stay the operator's own steps (an air-gap tool must not seize control of
// the registry), so the CLI prints those next steps rather than performing them.
package bundle

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/trust"
)

// Reserved entry names that carry the manifest and its signature, not bundle components.
const (
	manifestName = "manifest.json"
	sigName      = "manifest.sig"
)

// maxManifestBytes caps the in-memory manifest/signature reads so a malformed bundle
// can't exhaust memory before the signature is even checked. A real manifest is a few KiB.
const maxManifestBytes = 4 << 20 // 4 MiB

var (
	// ErrNoManifest means the archive did not begin with manifest.json + manifest.sig.
	ErrNoManifest = errors.New("bundle: manifest.json/manifest.sig missing or out of order")
	// ErrDigestMismatch means a component's bytes did not match its pinned sha256.
	ErrDigestMismatch = errors.New("bundle: component digest mismatch")
	// ErrUnlistedComponent means the archive carried a file not pinned in the manifest.
	ErrUnlistedComponent = errors.New("bundle: file not listed in manifest")
	// ErrMissingComponent means the manifest pinned a file the archive did not contain.
	ErrMissingComponent = errors.New("bundle: manifest component missing from archive")
	// ErrNotUpgrade means the bundle version is not newer than what is installed.
	ErrNotUpgrade = errors.New("bundle: version is not an upgrade over the installed version")
	// ErrUpgradeSkipped means the installed version is older than the bundle's min_upgrade_from.
	ErrUpgradeSkipped = errors.New("bundle: installed version is below the bundle's minimum upgrade-from")
)

// Component pins one file in the bundle by its digest and size. Path is a clean,
// forward-slash, relative path (e.g. "charts/keyorix-0.81.0.tgz").
type Component struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest describes a bundle: what version it carries, the components it pins, the
// signing key-id, and the anti-skip floor. Signing the manifest transitively authenticates
// every component, because each is pinned by sha256.
type Manifest struct {
	Version        string      `json:"version"`
	ReleasedAt     time.Time   `json:"released_at"`
	MinUpgradeFrom string      `json:"min_upgrade_from,omitempty"`
	KeyID          string      `json:"key_id"`
	Components     []Component `json:"components"`
}

// MarshalCanonical renders the manifest deterministically (components sorted by path,
// indented) so the same inputs always produce byte-identical manifest.json — the bytes
// that get signed and, at verify time, re-checked against the signature.
func (m *Manifest) MarshalCanonical() ([]byte, error) {
	c := *m
	c.Components = append([]Component(nil), m.Components...)
	sort.Slice(c.Components, func(i, j int) bool { return c.Components[i].Path < c.Components[j].Path })
	return json.MarshalIndent(&c, "", "  ")
}

// component lookup helper.
func (m *Manifest) byPath() map[string]Component {
	idx := make(map[string]Component, len(m.Components))
	for _, c := range m.Components {
		idx[c.Path] = c
	}
	return idx
}

// cleanComponentPath validates a component path is relative, normalized, and contained —
// no absolute paths, no "..", no leading slash. Returned in clean forward-slash form.
func cleanComponentPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("bundle: empty component path")
	}
	if path.IsAbs(p) || strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("bundle: absolute component path %q", p)
	}
	clean := path.Clean(filepath.ToSlash(p))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("bundle: component path escapes the bundle: %q", p)
	}
	if clean == manifestName || clean == sigName {
		return "", fmt.Errorf("bundle: component path %q collides with a reserved name", p)
	}
	return clean, nil
}

// BuildManifest walks srcDir and pins every regular file (by relative path) with its
// sha256 and size. It refuses reserved names; manifest.json/manifest.sig are written by
// WriteBundle, not taken from srcDir.
func BuildManifest(srcDir, version, keyID, minUpgradeFrom string, releasedAt time.Time) (*Manifest, error) {
	if strings.TrimSpace(version) == "" {
		return nil, fmt.Errorf("bundle: version is required")
	}
	if _, err := parseVersion(version); err != nil {
		return nil, fmt.Errorf("bundle: version %q: %w", version, err)
	}
	if strings.TrimSpace(keyID) == "" {
		return nil, fmt.Errorf("bundle: key-id is required")
	}
	if minUpgradeFrom != "" {
		if _, err := parseVersion(minUpgradeFrom); err != nil {
			return nil, fmt.Errorf("bundle: min-upgrade-from %q: %w", minUpgradeFrom, err)
		}
	}

	var components []Component
	err := filepath.WalkDir(srcDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}
		clean, err := cleanComponentPath(rel)
		if err != nil {
			return err
		}
		sum, size, err := hashFile(p)
		if err != nil {
			return err
		}
		components = append(components, Component{Path: clean, SHA256: sum, Size: size})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(components) == 0 {
		return nil, fmt.Errorf("bundle: no files found under %q", srcDir)
	}
	sort.Slice(components, func(i, j int) bool { return components[i].Path < components[j].Path })
	return &Manifest{
		Version:        strings.TrimSpace(version),
		ReleasedAt:     releasedAt.UTC(),
		MinUpgradeFrom: strings.TrimSpace(minUpgradeFrom),
		KeyID:          strings.TrimSpace(keyID),
		Components:     components,
	}, nil
}

// WriteBundle writes the signed bundle to w: manifest.json first, then manifest.sig, then
// every component file (sorted by path). sig must be an ed25519 signature over the exact
// canonical manifest bytes (see Sign).
func WriteBundle(w io.Writer, srcDir string, m *Manifest, sig []byte) error {
	manifestBytes, err := m.MarshalCanonical()
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	if err := writeTarBytes(tw, manifestName, manifestBytes); err != nil {
		return err
	}
	if err := writeTarBytes(tw, sigName, sig); err != nil {
		return err
	}
	for _, c := range m.Components {
		full := filepath.Join(srcDir, filepath.FromSlash(c.Path))
		f, err := os.Open(full) // #nosec G304 -- path validated by cleanComponentPath, rooted at srcDir
		if err != nil {
			return err
		}
		hdr := &tar.Header{Name: c.Path, Mode: 0o644, Size: c.Size, ModTime: m.ReleasedAt}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = f.Close()
			return err
		}
		if _, err := io.Copy(tw, f); err != nil { // #nosec G110 -- size is pinned in the header
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// Sign returns an ed25519 signature over the canonical manifest bytes. The private key is
// the offline signing secret; it never ships with the bundle.
func Sign(m *Manifest, priv ed25519.PrivateKey) ([]byte, error) {
	b, err := m.MarshalCanonical()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, b), nil
}

// Verify streams a bundle from r, checking the manifest signature against the trusted,
// embedded key for its key-id, then every component's digest. It is memory-bounded (it
// hashes component bytes as they stream; it does not buffer images) and fails closed on
// any mismatch, unlisted file, or missing component. On success it returns the manifest.
// Verify only reads — it stages nothing; see Extract.
func Verify(r io.Reader, reg *trust.KeyRegistry) (*Manifest, error) {
	return process(r, reg, nil)
}

// Extract verifies a bundle (exactly as Verify) and, only after the signature and the
// no-downgrade gate pass, stages every verified component under destDir — preserving the
// component's relative path, contained within destDir, written atomically (temp + rename)
// so a digest failure never leaves a poisoned file in place. installedVersion enforces
// no-downgrade / min_upgrade_from *before* any component is written. Re-running it
// overwrites identical verified content, so import is idempotent.
func Extract(r io.Reader, reg *trust.KeyRegistry, destDir, installedVersion string) (*Manifest, error) {
	return process(r, reg, &extractOpts{destDir: destDir, installedVersion: installedVersion})
}

// extractOpts is the staging configuration for process; nil means verify-only.
type extractOpts struct {
	destDir          string
	installedVersion string
}

// process is the single streaming pass shared by Verify and Extract. It reads the manifest
// and signature first, verifies the signature against the embedded trusted key, optionally
// runs the no-downgrade gate, then streams each component — hashing it against its pinned
// digest and (when staging) writing it atomically. It fails closed on any mismatch.
func process(r io.Reader, reg *trust.KeyRegistry, opts *extractOpts) (*Manifest, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("bundle: gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)

	manifestBytes, err := readNamedEntry(tr, manifestName)
	if err != nil {
		return nil, err
	}
	sig, err := readNamedEntry(tr, sigName)
	if err != nil {
		return nil, err
	}

	var m Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("bundle: parse manifest: %w", err)
	}
	if strings.TrimSpace(m.KeyID) == "" {
		return nil, fmt.Errorf("bundle: manifest has no key-id")
	}
	// Verify the signature over the EXACT manifest.json bytes carried in the archive,
	// against the embedded trusted key named by the manifest's key-id. A forged key-id is
	// not in the embedded registry, so this fails closed.
	if err := reg.Verify(trust.PurposeUpdate, m.KeyID, manifestBytes, sig); err != nil {
		return nil, fmt.Errorf("bundle: manifest signature: %w", err)
	}

	// When staging, gate on no-downgrade BEFORE writing any component, and prepare destDir.
	if opts != nil {
		if err := m.CheckUpgrade(opts.installedVersion); err != nil {
			return nil, err
		}
		if strings.TrimSpace(opts.destDir) == "" {
			return nil, fmt.Errorf("bundle: extract destination is required")
		}
		if err := os.MkdirAll(opts.destDir, 0o750); err != nil {
			return nil, fmt.Errorf("bundle: create destination: %w", err)
		}
	}

	pinned := m.byPath()
	seen := make(map[string]bool, len(pinned))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: read archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name, err := cleanComponentPath(hdr.Name)
		if err != nil {
			return nil, err
		}
		comp, ok := pinned[name]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnlistedComponent, name)
		}
		if err := streamComponent(tr, comp, optsDest(opts)); err != nil {
			return nil, err
		}
		seen[name] = true
	}
	for p := range pinned {
		if !seen[p] {
			return nil, fmt.Errorf("%w: %s", ErrMissingComponent, p)
		}
	}
	return &m, nil
}

func optsDest(opts *extractOpts) string {
	if opts == nil {
		return ""
	}
	return opts.destDir
}

// streamComponent reads exactly comp.Size bytes of the current tar entry, verifying the
// sha256 digest. The read is bounded to size+1 (a decompression-bomb guard that also
// rejects an oversized entry before its digest is compared). If destDir is non-empty the
// bytes are written atomically to destDir/comp.Path (temp file + rename); on any digest
// failure the temp file is removed, so a failed component never lands on disk.
func streamComponent(tr io.Reader, comp Component, destDir string) error {
	h := sha256.New()
	dst := io.Writer(h)

	var tmpPath, finalPath string
	var tmp *os.File
	if destDir != "" {
		final, err := safeJoin(destDir, comp.Path)
		if err != nil {
			return err
		}
		finalPath = final
		if err := os.MkdirAll(filepath.Dir(finalPath), 0o750); err != nil {
			return fmt.Errorf("bundle: mkdir for %s: %w", comp.Path, err)
		}
		tmp, err = os.CreateTemp(filepath.Dir(finalPath), ".kxbundle-*")
		if err != nil {
			return fmt.Errorf("bundle: temp for %s: %w", comp.Path, err)
		}
		tmpPath = tmp.Name()
		dst = io.MultiWriter(h, tmp)
	}

	n, copyErr := io.Copy(dst, io.LimitReader(tr, comp.Size+1))
	if tmp != nil {
		_ = tmp.Close()
	}
	cleanup := func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}
	if copyErr != nil {
		cleanup()
		return fmt.Errorf("bundle: read %s: %w", comp.Path, copyErr)
	}
	if n != comp.Size {
		cleanup()
		return fmt.Errorf("%w: %s (size %d, want %d)", ErrDigestMismatch, comp.Path, n, comp.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != comp.SHA256 {
		cleanup()
		return fmt.Errorf("%w: %s", ErrDigestMismatch, comp.Path)
	}
	if tmpPath != "" {
		if err := os.Rename(tmpPath, finalPath); err != nil {
			cleanup()
			return fmt.Errorf("bundle: stage %s: %w", comp.Path, err)
		}
	}
	return nil
}

// safeJoin joins a validated relative component path onto destDir and confirms the result
// stays within destDir (defence in depth atop cleanComponentPath).
func safeJoin(destDir, rel string) (string, error) {
	clean, err := cleanComponentPath(rel)
	if err != nil {
		return "", err
	}
	joined := filepath.Join(destDir, filepath.FromSlash(clean))
	rootAbs, err := filepath.Abs(destDir)
	if err != nil {
		return "", err
	}
	joinedAbs, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	if joinedAbs != rootAbs && !strings.HasPrefix(joinedAbs, rootAbs+string(os.PathSeparator)) {
		return "", fmt.Errorf("bundle: component %q escapes destination", rel)
	}
	return joined, nil
}

// CheckUpgrade enforces the no-downgrade and anti-skip rules against the installed
// version. An empty installed version (a first install) passes. It is the caller's gate
// before `import` actually stages anything.
func (m *Manifest) CheckUpgrade(installed string) error {
	if strings.TrimSpace(installed) == "" {
		return nil
	}
	cmp, err := compareVersions(m.Version, installed)
	if err != nil {
		return err
	}
	if cmp <= 0 {
		return fmt.Errorf("%w: bundle %s <= installed %s", ErrNotUpgrade, m.Version, installed)
	}
	if m.MinUpgradeFrom != "" {
		floor, err := compareVersions(installed, m.MinUpgradeFrom)
		if err != nil {
			return err
		}
		if floor < 0 {
			return fmt.Errorf("%w: installed %s < required %s", ErrUpgradeSkipped, installed, m.MinUpgradeFrom)
		}
	}
	return nil
}

// --- helpers ---

func writeTarBytes(tw *tar.Writer, name string, b []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b))}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

// readNamedEntry reads the next tar entry, requiring it to be the named regular file, and
// returns its bytes (bounded by maxManifestBytes).
func readNamedEntry(tr *tar.Reader, want string) ([]byte, error) {
	hdr, err := tr.Next()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoManifest, err)
	}
	if hdr.Name != want || hdr.Typeflag != tar.TypeReg {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrNoManifest, hdr.Name, want)
	}
	b, err := io.ReadAll(io.LimitReader(tr, maxManifestBytes))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func hashFile(p string) (string, int64, error) {
	f, err := os.Open(p) // #nosec G304 -- caller walks a trusted srcDir
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// parseVersion accepts a "vX.Y.Z" (or "X.Y.Z") release version, ignoring any pre-release
// or build metadata, and returns its numeric components.
func parseVersion(v string) ([3]int, error) {
	var out [3]int
	s := strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, fmt.Errorf("not a vMAJOR.MINOR.PATCH version")
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, fmt.Errorf("invalid version component %q", p)
		}
		out[i] = n
	}
	return out, nil
}

// compareVersions returns -1, 0, or 1 for a<b, a==b, a>b over vX.Y.Z versions.
func compareVersions(a, b string) (int, error) {
	pa, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

// ParsePrivateKeyPEM decodes a PKCS#8 PEM (as written by `keyorix trust keygen`) into an
// ed25519 private key for signing. It is the only signing-key entry point, shared by the
// CLI and tests.
func ParsePrivateKeyPEM(b []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("bundle: no PEM block in signing key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bundle: parse signing key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("bundle: signing key is not ed25519 (%T)", key)
	}
	return priv, nil
}
