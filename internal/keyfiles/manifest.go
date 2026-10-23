// manifest.go — the key-set manifest (#2900): a generation id and a per-file
// SHA-256 for every file in RequiredKeyFilePaths, written by every operation
// that changes the key set and verified at boot (VerifyKeySetConsistency).
//
// Why a manifest and not file metadata: presence/absence is decidable from
// os.Stat, but "these files belong to the same generation" is not. cp,
// install, docker cp and kubectl cp stamp every destination with the current
// time, so a key directory assembled from two backups shows identical mtimes;
// and the two interrupted-rotate-kek states that matter (harmless leftover
// staging vs. a renamed DEK under the old salt) have identical file layouts.
// The recorded hashes tell all of these apart without a passphrase.
//
// Per-file generation, not one per set: the DEK (rotate-dek, ADR-046) and each
// provider blob change on independent schedules, so each entry records the
// generation of the operation that last wrote THAT file. The set-level
// Generation is a counter bumped by every commit.
//
// Two-phase writes. A writer that replaces active key files first stages its
// intent (Next: the hashes the files will have), then replaces the files, then
// Commits (the entries take the new hashes, Next is cleared). Every on-disk
// state a crash can leave is therefore classifiable at boot: each file matches
// either its recorded hash or the staged one, and a set where some files match
// the staged hashes and others do not is an interrupted operation, not a mix
// of backups. The manifest itself is replaced atomically (write
// <name>.pending, fsync, rename, fsync the directory), the same
// write-pending → rename → fsync path the key files use.
//
// What the manifest is NOT: an authenticator. The hashes are unkeyed (the KEK
// that could key them is not available before the passphrase is), so anyone
// who can write the key directory can rewrite the manifest too. It detects
// accidents — a set assembled from different generations, a file replaced by
// a tool that does not maintain the manifest — not a deliberate attacker with
// write access to the key directory, who could equally replace the keys.
package keyfiles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// ManifestFileName is the manifest's name inside the DEK's directory.
const ManifestFileName = "keyset.manifest.json"

// manifestFormat is the only format this binary reads or writes. A manifest
// with any other value is treated as unparseable (ErrManifestInvalid).
const manifestFormat = 1

// Operation names recorded in the manifest. They are labels for operators and
// tests, not control flow: boot classification never branches on them.
const (
	OpFirstBoot       = "first-boot"
	OpAdopted         = "adopted"
	OpRotateKEK       = "rotate-kek"
	OpRotateDEK       = "rotate-dek"
	OpRewrapDEK       = "migrate-provider"
	OpRewrapRollback  = "migrate-provider-rollback"
	OpRestore         = "restore"
	OpFinishRotateKEK = "finish-interrupted-rotation"
)

// ErrManifestMissing and ErrManifestInvalid distinguish "no manifest yet"
// (every install that predates #2900) from "a manifest that cannot be read".
var (
	ErrManifestMissing = errors.New("key-set manifest is missing")
	ErrManifestInvalid = errors.New("key-set manifest is unparseable")
)

// Manifest is the on-disk key-set manifest.
type Manifest struct {
	Format     int                      `json:"format"`
	Generation uint64                   `json:"generation"`
	Files      map[string]ManifestEntry `json:"files"`
	// Next is a staged, not yet committed operation (see the package comment).
	Next *ManifestIntent `json:"next,omitzero"`
}

// ManifestEntry records one key file: its content hash and the generation and
// operation that last wrote it.
type ManifestEntry struct {
	SHA256     string `json:"sha256"`
	Generation uint64 `json:"generation"`
	Operation  string `json:"operation"`
}

// ManifestIntent is a staged operation: the hashes the named files will have
// once the operation commits, and the generation it will commit as.
type ManifestIntent struct {
	Generation uint64            `json:"generation"`
	Operation  string            `json:"operation"`
	Files      map[string]string `json:"files"`
}

// ManifestFS is the write path a manifest is committed through. The zero value
// uses securefiles (SecureWriteFileSync, os.Rename, SyncDir);
// internal/encryption passes its fault-injectable durableWriteSync /
// durableRename / durableSyncDir so the manifest shares the key files' seams.
type ManifestFS struct {
	// WriteSync durably writes data to dir/name with mode 0600.
	WriteSync func(dir, name string, data []byte) error
	Rename    func(oldPath, newPath string) error
	SyncDir   func(dir string) error
}

func (fs ManifestFS) withDefaults() ManifestFS {
	if fs.WriteSync == nil {
		fs.WriteSync = func(dir, name string, data []byte) error {
			return securefiles.SecureWriteFileSync(dir, name, data, keyMaterialMode)
		}
	}
	if fs.Rename == nil {
		fs.Rename = os.Rename
	}
	if fs.SyncDir == nil {
		fs.SyncDir = securefiles.SyncDir
	}
	return fs
}

// ManifestPath returns where enc's manifest lives: ManifestFileName in the
// directory of the resolved DEK path ("" when no DEK path is configured).
func ManifestPath(enc *config.EncryptionConfig, baseDir string) (string, error) {
	if enc == nil || enc.DEKPath == "" {
		return "", nil
	}
	clean, err := SafePath("DEK", enc.DEKPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(resolve(baseDir, clean)), ManifestFileName), nil
}

// manifestKey names full in the manifest: relative to the manifest's directory
// when it lies inside it (so moving the whole key directory keeps the
// manifest valid), the cleaned absolute path otherwise.
func manifestKey(manifestDir, full string) string {
	absDir, derr := filepath.Abs(manifestDir)
	absFull, ferr := filepath.Abs(full)
	if derr == nil && ferr == nil {
		if rel, err := filepath.Rel(absDir, absFull); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(rel)
		}
		return filepath.ToSlash(absFull)
	}
	return filepath.ToSlash(filepath.Clean(full))
}

// HashBytes is the manifest's content hash: lowercase hex SHA-256.
func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// readKeyFile reads a key file for hashing. Symlinks are followed (Kubernetes
// Secret volumes mount key files through them); a non-regular file (a FIFO
// planted at a key path would otherwise block open(2) and hang boot) is
// refused, as securefiles.SafeReadFile does.
func readKeyFile(full string) ([]byte, error) {
	f, err := os.OpenFile(full, os.O_RDONLY|unix.O_NONBLOCK, 0) // #nosec G304 -- a config-derived key path, already SafePath-checked
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", full)
	}
	return io.ReadAll(f)
}

func hashKeyFile(full string) (string, error) {
	data, err := readKeyFile(full)
	if err != nil {
		return "", err
	}
	return HashBytes(data), nil
}

// LoadManifest reads and validates the manifest at path. It returns an error
// wrapping ErrManifestMissing when there is none, and one wrapping
// ErrManifestInvalid when it cannot be parsed or is not a format this binary
// knows.
func LoadManifest(path string) (*Manifest, error) {
	data, err := readKeyFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrManifestMissing, path)
		}
		return nil, fmt.Errorf("%w: %s: %v", ErrManifestInvalid, path, err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrManifestInvalid, path, err)
	}
	if m.Format != manifestFormat {
		return nil, fmt.Errorf("%w: %s: format %d, this binary reads format %d", ErrManifestInvalid, path, m.Format, manifestFormat)
	}
	if m.Files == nil {
		return nil, fmt.Errorf("%w: %s: no files section", ErrManifestInvalid, path)
	}
	for k, e := range m.Files {
		if !validHash(e.SHA256) {
			return nil, fmt.Errorf("%w: %s: entry %q has no valid sha256", ErrManifestInvalid, path, k)
		}
	}
	if m.Next != nil {
		for k, h := range m.Next.Files {
			if !validHash(h) {
				return nil, fmt.Errorf("%w: %s: staged entry %q has no valid sha256", ErrManifestInvalid, path, k)
			}
		}
	}
	return &m, nil
}

func validHash(h string) bool {
	if len(h) != 2*sha256.Size {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}

// writeManifest replaces the manifest at path atomically through fs.
func writeManifest(path string, m *Manifest, fs ManifestFS) error {
	fs = fs.withDefaults()
	data, err := json.Marshal(m, json.Deterministic(true))
	if err != nil {
		return fmt.Errorf("encode key-set manifest: %w", err)
	}
	dir, name := filepath.Dir(path), filepath.Base(path)
	if err := fs.WriteSync(dir, name+".pending", data); err != nil {
		return fmt.Errorf("write key-set manifest: %w", err)
	}
	if err := fs.Rename(filepath.Join(dir, name+".pending"), path); err != nil {
		_ = os.Remove(filepath.Join(dir, name+".pending"))
		return fmt.Errorf("commit key-set manifest: %w", err)
	}
	if err := fs.SyncDir(dir); err != nil {
		return fmt.Errorf("fsync key directory after committing the key-set manifest: %w", err)
	}
	return nil
}

// adoptFromDisk builds a manifest at generation gen from whichever of required
// is present on disk. The caller decides whether adopting is acceptable (it
// is only for a set that has no manifest yet). Boot writes the adoption itself
// as generation 1; a writer adopts at generation 0 ("before the manifest
// existed") and its own commit then becomes generation 1.
//
// strict is boot's adoption: a present file that cannot be hashed fails it. A
// writer adopts leniently (skips the file with a WARN): it must not fail the
// operation an operator asked for over a file it is not changing, and the
// unrecorded file is reported by the next boot.
func adoptFromDisk(manifestDir string, required []string, gen uint64, strict bool) (*Manifest, error) {
	m := &Manifest{Format: manifestFormat, Generation: gen, Files: map[string]ManifestEntry{}}
	for _, p := range required {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		h, err := hashKeyFile(p)
		if err != nil {
			if !strict {
				log.Printf("[WARN] key-set manifest: %s cannot be read (%v) and is left unrecorded", p, err)
				continue
			}
			return nil, fmt.Errorf("hash %s for the key-set manifest: %w", p, err)
		}
		m.Files[manifestKey(manifestDir, p)] = ManifestEntry{SHA256: h, Generation: gen, Operation: OpAdopted}
	}
	return m, nil
}

// SetWriter updates one key set's manifest. Every operation that writes key
// material into the active set goes through one; the structural guard
// TestEveryKeyMaterialWriterUpdatesTheManifest (this package) checks
// internal/encryption, internal/encryptionops and server/admin for writers
// that do not.
type SetWriter struct {
	manifestPath string
	// required are the files to adopt when no manifest exists yet: a writer
	// running on a pre-manifest install records the whole current set first,
	// then its own change, so the files it did not touch are not left
	// unrecorded.
	required []string
	fs       ManifestFS
}

// NewSetWriter returns the writer for enc's key set, rooted at baseDir (the
// same arguments RequiredKeyFilePaths takes). It returns nil, nil when enc
// configures no DEK path (nothing to record).
func NewSetWriter(enc *config.EncryptionConfig, baseDir string) (*SetWriter, error) {
	path, err := ManifestPath(enc, baseDir)
	if err != nil || path == "" {
		return nil, err
	}
	required, err := RequiredKeyFilePaths(enc, baseDir)
	if err != nil {
		return nil, err
	}
	return &SetWriter{manifestPath: path, required: required}, nil
}

// NewSetWriterForFiles returns a writer whose manifest sits in manifestDir and
// whose adoptable set is required (full paths). For a KeyManager built without
// an encryption config, where the salt and the DEK are the whole set.
func NewSetWriterForFiles(manifestDir string, required ...string) *SetWriter {
	return &SetWriter{manifestPath: filepath.Join(manifestDir, ManifestFileName), required: required}
}

// WithFS returns w writing through fs.
func (w *SetWriter) WithFS(fs ManifestFS) *SetWriter {
	if w == nil {
		return nil
	}
	c := *w
	c.fs = fs
	return &c
}

// Path is the manifest's full path.
func (w *SetWriter) Path() string { return w.manifestPath }

// load returns the current manifest, adopting the on-disk set when there is
// none or it cannot be parsed (logged: the boot-time check, not a writer, is
// where that is reported and audited; a writer must not fail an operation an
// operator asked for because an older binary never wrote a manifest).
func (w *SetWriter) load() (*Manifest, error) {
	m, err := LoadManifest(w.manifestPath)
	if err == nil {
		return m, nil
	}
	if !errors.Is(err, ErrManifestMissing) {
		log.Printf("[WARN] %v — re-recording the current key files before this operation's change", err)
	}
	return adoptFromDisk(filepath.Dir(w.manifestPath), w.required, 0, false)
}

func (w *SetWriter) hashes(files map[string][]byte) map[string]string {
	dir := filepath.Dir(w.manifestPath)
	out := make(map[string]string, len(files))
	for p, data := range files {
		out[manifestKey(dir, p)] = HashBytes(data)
	}
	return out
}

// StageManifest records that op is about to replace files (full path → the content
// they will have). Call it before the first active file is replaced; a crash
// between Stage and Commit leaves a set boot can classify (VerifyKeySetConsistency).
func (w *SetWriter) StageManifest(op string, files map[string][]byte) error {
	if w == nil {
		return nil
	}
	m, err := w.load()
	if err != nil {
		return err
	}
	m.Next = &ManifestIntent{Generation: m.Generation + 1, Operation: op, Files: w.hashes(files)}
	return writeManifest(w.manifestPath, m, w.fs)
}

// CommitManifest records that op has replaced files (full path → their new content):
// each entry takes the new hash and the new generation, and any staged intent
// is cleared. Files op did not write keep their entries unchanged.
func (w *SetWriter) CommitManifest(op string, files map[string][]byte) error {
	if w == nil {
		return nil
	}
	m, err := w.load()
	if err != nil {
		return err
	}
	gen := m.Generation + 1
	for k, h := range w.hashes(files) {
		m.Files[k] = ManifestEntry{SHA256: h, Generation: gen, Operation: op}
	}
	m.Generation = gen
	m.Next = nil
	return writeManifest(w.manifestPath, m, w.fs)
}

// CommitManifestFromDisk is CommitManifest for files op has just produced on disk (first-boot
// generation, a provider's freshly persisted blob), hashed as they are now.
func (w *SetWriter) CommitManifestFromDisk(op string, paths ...string) error {
	if w == nil {
		return nil
	}
	files := make(map[string][]byte, len(paths))
	for _, p := range paths {
		data, err := readKeyFile(p)
		if err != nil {
			return fmt.Errorf("read %s for the key-set manifest: %w", p, err)
		}
		files[p] = data
	}
	return w.CommitManifest(op, files)
}

// Required returns the full paths of the set this writer adopts.
func (w *SetWriter) Required() []string {
	if w == nil {
		return nil
	}
	return append([]string(nil), w.required...)
}
