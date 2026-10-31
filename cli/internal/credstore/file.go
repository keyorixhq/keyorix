package credstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/cli/internal/regularfile"
	"gopkg.in/yaml.v3"
)

// FileStore is the plaintext-file credential store (ADR-108 PR 0 decision, see this
// package's doc comment). It refuses to Load a file whose permissions are wider than 0600
// rather than silently trusting it -- a widened mode is exactly what a misconfigured
// shared/multi-user host, or a deliberate tamper attempt, would produce.
type FileStore struct {
	path string
}

// DefaultPath returns the one credentials-file location the thin CLI uses:
// os.UserConfigDir()/keyorix/credentials.yaml. There is deliberately no second, CWD-relative
// fallback (docs/cli-split-inventory.md §4's "#G73/#G74" untrusted-CWD-config finding on the
// old CLI does not carry forward).
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "keyorix", "credentials.yaml"), nil
}

// NewFileStore returns a FileStore backed by path.
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// Path returns the file this store reads and writes.
func (s *FileStore) Path() string {
	return s.path
}

// Save writes c to the store's path at mode 0600, creating its parent directory (mode
// 0700) if needed. The mode is set explicitly on the open call AND via an explicit
// Chmod after opening: O_CREATE's mode argument only applies when the file is newly
// created -- if s.path already existed (e.g. left behind with wider permissions by a
// misconfigured shared host, an older CLI version, or a manual chmod), O_TRUNC reuses
// that existing file and keeps its existing mode, silently writing a plaintext token
// into a file Load refuses to read back (Load enforces 0600; Save must guarantee it,
// not just request it). Mirrors internal/securefiles.writeFile's identical fix for the
// exact same class of bug ("O_TRUNC keeps a pre-existing file's mode ... so set the
// intended permissions explicitly either way").
func (s *FileStore) Save(c Credentials) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|noFollowFlag, 0600)
	if err != nil {
		return fmt.Errorf("open credentials file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := f.Chmod(0600); err != nil {
		return fmt.Errorf("chmod credentials file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	return nil
}

// Load reads and parses the store's credentials file. It refuses (returns an error without
// reading the contents) if the file's mode is wider than 0600, or if the final path
// component is a symlink.
func (s *FileStore) Load() (Credentials, error) {
	info, err := os.Lstat(s.path)
	if err != nil {
		return Credentials{}, fmt.Errorf("no stored credentials: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Credentials{}, fmt.Errorf("credentials file %s is a symlink, refusing to read", s.path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return Credentials{}, fmt.Errorf("credentials file %s has permissions %#o, wider than the required 0600 -- refusing to read; fix with chmod 600 %s", s.path, perm, s.path)
	}

	f, _, err := regularfile.OpenFlags("credentials file", s.path, noFollowFlag)
	if err != nil {
		return Credentials{}, fmt.Errorf("open credentials file: %w", err)
	}
	defer func() { _ = f.Close() }()

	var c Credentials
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&c); err != nil {
		return Credentials{}, fmt.Errorf("parse credentials file: %w", err)
	}
	return c, nil
}

// ForgetSession drops the session from the credentials file -- the token and the active
// project, which belongs to the session's user -- and keeps the operator's settings: the
// server URL and ca_file (not secrets; losing ca_file made the next login fail TLS
// verification). The file is rewritten through a temp file in the same directory and renamed
// over the original, at 0600, so a crash never leaves a half-written or world-readable file.
//
// Nothing stored is not an error. A file that cannot be read back safely (a symlink, a mode
// wider than 0600, unparseable) is removed instead, as Clear does: it may still hold a token,
// and failing closed on the token matters more than keeping a setting we cannot trust. When
// no setting is left to keep, the file is removed. When the rewrite itself fails, the file is
// removed too and the returned error wraps ErrSettingsDropped; only if that removal also
// fails is the token possibly still on disk, and the error is a plain one.
func (s *FileStore) ForgetSession() error {
	if _, err := os.Lstat(s.path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat credentials file: %w", err)
	}
	c, err := s.Load()
	if err != nil || (c.ServerURL == "" && c.CAFile == "") {
		return s.Clear()
	}
	if err := s.writeKept(Credentials{ServerURL: c.ServerURL, CAFile: c.CAFile}); err != nil {
		// The original file still holds the token. Remove it, as Clear does, rather than
		// leave a credential on disk because the settings could not be kept (ENOSPC, EIO).
		if cerr := s.Clear(); cerr != nil {
			return errors.Join(err, cerr)
		}
		return fmt.Errorf("%w: %w", ErrSettingsDropped, err)
	}
	return nil
}

// writeKept replaces the credentials file with kept, through a 0600 temp file in the same
// directory renamed over the original. On error the original file is left as it was.
func (s *FileStore) writeKept(kept Credentials) error {
	data, err := yaml.Marshal(kept)
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".credentials-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp credentials file: %w", err)
	}
	tmpName := tmp.Name()
	fail := func(what string, err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := tmp.Chmod(0600); err != nil {
		return fail("chmod temp credentials file", err)
	}
	if err := writeTempCredentials(tmp, data); err != nil {
		return fail("write temp credentials file", err)
	}
	if err := tmp.Sync(); err != nil {
		return fail("sync temp credentials file", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp credentials file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace credentials file: %w", err)
	}
	return nil
}

// ErrSettingsDropped is wrapped in ForgetSession's error when the settings could not be
// rewritten and the whole file was removed instead: the token is gone, but so are server_url
// and ca_file. Callers treat it as a warning, not a failure.
var ErrSettingsDropped = errors.New("could not keep server_url and ca_file; removed the credentials file instead")

// writeTempCredentials writes the kept settings to the temp file. A test seam: tests replace
// it to make the rewrite fail.
var writeTempCredentials = func(f *os.File, data []byte) error {
	_, err := f.Write(data)
	return err
}

// Clear removes the credentials file. Clearing when none exists is not an error.
func (s *FileStore) Clear() error {
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove credentials file: %w", err)
	}
	return nil
}
