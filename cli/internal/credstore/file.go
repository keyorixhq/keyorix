package credstore

import (
	"fmt"
	"os"
	"path/filepath"

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

// Save writes c to the store's path at mode 0600, creating its parent directory (mode
// 0700) if needed. The mode is set explicitly on the open call, not left to umask.
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

	f, err := os.OpenFile(s.path, os.O_RDONLY|noFollowFlag, 0)
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

// Clear removes the credentials file. Clearing when none exists is not an error.
func (s *FileStore) Clear() error {
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove credentials file: %w", err)
	}
	return nil
}
