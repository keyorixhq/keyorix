package secretenv

import (
	"os"
	"sync"
)

// Snapshot holds *_FILE secrets read once, together with the verdict on the
// descriptor each was read from (SECRETENV-REVIEW-1 F5/F6).
//
// Why: a caller that re-reads X_FILE on every use (internal/config's accessors
// did) lets the value a boot check judges -- the duplicate-secret check, the SCIM
// token strength check, the permission check -- differ from the value later
// used: whoever can write the file swaps it between the two reads. And a
// permission check that stats the path while the read is a separate open judges
// a file that need not be the one read. A Snapshot reads each source once, through
// OpenRegular, judges the fstat of that same descriptor (checkInfo, without
// refusing: the warn-or-refuse matrix stays the caller's), and from then on hands
// out that value and that verdict.
//
// An entry is keyed by the variable and the path it named when it was taken. A
// lookup uses the entry only while the environment still names the same source
// (X unset, X_FILE equal to the recorded path); otherwise it falls back to a live
// Lookup, so a changed environment is never answered from a stale entry. Take
// never re-reads a source it already holds: a second config load in the same
// process (startup validation loads the config again) sees the same bytes as the
// first. A changed file is picked up on restart.
//
// Key material (LookupChecked: master password, KEK, Shamir shares) does not
// belong in a Snapshot: its readers judge and refuse on their own descriptor, and
// a long-lived copy of it is not wanted.
type Snapshot struct {
	mu sync.Mutex
	m  map[snapshotKey]snapshotEntry
}

type snapshotKey struct{ name, path string }

type snapshotEntry struct {
	value   string
	err     error // the Lookup error (already a *FileError naming the variable)
	permErr error // checkInfo on the read descriptor, unwrapped
	judged  bool  // the file was opened and fstat'ed, so permErr is meaningful
}

// NewSnapshot returns an empty Snapshot.
func NewSnapshot() *Snapshot { return &Snapshot{m: map[snapshotKey]snapshotEntry{}} }

// Take reads every name whose <name>_FILE is set (and name itself is not: both
// set is Lookup's error, answered live) and records its value or error and the
// verdict on its descriptor. A source already recorded is not read again.
func (s *Snapshot) Take(names ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, name := range names {
		path := os.Getenv(name + FileSuffix)
		if path == "" || os.Getenv(name) != "" {
			continue
		}
		k := snapshotKey{name, path}
		if _, ok := s.m[k]; ok {
			continue
		}
		v, permErr, judged, err := readSecretFileJudged(path, false)
		e := snapshotEntry{value: v, permErr: permErr, judged: judged}
		if err != nil {
			e.value, e.err = "", NewFileError(name+FileSuffix, path, err)
		}
		s.m[k] = e
	}
}

// entry returns the recorded entry for name when the environment still names
// the source it was taken from.
func (s *Snapshot) entry(name string) (snapshotEntry, string, bool) {
	if s == nil {
		return snapshotEntry{}, "", false
	}
	path := os.Getenv(name + FileSuffix)
	if path == "" || os.Getenv(name) != "" {
		return snapshotEntry{}, "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[snapshotKey{name, path}]
	return e, path, ok
}

// Lookup is secretenv.Lookup answered from the snapshot when it holds the
// source the environment names, and live otherwise. A recorded read failure is
// returned as the error, with no value: callers fail closed exactly as on a live
// failure.
func (s *Snapshot) Lookup(name string) (value string, found bool, err error) {
	if e, _, ok := s.entry(name); ok {
		if e.err != nil {
			return "", false, e.err
		}
		return e.value, true, nil
	}
	return Lookup(name)
}

// CheckPermissions is CheckPermissionsNamed(name+"_FILE", path) judged on the
// descriptor the snapshot read rather than on a fresh stat of the path. ok is
// false when the snapshot has no judged entry for name (not taken, the
// environment changed, or the file could not be opened); the caller then checks
// the path itself.
func (s *Snapshot) CheckPermissions(name string) (err error, ok bool) {
	e, path, found := s.entry(name)
	if !found || !e.judged {
		return nil, false
	}
	if e.permErr != nil {
		return NewFileError(name+FileSuffix, path, e.permErr), true
	}
	return nil, true
}
