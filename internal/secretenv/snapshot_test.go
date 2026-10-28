package secretenv

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapshot_ReadsOnceAndJudgesTheReadDescriptor(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s")
	require.NoError(t, os.WriteFile(p, []byte("first\n"), 0o600))
	require.NoError(t, os.Chmod(p, 0o640))
	t.Setenv(testVar, "")
	t.Setenv(testVar+FileSuffix, p)

	s := NewSnapshot()
	s.Take(testVar)
	require.NoError(t, os.WriteFile(p, []byte("second\n"), 0o600))
	require.NoError(t, os.Chmod(p, 0o600))
	s.Take(testVar) // a second Take keeps the first read

	v, found, err := s.Lookup(testVar)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "first", v)

	perr, ok := s.CheckPermissions(testVar)
	require.True(t, ok)
	require.Error(t, perr, "the verdict is the 0640 descriptor's, not the path's current 0600")
	assert.Contains(t, perr.Error(), "mode 0640")
	assert.Contains(t, perr.Error(), testVar+FileSuffix+"=")
	assert.NotContains(t, perr.Error(), "first")
}

func TestSnapshot_NotTakenOrNilFallsBackToLive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s")
	require.NoError(t, os.WriteFile(p, []byte("live\n"), 0o600))
	t.Setenv(testVar, "")
	t.Setenv(testVar+FileSuffix, p)

	var nilSnap *Snapshot
	v, found, err := nilSnap.Lookup(testVar)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "live", v)
	_, ok := nilSnap.CheckPermissions(testVar)
	assert.False(t, ok)

	v, _, err = NewSnapshot().Lookup(testVar)
	require.NoError(t, err)
	assert.Equal(t, "live", v)

	t.Setenv(testVar, "direct")
	s := NewSnapshot()
	s.Take(testVar) // both set: not taken, Lookup reports it live
	_, _, err = s.Lookup(testVar)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "both")
}
