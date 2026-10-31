package secretenv

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRefusalPathsCloseTheDescriptor pins that every refusal after a successful
// open releases the descriptor (SEC-REVIEW-ROWS-1): OpenRegular on a directory
// and on a FIFO, LookupChecked on a too-open file (refused after the fstat, before
// the read), Lookup on an empty file and on an oversized one (refused after the
// read), and Snapshot.Take over the same. A leak here is one descriptor per boot
// check or config load, so the test repeats each refusal and asserts the
// process's open-descriptor count did not grow by the repeat count.
//
// It counts /dev/fd entries (macOS and Linux), so it says nothing about a leak
// smaller than the slack below or about descriptors other goroutines open.
func TestRefusalPathsCloseTheDescriptor(t *testing.T) {
	if _, err := os.ReadDir("/dev/fd"); err != nil {
		t.Skipf("no /dev/fd to count descriptors: %v", err)
	}
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	loose := filepath.Join(dir, "loose")
	require.NoError(t, os.WriteFile(loose, []byte("v"), 0o600))
	require.NoError(t, os.Chmod(loose, 0o644))
	empty := filepath.Join(dir, "empty")
	require.NoError(t, os.WriteFile(empty, nil, 0o600))
	big := filepath.Join(dir, "big")
	require.NoError(t, os.WriteFile(big, make([]byte, MaxSecretFileSize+1), 0o600))

	const repeat = 64
	cases := map[string]func(){
		"OpenRegular directory": func() { _, _, err := OpenRegular(dir, 0); require.ErrorIs(t, err, ErrNotRegular) },
		"OpenRegular FIFO":      func() { _, _, err := OpenRegular(fifo, 0); require.ErrorIs(t, err, ErrNotRegular) },
		"LookupChecked too open": func() {
			t.Setenv(testVar+FileSuffix, loose)
			_, _, err := LookupChecked(testVar)
			require.Error(t, err)
		},
		"Lookup empty": func() {
			t.Setenv(testVar+FileSuffix, empty)
			_, _, err := Lookup(testVar)
			require.Error(t, err)
		},
		"Lookup too large": func() {
			t.Setenv(testVar+FileSuffix, big)
			_, _, err := Lookup(testVar)
			require.Error(t, err)
		},
		"Snapshot.Take FIFO": func() {
			t.Setenv(testVar+FileSuffix, fifo)
			NewSnapshot().Take(testVar)
		},
	}
	t.Setenv(testVar, "")

	// Calibration: the counter must see a real leak of the same size, or a green
	// run below proves nothing.
	before := openFDs(t)
	leaked := make([]*os.File, 0, repeat)
	for range repeat {
		f, err := os.Open(empty)
		require.NoError(t, err)
		leaked = append(leaked, f)
	}
	if after := openFDs(t); after-before < repeat {
		t.Fatalf("calibration: %d deliberate leaks moved the /dev/fd count only %d -> %d", repeat, before, after)
	}
	for _, f := range leaked {
		require.NoError(t, f.Close())
	}

	for name, refuse := range cases {
		refuse() // warm up: first-use allocations (poller, env) are not leaks
		before := openFDs(t)
		for range repeat {
			refuse()
		}
		if after := openFDs(t); after-before >= repeat/2 {
			t.Errorf("%s: %d refusals left %d more descriptors open (%d -> %d)", name, repeat, after-before, before, after)
		}
	}
}

func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	require.NoError(t, err)
	return len(entries)
}
