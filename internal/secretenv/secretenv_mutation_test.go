package secretenv

// secretenv_mutation_test.go pins properties that gremlins mutation testing showed
// were not covered by a test that would notice them going wrong (MUTANT-SEC-2): the
// full X / X_FILE truth table (the switch's case expressions are invisible to Go's
// coverage profile, so gremlins reports them NOT COVERED and only a complete table
// kills their mutants), the OpenRegularNamed / ReadRegularFile / NotRegularError
// surface, and that refusals name the variable and path but never the contents.

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLookup_TruthTable_EnvVersusFile: the four combinations of (X set, X_FILE set)
// each resolve one way and never fall back across the boundary. An empty variable
// counts as unset on either side.
func TestLookup_TruthTable_EnvVersusFile(t *testing.T) {
	file := writeSecret(t, "from-file\n", 0o600)
	cases := []struct {
		name         string
		direct, path string
		wantValue    string
		wantFound    bool
		wantErr      bool
	}{
		{"neither set", "", "", "", false, false},
		{"only X", "from-env", "", "from-env", true, false},
		{"only X_FILE", "", file, "from-file", true, false},
		{"both set", "from-env", file, "", false, true},
	}
	for _, tc := range cases {
		for name, look := range map[string]func(string) (string, bool, error){"Lookup": Lookup, "LookupChecked": LookupChecked} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				t.Setenv(testVar, tc.direct)
				t.Setenv(testVar+"_FILE", tc.path)
				v, found, err := look(testVar)
				assert.Equal(t, tc.wantValue, v)
				assert.Equal(t, tc.wantFound, found)
				assert.Equal(t, tc.wantErr, err != nil)
			})
		}
	}
}

// TestLookup_ErrorsNameVariableAndPathNotContents: a refusal reads "<VAR>_FILE=<path>:
// <reason>" and carries nothing from the file, for every way a file can be refused.
func TestLookup_ErrorsNameVariableAndPathNotContents(t *testing.T) {
	const secret = "TOPSECRET-9c1e"
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose")
	require.NoError(t, os.WriteFile(loose, []byte(secret+"\n"), 0o644))
	require.NoError(t, os.Chmod(loose, 0o644))
	foreign := writeSecret(t, secret+"\n", 0o600)

	cases := map[string]struct {
		path    string
		checked bool
		reason  string
		restore func() func()
	}{
		"missing file":            {path: filepath.Join(dir, "absent"), reason: "cannot open secret file: no such file or directory"},
		"directory":               {path: dir, reason: ErrNotRegular.Error()},
		"too open (checked)":      {path: loose, checked: true, reason: "too open (accessible to other users)"},
		"foreign owner (checked)": {path: foreign, checked: true, reason: "owned by uid 4242", restore: func() func() { return OverrideOwnershipForTest(4242, os.Geteuid()) }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if tc.restore != nil {
				defer tc.restore()()
			}
			t.Setenv(testVar+"_FILE", tc.path)
			look := Lookup
			if tc.checked {
				look = LookupChecked
			}
			v, found, err := look(testVar)
			require.Error(t, err)
			assert.Empty(t, v)
			assert.False(t, found)
			assert.Contains(t, err.Error(), testVar+"_FILE="+`"`+tc.path+`"`+": ")
			assert.Contains(t, err.Error(), tc.reason)
			assert.NotContains(t, err.Error(), secret)
		})
	}
}

// TestLookup_PathHandling: relative paths resolve against the working directory, a
// dangling or looping symlink is refused (never read as empty or as unset), and
// OpenRegular with O_NOFOLLOW refuses a symlink that the default follows.
func TestLookup_PathHandling(t *testing.T) {
	t.Run("relative path", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "rel-secret"), []byte("relative-value\n"), 0o600))
		t.Chdir(dir)
		t.Setenv(testVar+"_FILE", "rel-secret")
		v, found, err := LookupChecked(testVar)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, "relative-value", v)
	})
	t.Run("dangling symlink", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "dangling")
		require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "gone"), link))
		t.Setenv(testVar+"_FILE", link)
		_, found, err := Lookup(testVar)
		require.Error(t, err)
		assert.False(t, found)
	})
	t.Run("symlink loop", func(t *testing.T) {
		dir := t.TempDir()
		a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
		require.NoError(t, os.Symlink(b, a))
		require.NoError(t, os.Symlink(a, b))
		t.Setenv(testVar+"_FILE", a)
		_, found, err := Lookup(testVar)
		require.Error(t, err)
		assert.False(t, found)
	})
	t.Run("OpenRegular follows symlinks by default and refuses them with O_NOFOLLOW", func(t *testing.T) {
		target := writeSecret(t, "x\n", 0o600)
		link := filepath.Join(t.TempDir(), "link")
		require.NoError(t, os.Symlink(target, link))

		f, info, err := OpenRegular(link, 0)
		require.NoError(t, err)
		require.NoError(t, f.Close())
		assert.True(t, info.Mode().IsRegular())

		_, _, err = OpenRegular(link, syscall.O_NOFOLLOW)
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrNotRegular), "a refused symlink is an open error, not a not-regular file")
	})
}

// TestFilePaths_ReturnsSetVariablesInOrder: only non-empty X_FILE values, in argument
// order, so startup checks exactly the files the operator configured.
func TestFilePaths_ReturnsSetVariablesInOrder(t *testing.T) {
	t.Setenv("MUT_A_FILE", "/run/secrets/a")
	t.Setenv("MUT_B_FILE", "")
	t.Setenv("MUT_C_FILE", "/run/secrets/c")
	assert.Equal(t, []string{"/run/secrets/c", "/run/secrets/a"}, FilePaths("MUT_C", "MUT_B", "MUT_A", "MUT_D"))
	assert.Empty(t, FilePaths())
	assert.Empty(t, FilePaths("MUT_B", "MUT_D"))
}

func TestNotRegularError_MessageAndIdentity(t *testing.T) {
	err := error(&NotRegularError{What: "CA bundle", Path: "/etc/ca.pem"})
	assert.Equal(t, "CA bundle /etc/ca.pem: not a regular file", err.Error())
	assert.ErrorIs(t, err, ErrNotRegular)
	assert.False(t, errors.Is(err, os.ErrNotExist))
	assert.False(t, errors.Is(errors.New("other"), ErrNotRegular))
}

// OpenRegularNamed / ReadRegularFile serve operator-supplied non-secret input: a
// non-regular path is a NotRegularError naming the input, any other failure passes
// through unchanged, and a regular file is returned whole (no trimming, no size cap).
func TestOpenRegularNamed_RefusalsNameTheInput(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))

	for name, path := range map[string]string{"directory": dir, "fifo": fifo} {
		t.Run(name, func(t *testing.T) {
			f, err := OpenRegularNamed("license", path)
			require.Nil(t, f)
			var nre *NotRegularError
			require.ErrorAs(t, err, &nre)
			assert.Equal(t, "license", nre.What)
			assert.Equal(t, path, nre.Path)
			assert.ErrorIs(t, err, ErrNotRegular)
			assert.Equal(t, "license "+path+": not a regular file", err.Error())
		})
	}
	t.Run("missing file passes the open error through", func(t *testing.T) {
		f, err := OpenRegularNamed("license", filepath.Join(dir, "absent"))
		require.Nil(t, f)
		require.ErrorIs(t, err, os.ErrNotExist)
		var nre *NotRegularError
		assert.False(t, errors.As(err, &nre))
		var pe *os.PathError
		assert.ErrorAs(t, err, &pe, "the *os.PathError already carries the path")
	})
	t.Run("regular file is returned open", func(t *testing.T) {
		p := writeSecret(t, "bundle\n", 0o600)
		f, err := OpenRegularNamed("license", p)
		require.NoError(t, err)
		defer func() { _ = f.Close() }()
		b, err := io.ReadAll(f)
		require.NoError(t, err)
		assert.Equal(t, "bundle\n", string(b))
	})
}

func TestReadRegularFile(t *testing.T) {
	t.Run("returns the whole file untrimmed", func(t *testing.T) {
		b, err := ReadRegularFile("backup", writeSecret(t, "line1\nline2\n\n", 0o600))
		require.NoError(t, err)
		assert.Equal(t, "line1\nline2\n\n", string(b))
	})
	t.Run("empty regular file is an empty read, not an error", func(t *testing.T) {
		b, err := ReadRegularFile("backup", writeSecret(t, "", 0o600))
		require.NoError(t, err)
		assert.Empty(t, b)
	})
	t.Run("refuses a directory by name", func(t *testing.T) {
		dir := t.TempDir()
		b, err := ReadRegularFile("backup", dir)
		require.Nil(t, b)
		assert.EqualError(t, err, "backup "+dir+": not a regular file")
	})
	t.Run("refuses a FIFO without blocking", func(t *testing.T) {
		fifo := filepath.Join(t.TempDir(), "fifo")
		require.NoError(t, syscall.Mkfifo(fifo, 0o600))
		done := make(chan error, 1)
		go func() { _, err := ReadRegularFile("backup", fifo); done <- err }()
		select {
		case err := <-done:
			assert.ErrorIs(t, err, ErrNotRegular)
		case <-time.After(5 * time.Second):
			t.Fatal("blocked opening a FIFO instead of refusing it")
		}
	})
	t.Run("missing file", func(t *testing.T) {
		_, err := ReadRegularFile("backup", filepath.Join(t.TempDir(), "absent"))
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}

// fakeModeInfo is an os.FileInfo that reports an arbitrary mode: the sandbox this suite
// also runs in refuses to set setuid/setgid/sticky bits on real files.
type fakeModeInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (f fakeModeInfo) Mode() os.FileMode { return f.mode }

// TestCheckInfo_RefusesSpecialBitsGroupWriteAndOther: whatever else is right about a
// file, a setuid/setgid/sticky bit, any access for other and group write are each refused
// on their own, with the reason named (the owner is judged only after these).
func TestCheckInfo_RefusesSpecialBitsGroupWriteAndOther(t *testing.T) {
	real, err := os.Stat(writeSecret(t, "x\n", 0o600))
	require.NoError(t, err)
	for name, tc := range map[string]struct {
		mode   os.FileMode
		reason string
	}{
		"setuid":      {0o600 | os.ModeSetuid, "setuid/setgid/sticky bit"},
		"setgid":      {0o600 | os.ModeSetgid, "setuid/setgid/sticky bit"},
		"sticky":      {0o600 | os.ModeSticky, "setuid/setgid/sticky bit"},
		"other read":  {0o604, "accessible to other users"},
		"other write": {0o602, "accessible to other users"},
		"other exec":  {0o601, "accessible to other users"},
		"group write": {0o620, "writable by its group"},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkInfo(fakeModeInfo{FileInfo: real, mode: tc.mode})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.reason)
		})
	}
	t.Run("0600 owned by the running user is accepted", func(t *testing.T) {
		require.NoError(t, checkInfo(fakeModeInfo{FileInfo: real, mode: 0o600}))
	})
}
