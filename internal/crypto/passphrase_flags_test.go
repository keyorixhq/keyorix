package crypto

// RegisterPassphraseFlags and passphraseFDValue had no coverage inside this
// package (their tests live with the CLI callers), so gremlins reported every
// mutant in passphrase_flags.go as NOT COVERED (#3612, MUTANT-CRYPTO-1).

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterPassphraseFlags_NamesPrefixAndUsage(t *testing.T) {
	for _, tc := range []struct{ prefix, human, fd, file, stdin string }{
		{"", "master passphrase", "passphrase-fd", "passphrase-file", "passphrase-stdin"},
		{"new-", "new passphrase", "new-passphrase-fd", "new-passphrase-file", "new-passphrase-stdin"},
	} {
		fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
		var src PassphraseSource
		fdFlag, fileFlag, stdinFlag := RegisterPassphraseFlags(fs, &src, tc.prefix, tc.human)
		assert.Equal(t, tc.fd, fdFlag)
		assert.Equal(t, tc.file, fileFlag)
		assert.Equal(t, tc.stdin, stdinFlag)

		assert.Equal(t, "Read the "+tc.human+" from this already-open file descriptor", fs.Lookup(fdFlag).Usage)
		assert.Equal(t, "Read the "+tc.human+" from this file (refused if group- or world-readable, or owned by anyone but you or root)", fs.Lookup(fileFlag).Usage)
		assert.Equal(t, "Read the "+tc.human+" from stdin", fs.Lookup(stdinFlag).Usage)
		assert.Equal(t, "int", fs.Lookup(fdFlag).Value.Type())
	}
}

func TestRegisterPassphraseFlags_ParsesIntoSource(t *testing.T) {
	parse := func(args ...string) PassphraseSource {
		fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
		var src PassphraseSource
		RegisterPassphraseFlags(fs, &src, "", "passphrase")
		require.NoError(t, fs.Parse(args))
		return src
	}

	assert.Equal(t, PassphraseSource{}, parse(), "no flag passed: nothing is set")
	assert.Equal(t, PassphraseSource{FD: 0, FDSet: true}, parse("--passphrase-fd=0"), "an explicit fd 0 is distinguishable from not passed")
	assert.Equal(t, PassphraseSource{FD: 7, FDSet: true}, parse("--passphrase-fd", "7"))
	assert.Equal(t, PassphraseSource{FilePath: "/run/mp"}, parse("--passphrase-file", "/run/mp"))
	assert.Equal(t, PassphraseSource{Stdin: true}, parse("--passphrase-stdin"))
}

func TestPassphraseFDValue_SetStringType(t *testing.T) {
	var (
		fd  int
		set bool
	)
	v := &passphraseFDValue{dest: &fd, set: &set}
	assert.Equal(t, "0", v.String())

	require.NoError(t, v.Set("12"))
	assert.Equal(t, 12, fd)
	assert.True(t, set)
	assert.Equal(t, "12", v.String())

	fd, set = 0, false
	err := v.Set("not-a-number")
	require.ErrorContains(t, err, `invalid file descriptor "not-a-number"`)
	assert.False(t, set, "a rejected value must not mark the flag as set")
	assert.Equal(t, 0, fd)

	assert.Equal(t, "int", v.Type())
	assert.Equal(t, "0", (&passphraseFDValue{}).String(), "a nil dest renders as 0, not a nil dereference")
}
