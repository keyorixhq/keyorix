package crypto

// LIB-FUZZ-2 target 4b: spf13/pflag behind RegisterPassphraseFlags, and the
// passphrase sources those flags select (ResolvePassphrase).
//
// Inventory. `--passphrase-fd N`, `--passphrase-file PATH`, `--passphrase-stdin`
// (and the --new- twins) are typed by the operator of the server and the admin
// commands that unlock the master key; what they point at is the passphrase.
// pflag parses the flags (the fd value through the custom passphraseFDValue),
// ResolvePassphrase reads the source, and every refusal is formatted into an
// error that reaches the terminal or the journal. The data the harness does not
// control is the CONTENT of the source (a file, an inherited descriptor, a pipe
// on stdin, an environment variable), because that is the secret.
//
// Oracles:
//   - a sentinel is planted inside the content of every source kind; it must
//     not appear in any returned error, in Describe, in the flag set's usage
//     text or in pflag's parse error, whatever the surrounding bytes, permissions
//     or combination of sources;
//   - an error never comes with bytes (a half-read passphrase);
//   - success returns exactly the content with one trailing "\n" then one "\r"
//     removed (the environment variable: whitespace-trimmed), from the first
//     source of fd, file, stdin, environment;
//   - FDSet is true if and only if the fd flag parsed, and a value that is not
//     an integer is refused without touching the descriptor fields.
//
// A passphrase typed as the VALUE of a mis-used flag (--passphrase-file hunter2)
// is echoed back by pflag and by the "opening %s %q" refusal: that is the
// metadata-echo the CLI canary rules (internal/fuzzutil/canary,
// cliCanaryRules "meta-stderr") allow on purpose, the user having typed it, so
// it is not an oracle here.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/spf13/pflag"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

const (
	ppSentinel = "KXSENTINEL-7c1e5a90-passphrase"
	ppEnv      = "KEYORIX_FUZZ_PASSPHRASE"
)

// ppExpect is the independent expectation: the first enabled source in the
// precedence order fd, file, stdin, environment, and what it must yield.
func ppExpect(sources uint8, content []byte, filePerm os.FileMode) (want []byte, wantErr bool) {
	trim := func(b []byte) []byte {
		b = bytes.TrimSuffix(b, []byte("\n"))
		return bytes.TrimSuffix(b, []byte("\r"))
	}
	switch {
	case sources&1 != 0: // fd
		return trim(content), len(content) == 0
	case sources&2 != 0: // file
		return trim(content), len(content) == 0 || filePerm&0o077 != 0
	case sources&4 != 0: // stdin
		return trim(content), len(content) == 0
	case sources&8 != 0: // environment
		v := strings.TrimSpace(string(content))
		return []byte(v), v == ""
	default: // no source at all (the *_FILE variant is judged separately)
		return nil, true
	}
}

// ppCheck is the oracle over one resolution.
func ppCheck(res []byte, err error, describe, usage, parseErr string, sources uint8, content []byte, filePerm os.FileMode) error {
	for name, text := range map[string]string{"describe": describe, "usage": usage, "parse error": parseErr, "error": fmt.Sprint(err)} {
		if strings.Contains(text, ppSentinel) {
			return fmt.Errorf("the passphrase appeared in the %s text: %q", name, text)
		}
	}
	if err != nil {
		if len(res) != 0 {
			return errors.New("ResolvePassphrase returned bytes together with an error")
		}
		if want, wantErr := ppExpect(sources, content, filePerm); !wantErr && sources&0x18 == 0 {
			return fmt.Errorf("refused a readable source (%v); expected %q", err, want)
		}
		return nil
	}
	want, wantErr := ppExpect(sources, content, filePerm)
	switch {
	case sources&0x18 != 0 && sources&7 == 0:
		return nil // the *_FILE variant is secretenv's own contract; only the leak checks apply
	case wantErr:
		return fmt.Errorf("accepted a source that must be refused (sources %03b, perm %o, %d bytes)", sources, filePerm, len(content))
	case !bytes.Equal(res, want):
		return fmt.Errorf("returned %q, want %q", res, want)
	}
	return nil
}

func FuzzPassphraseSources(f *testing.F) {
	for _, s := range []struct {
		sources uint8
		pre     string
		post    string
		perm    uint16
	}{
		{1, "", "", 0o600}, {2, "", "\n", 0o600}, {2, "", "", 0o640}, {2, "x\r", "\r\n", 0o400}, {4, "", "\n", 0},
		{8, "  ", "\t \n", 0}, {16, "", "", 0o600}, {16, "", "", 0o644}, {3, "a", "b", 0o600}, {6, "", "", 0o666},
		{1, "\x00\xff", "\x00", 0}, {2, "", "\n\n", 0o600}, {2, "\n", "", 0o600},
	} {
		f.Add(s.sources, uint8(1), []byte(s.pre), []byte(s.post), s.perm, "", "--passphrase-fd=3")
	}
	for _, src := range []uint8{1, 2, 4, 8} { // no sentinel: empty and newline-only sources
		f.Add(src, uint8(0), []byte{}, []byte{}, uint16(0o600), "", "")
		f.Add(src, uint8(0), []byte("\n"), []byte{}, uint16(0o600), "", "")
		f.Add(src, uint8(0), []byte("\r"), []byte("\n"), uint16(0o600), "", "")
	}
	f.Add(uint8(2), uint8(1), []byte{}, []byte{}, uint16(0o600), "12", "--new-passphrase-file=/x\x00--passphrase-stdin\x00--passphrase-fd=-1")
	f.Fuzz(func(t *testing.T, sources, plant uint8, pre, post []byte, perm uint16, fdArg, soup string) {
		sources &= 0x1f
		if sources&0x18 == 0x18 { // KEYORIX_..._FILE together with the plain variable: secretenv's error, not ours
			sources &^= 0x10
		}
		if len(pre) > 2048 || len(post) > 2048 {
			t.Skip()
		}
		// plant&1 == 0 leaves the sentinel out, which is what lets empty and
		// newline-only sources (the refusal paths) be generated at all.
		content := append(append([]byte{}, pre...), post...)
		if plant&1 == 1 {
			content = append(append(append([]byte{}, pre...), ppSentinel...), post...)
		}
		if sources&0x18 != 0 && bytes.IndexByte(content, 0) >= 0 {
			t.Skip() // an environment value cannot hold NUL
		}
		// Owner-readable always: a file the owner cannot open is refused by the
		// kernel, which says nothing about the code under test.
		filePerm := os.FileMode(perm)&0o777 | 0o400

		// --- parse side: pflag + passphraseFDValue ---
		fs := pflag.NewFlagSet("fuzz", pflag.ContinueOnError)
		var parseOut bytes.Buffer
		fs.SetOutput(&parseOut)
		var src PassphraseSource
		RegisterPassphraseFlags(fs, &src, "", "passphrase")
		var parseErr error
		fuzzutil.Guard(t.Fatalf, "pflag.Parse", func() {
			parseErr = fs.Parse(append([]string{"--passphrase-fd=" + fdArg}, strings.Split(soup, "\x00")...))
		})
		if _, aerr := strconv.Atoi(fdArg); parseErr == nil && aerr != nil && !strings.Contains(soup, "passphrase-fd") {
			t.Fatalf("--passphrase-fd=%q parsed without error but is not an integer", fdArg)
		}
		if _, aerr := strconv.Atoi(fdArg); aerr != nil && src.FDSet && src.FD != 0 && !strings.Contains(soup, "passphrase-fd") {
			t.Fatalf("a rejected fd value %q still set FD=%d", fdArg, src.FD)
		}

		// --- resolve side: a fresh source over the planted content ---
		dir := t.TempDir()
		var s PassphraseSource
		if sources&1 != 0 {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write(content)
			_ = w.Close()
			// ResolvePassphrase closes the descriptor it is given, so it gets a
			// duplicate and r closes its own: no descriptor number is closed twice,
			// which could otherwise close one a later open has been handed.
			dup, err := syscall.Dup(int(r.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			_ = r.Close()
			s.FDSet, s.FD = true, dup
		}
		if sources&2 != 0 {
			p := filepath.Join(dir, "pass")
			if err := os.WriteFile(p, content, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, filePerm); err != nil {
				t.Fatal(err)
			}
			s.FilePath = p
		}
		if sources&4 != 0 {
			p := filepath.Join(dir, "stdin")
			if err := os.WriteFile(p, content, 0o600); err != nil {
				t.Fatal(err)
			}
			in, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			old := os.Stdin
			os.Stdin, s.Stdin = in, true
			defer func() { os.Stdin = old; _ = in.Close() }()
		}
		if sources&8 != 0 {
			t.Setenv(ppEnv, string(content))
		}
		if sources&0x10 != 0 {
			p := filepath.Join(dir, "envfile")
			if err := os.WriteFile(p, content, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, filePerm); err != nil {
				t.Fatal(err)
			}
			t.Setenv(ppEnv+"_FILE", p)
		}

		var (
			res []byte
			err error
		)
		fuzzutil.Guard(t.Fatalf, "ResolvePassphrase", func() { res, err = ResolvePassphrase(s, ppEnv) })
		if oerr := ppCheck(res, err, s.Describe(ppEnv), fs.FlagUsages(), parseOut.String()+fmt.Sprint(parseErr), sources, content, filePerm); oerr != nil {
			t.Fatal(oerr)
		}
	})
}

// TestPassphraseOracle_RedProof plants each fault and requires the oracle to name it.
func TestPassphraseOracle_RedProof(t *testing.T) {
	content := []byte("pre" + ppSentinel + "post\n")
	good := func() error {
		return ppCheck([]byte("pre"+ppSentinel+"post"), nil, "--passphrase-file \"/x\"", "usage", "", 2, content, 0o600)
	}
	if err := good(); err != nil {
		t.Fatalf("oracle rejects a correct resolution: %v", err)
	}
	leak := errors.New("reading --passphrase-file: bad passphrase " + ppSentinel)
	for name, err := range map[string]error{
		"sentinel in the returned error": ppCheck(nil, leak, "d", "u", "", 2, content, 0o600),
		"sentinel in Describe":           ppCheck(nil, errors.New("e"), "file "+ppSentinel, "u", "", 2, content, 0o600),
		"sentinel in usage":              ppCheck([]byte("x"), nil, "d", "u"+ppSentinel, "", 2, content, 0o600),
		"sentinel in the parse error":    ppCheck(nil, errors.New("e"), "d", "u", "unknown "+ppSentinel, 2, content, 0o600),
		"bytes with an error":            ppCheck([]byte("half"), errors.New("e"), "d", "u", "", 2, content, 0o600),
		"group-readable file accepted":   ppCheck([]byte("pre"+ppSentinel+"post"), nil, "d", "u", "", 2, content, 0o640),
		"empty source accepted":          ppCheck(nil, nil, "d", "u", "", 4, nil, 0),
		"wrong bytes":                    ppCheck([]byte("pre"+ppSentinel+"post\n"), nil, "d", "u", "", 2, content, 0o600),
		"readable source refused":        ppCheck(nil, errors.New("e"), "d", "u", "", 1, content, 0),
	} {
		if err == nil {
			t.Errorf("oracle missed planted fault: %s", name)
		}
	}
}
