//go:build !windows

package credstore_test

// credstore_crash_replay_fuzz_test.go — FuzzCredStoreCrashReplay (FS1).
//
// The thin CLI's credential store (file.go) persists the operator's session
// token to ~/.config/keyorix/credentials.yaml. Save() writes IN PLACE
// (O_WRONLY|O_CREATE|O_TRUNC, no fsync, no temp+rename), so a crash during Save
// can leave a truncated/torn file — unlike ForgetSession's writeKept(), which
// is atomic (temp → Sync → rename). This fuzzes what Load() does with whatever
// post-crash bytes Save can leave.
//
// Oracles (and what each does NOT verify):
//
//	(a) ROUND-TRIP — Save(c) then Load() returns c exactly. DOES NOT verify
//	    durability (Save does not fsync — see the FS1 report finding FS1-F1).
//	(c) SURFACED — an EXISTING credentials file that does not decode as YAML
//	    into Credentials is an error from Load, never a silently-returned
//	    zero/partial Credentials treated as valid. DOES NOT verify that a
//	    truncated-but-still-valid-YAML token is rejected: the credentials file
//	    has NO integrity guard (no checksum/MAC) by design, so a torn Save that
//	    happens to leave valid YAML yields a truncated token Load accepts — a
//	    real but availability-only gap, reported as FS1-F1, not asserted here as
//	    a failure (it is by-design behaviour, not a bug the oracle should flag).
//	ROBUSTNESS / NO FD LEAK — Load never panics and leaks no fd on arbitrary
//	    bytes.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/cli/internal/credstore"
	"gopkg.in/yaml.v3"
)

// credField constrains a fuzzed field to the domain real credential values
// live in: no control characters and no leading/trailing whitespace. YAML
// (yaml.v3) does not byte-round-trip a scalar with a leading newline or
// trailing space — "\n0" marshals and unmarshals back as "0" — but a server
// URL, bearer token, project name or CA-file path never contains such bytes.
// Fuzzing those into the ROUND-TRIP oracle (a) tests YAML scalar-folding
// fidelity, not the credential store's crash-replay behaviour, so this bounds
// the input domain to realistic values (a fixture fix, not an assertion
// change — oracle (c)'s torn-file handling is unaffected and still fuzzed on
// fully arbitrary bytes via mutateCreds).
func credField(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// fdCount returns the open fd count, or ok=false without /proc/self/fd
// (darwin), in which case only the fd-leak sub-check is skipped.
func fdCount() (n int, ok bool) {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	return len(ents), true
}

func FuzzCredStoreCrashReplay(f *testing.F) {
	f.Add("https://vault.example", "tok-abcdef", "proj-1", "/etc/ca.pem", byte(0), uint16(5))
	f.Add("", "", "", "", byte(1), uint16(0))
	f.Add("https://x", "t", "p", "c", byte(2), uint16(1))
	f.Add("srv", "token-with-newline\nand-more", "proj", "ca", byte(3), uint16(10))
	f.Add("s", "tok", "pr", "ca", byte(4), uint16(2))

	f.Fuzz(func(t *testing.T, serverURL, token, project, caFile string, mutSel byte, truncK uint16) {
		dir := t.TempDir()
		path := filepath.Join(dir, "credentials.yaml")
		store := credstore.NewFileStore(path)

		c := credstore.Credentials{
			ServerURL:     credField(serverURL),
			Token:         credField(token),
			ActiveProject: credField(project),
			CAFile:        credField(caFile),
		}

		// ── oracle (a): round-trip ────────────────────────────────────────
		if err := store.Save(c); err != nil {
			t.Fatalf("Save: %v", err)
		}
		got, err := store.Load()
		if err != nil {
			t.Fatalf("Load after Save: %v", err)
		}
		if got != c {
			t.Fatalf("ROUND-TRIP(a): Load != Save: got %+v want %+v", got, c)
		}

		// ── manufacture a post-crash torn file at the credentials path ────
		orig, err := os.ReadFile(path) //nolint:gosec
		if err != nil {
			t.Fatalf("read saved bytes: %v", err)
		}
		mutated, kind := mutateCreds(orig, int(mutSel), int(truncK))
		if err := os.WriteFile(path, mutated, 0o600); err != nil { //nolint:gosec
			t.Fatalf("write mutated creds: %v", err)
		}

		// ── oracle (c): Load must error iff the bytes don't decode ────────
		// Probe through a yaml.Decoder (not yaml.Unmarshal), mirroring Load's
		// exact decode path: on EMPTY input Unmarshal returns nil (zero value)
		// but Decoder.Decode returns io.EOF, so Unmarshal would mis-predict the
		// empty-file case and false-fail the oracle (harness calibration).
		var probe credstore.Credentials
		decodes := yaml.NewDecoder(bytes.NewReader(mutated)).Decode(&probe) == nil
		loaded, lerr := store.Load()
		switch {
		case decodes:
			// Valid YAML → Load must succeed and match the decode. (A
			// truncated-but-valid token is accepted here by design; see the
			// oracle note / FS1-F1. We only assert Load agrees with the parse.)
			if lerr != nil {
				t.Fatalf("SURFACED-WRONG(c): Load errored on YAML-decodable creds (%s): %v", kind, lerr)
			}
			if loaded != probe {
				t.Fatalf("Load disagrees with a direct YAML decode (%s): %+v vs %+v", kind, loaded, probe)
			}
		default:
			// Not decodable → Load MUST surface an error, never a silent
			// zero-value Credentials.
			if lerr == nil {
				t.Fatalf("SILENT-ACCEPT(c): Load returned no error for a credentials file that does not decode as YAML (%s): %q", kind, mutated)
			}
		}

		// ── robustness / fd leak ──────────────────────────────────────────
		before, fdOK := fdCount()
		for range 16 {
			_, _ = store.Load()
		}
		if !fdOK {
			t.Log("no /proc/self/fd: fd-leak sub-check skipped")
			return
		}
		after, _ := fdCount()
		if after > before+2 {
			t.Fatalf("FD LEAK: fd count grew %d→%d across 16 Loads (%s)", before, after, kind)
		}
	})
}

func mutateCreds(orig []byte, sel, truncK int) ([]byte, string) {
	switch sel % 5 {
	case 0:
		return orig, "unchanged"
	case 1:
		k := min(truncK, len(orig))
		return orig[:k], "truncated"
	case 2:
		b := append([]byte(nil), orig...)
		if len(b) > 0 {
			b[truncK%len(b)] ^= 0x10
		}
		return b, "bitflip"
	case 3:
		return append(append([]byte(nil), orig...), []byte("\n\t: : : invalid\n  - [}{")...), "appended-invalid"
	default:
		return []byte{}, "empty"
	}
}
