package secretenv

// FuzzReadSecretFileRoundTrip drives ReadFile -- the whole secret-file read path
// (OpenRegular -> ReadCapped -> trimOneTerminator -> empty-file refusal) used for
// *_FILE secrets and config-key secret files (metrics_token_file, etc.). The file
// bytes are untrusted operator/orchestrator input.
//
// ORACLE (round-trip + bounded + fail-closed, each a direction that cannot
// false-positive):
//
//	Let want = trimOneTerminator(content).
//	  - FAIL-CLOSED EMPTY: if want == "" (an empty file, or one that is only a
//	    single line terminator) ReadFile MUST return an error -- a secret is never
//	    the empty string. It must not hand back "" as a successful value.
//	  - ROUND-TRIP: otherwise ReadFile MUST succeed and return EXACTLY want. The
//	    read path applies one trim and nothing else: no truncation below the cap,
//	    no extra stripping, no decoding, no corruption.
//	  - BOUNDED: the returned value is never longer than MaxSecretFileSize.
//	  - never panics on arbitrary bytes.
//
// The round-trip compares against trimOneTerminator applied independently to the
// same bytes, which is the documented contract ("read the file, strip ONE
// trailing line terminator"); any deviation is a real behaviour change to a
// secret-reading function, so the equality cannot false-positive on correct code.
//
// WHAT THIS DOES NOT VERIFY:
//   - It does not exercise non-regular files (FIFO/device/socket): those cannot
//     be produced from fuzz bytes in a temp dir, and OpenRegular's ErrNotRegular
//     gate has its own tests. Only regular files are driven here.
//   - It does not reach the >1 MiB size-cap boundary: fuzz mutation does not
//     realistically generate a megabyte, so ReadCapped's too-large refusal is
//     exercised by its unit tests, not here. The BOUNDED clause still holds for
//     every size.
//   - It does not judge permissions or owner (ReadFile uses checkPerms=false);
//     that is the classifier fuzzer's job.
//   - It does not assert error-text non-disclosure (covered by the describe/leak
//     and precedence targets); the only error path reachable with small fuzz
//     bytes is the empty-file refusal, whose message carries no content.

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzReadSecretFileRoundTrip(f *testing.F) {
	for _, s := range []string{
		"secret", "secret\n", "secret\r\n", "secret\r",
		"", "\n", "\r\n", "multi\nline\nsecret\n",
		"  spaces kept  ", "\x00binary\x01", "trailing\n\n",
	} {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, content []byte) {
		path := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Skipf("write fixture: %v", err)
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ReadFile panicked on %q: %v", content, r)
			}
		}()

		want := trimOneTerminator(string(content))
		v, err := ReadFile(path)

		if want == "" {
			if err == nil {
				t.Fatalf("empty secret accepted: content=%q returned value=%q with no error", content, v)
			}
			return
		}
		if err != nil {
			t.Fatalf("readable non-empty file errored: content=%q err=%v", content, err)
		}
		if v != want {
			t.Fatalf("read-path corrupted the secret: content=%q got %q want %q", content, v, want)
		}
		if len(v) > MaxSecretFileSize {
			t.Fatalf("returned value exceeds the cap: len=%d > %d", len(v), MaxSecretFileSize)
		}
	})
}
