// Hostile-argv fuzz harness for spf13/pflag (the flag parser under spf13/cobra,
// which Keyorix's CLI is built on).
//
// This target attacks FlagSet.Parse with an attacker-chosen argv. A real CLI
// caller controls argv, so argv is the untrusted surface. The FlagSet is built
// with ContinueOnError so a parse failure returns an error instead of calling
// os.Exit (which pflag's default ExitOnError does) — that keeps the fuzzer alive
// and makes "panic" the only crash class.
//
// Oracle (crash-only / bounded):
//   - no panic inside Parse for any argv.
//   - bounded work: Parse of a bounded argv returns within a generous budget.
//
// What this oracle does NOT verify: that parse RESULTS are correct, cobra's own
// command dispatch, or shell-completion code paths — only that pflag's argv
// tokeniser/assigner never panics or hangs on hostile argv.
package spf13pflaghostile

import (
	"strings"
	"testing"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

func newFS() *flag.FlagSet {
	fs := flag.NewFlagSet("fuzz", flag.ContinueOnError)
	fs.String("name", "", "")
	fs.StringP("output", "o", "", "")
	fs.Int("count", 0, "")
	fs.IntP("verbose", "v", 0, "")
	fs.Bool("force", false, "")
	fs.BoolP("yes", "y", false, "")
	fs.StringSlice("tag", nil, "")
	fs.StringArray("arr", nil, "")
	fs.CountP("debug", "d", "")
	fs.Duration("timeout", 0, "")
	fs.StringToString("label", nil, "")
	return fs
}

func FuzzPflagParse(f *testing.F) {
	// argv elements are NUL-separated so empty arguments and arguments that
	// contain spaces are reachable.
	f.Add("--name=x\x00-o\x00out\x00--count\x003\x00-vvv")
	f.Add("--force\x00--tag\x00a\x00--tag\x00b\x00--\x00positional")
	f.Add("-dddd\x00--label\x00k=v\x00--timeout\x005s")
	f.Add("--=--")
	f.Add("-")
	f.Add("--name")
	f.Add("--count=notanint")
	f.Add("--name\x00\x00a b")

	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > 16*1024 {
			return
		}
		args := strings.Split(line, "\x00")
		if len(args) > 4096 {
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			fs := newFS()
			fs.SetOutput(discard{})
			_ = fs.Parse(args)
		}()
		if _, ok, fz := fuzzutil.Wait(done, 10*time.Second); !ok {
			t.Logf("stall monitor: process frozen %s of the wait window", fz)
			t.Fatalf("bounded-work: pflag.Parse did not return in 10s for %d args", len(args))
		}
	})
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
