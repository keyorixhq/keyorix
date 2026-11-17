// SPDX-License-Identifier: BSD-3-Clause

// Package pflagfs fuzzes github.com/spf13/pflag argument parsing (the flag
// engine under spf13/cobra, which DashDiag uses for its whole CLI). The input
// is an argv split on NUL. DashDiag's argv is operator-supplied rather than a
// remote attack surface, so this is a robustness (priority-7) target, not a
// vulnerability hunt.
//
// Oracle: no panic, no hang. Crash-only.
package pflagfs

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func FuzzParse(f *testing.F) {
	f.Add("--count\x003\x00--name\x00x\x00--verbose")
	f.Add("-c\x00-n=\x00--")
	f.Add("--count=\x00--count=--count")
	f.Add("--\x00--name\x00-")
	f.Fuzz(func(t *testing.T, joined string) {
		args := strings.Split(joined, "\x00")
		fs := pflag.NewFlagSet("fuzz", pflag.ContinueOnError)
		fs.SetOutput(discard{})
		var (
			count   int
			name    string
			verbose bool
			ratios  map[string]int
		)
		fs.IntVarP(&count, "count", "c", 0, "")
		fs.StringVarP(&name, "name", "n", "", "")
		fs.BoolVarP(&verbose, "verbose", "v", false, "")
		fs.StringToIntVar(&ratios, "ratios", nil, "")
		_ = fs.Parse(args)
		_ = fs.Args()
	})
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
