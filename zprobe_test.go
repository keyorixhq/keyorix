// SCRATCH probe — not for commit. Measures super-linearity of decode/encode
// across doubling nesting depth and width. Run with:
//
//	go test -run TestProbe -v .
package yaml_test

import (
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v4"
)

func timeIt(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

func TestProbeDeepFlow(t *testing.T) {
	for _, d := range []int{500, 1000, 2000, 4000, 8000} {
		in := []byte(strings.Repeat("[", d) + strings.Repeat("]", d) + "\n")
		var v any
		dec := timeIt(func() { _ = yaml.Unmarshal(in, &v) })
		var enc time.Duration
		if v != nil {
			enc = timeIt(func() { _, _ = yaml.Marshal(v) })
		}
		t.Logf("flow depth=%-6d bytes=%-7d decode=%-10v encode=%-10v", d, len(in), dec, enc)
	}
}

func TestProbeDeepBlockSeq(t *testing.T) {
	for _, d := range []int{500, 1000, 2000, 4000} {
		// nested block sequences: "- - - ... x"
		in := []byte(strings.Repeat("- ", d) + "x\n")
		var v any
		dec := timeIt(func() { _ = yaml.Unmarshal(in, &v) })
		var enc time.Duration
		if v != nil {
			enc = timeIt(func() { _, _ = yaml.Marshal(v) })
		}
		t.Logf("blockseq depth=%-6d bytes=%-7d decode=%-10v encode=%-10v", d, len(in), dec, enc)
	}
}

func TestProbeDeepBlockMap(t *testing.T) {
	// nested block mappings via indentation: a:\n b:\n  c:\n ...
	for _, d := range []int{200, 400, 800, 1600} {
		var sb strings.Builder
		for i := 0; i < d; i++ {
			sb.WriteString(strings.Repeat(" ", i))
			sb.WriteString("k:\n")
		}
		sb.WriteString(strings.Repeat(" ", d))
		sb.WriteString("v\n")
		in := []byte(sb.String())
		var v any
		dec := timeIt(func() { _ = yaml.Unmarshal(in, &v) })
		var enc time.Duration
		if v != nil {
			enc = timeIt(func() { _, _ = yaml.Marshal(v) })
		}
		t.Logf("blockmap depth=%-6d bytes=%-7d decode=%-10v encode=%-10v", d, len(in), dec, enc)
	}
}

func TestProbeLongScalar(t *testing.T) {
	for _, n := range []int{10000, 20000, 40000, 80000} {
		in := []byte("x: " + strings.Repeat("a", n) + "\n")
		var v any
		dec := timeIt(func() { _ = yaml.Unmarshal(in, &v) })
		enc := timeIt(func() { _, _ = yaml.Marshal(v) })
		t.Logf("longscalar n=%-7d decode=%-10v encode=%-10v", n, dec, enc)
	}
}

func TestProbeWideFlowSeq(t *testing.T) {
	for _, n := range []int{10000, 20000, 40000} {
		in := []byte("[" + strings.Repeat("1,", n) + "1]\n")
		var v any
		dec := timeIt(func() { _ = yaml.Unmarshal(in, &v) })
		enc := timeIt(func() { _, _ = yaml.Marshal(v) })
		t.Logf("wideflow n=%-7d bytes=%-8d decode=%-10v encode=%-10v", n, len(in), dec, enc)
	}
}
