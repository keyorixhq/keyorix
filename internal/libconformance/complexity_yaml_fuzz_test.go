package libconformance

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/complexity"
)

// FuzzYAMLParseComplexity is a cost-per-byte oracle over gopkg.in/yaml.v3's
// decoder, with a focus on the anchor/alias/merge-key expansion that is the
// classic YAML "billion laughs" amplification: a few hundred bytes of nested
// aliases (`a: &a [*b,*b]; b: &b [*c,*c]; ...`) expand to an exponentially large
// in-memory structure.
//
// Reachability (recorded honestly): in Keyorix today yaml.v3 parses OPERATOR-
// controlled input, not network-attacker input — server/CLI config
// (internal/config/config.go), k8s sync config (internal/k8ssync/config.go),
// and `keyorix secret import` of a local YAML file
// (cli/cmd/secret_import_parsers.go). An operator importing a hostile YAML file,
// or a config supplied by a lower-trust automation layer, is the realistic
// threat; there is no network path that reaches yaml.v3 with a size cap. This
// target is therefore primarily an UPSTREAM-ready amplification check (and a
// regression guard should a future feature expose yaml.v3 to the network).
//
// Property: decoding N bytes of YAML must allocate O(N). yaml.v3 added an
// alias-expansion budget after the original billion-laughs report; this target
// is the standing check that the budget is still effective for the versions
// Keyorix pins.
//
// What this oracle does NOT verify:
//   - Nothing about the decoded value. Cost only.
//   - It decodes into interface{}; decoding into a typed struct (as config does)
//     has a different, generally smaller, profile — this is the permissive
//     worst case.
//   - Allocated bytes, not CPU.
func FuzzYAMLParseComplexity(f *testing.F) {
	f.Add([]byte("a: 1\n"))
	f.Add([]byte("- 1\n- 2\n- 3\n"))
	f.Add([]byte("a: &x 1\nb: *x\n")) // simple alias
	f.Add([]byte("<<: &m {a: 1}\nc:\n  <<: *m\n"))
	// A compact billion-laughs seed (bounded so the seed itself is cheap).
	f.Add([]byte("a: &a [x,x]\nb: &b [*a,*a]\nc: &c [*b,*b]\nd: [*c,*c]\n"))
	f.Add([]byte(""))

	// yaml.v3's own expansion budget should keep this linear-ish; a 512 B/byte
	// slope with a 2 MiB floor flags a genuine exponential blow-up while
	// tolerating the moderate fan-out of legitimate alias reuse. No fixed
	// absolute ceiling (no network size limit applies); the slope is the oracle.
	budget := complexity.Budget{
		MaxAllocBytesPerByte: 512,
		FloorBytes:           2 << 20,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		n := len(data)
		c := complexity.Measure(func() {
			var v any
			_ = yaml.Unmarshal(data, &v) // result/err discarded; cost is the property
		})
		budget.Check(t.Fatalf, "yaml.Unmarshal", n, c)
	})
}
