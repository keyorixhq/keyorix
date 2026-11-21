// Reachability-first fuzz harness for go.yaml.in/yaml/v4, the YAML decoder
// Keyorix uses to read operator configuration and the CLI credential store.
//
// Live callers (traced from reachgen, prov=config):
//   - internal/config/explicit_paths.go:49        yaml.Unmarshal(data, &root)
//   - internal/config/insecure_settings_aliases.go yaml.Unmarshal(data, &root)
//   - cli/internal/credstore/file.go:101           yaml.NewDecoder(f).Decode(...)
//   - cli/internal/migrate/migrate.go              yaml.Unmarshal(data, &cfg)
//     `data` is the contents of an operator-provided config / credential file.
//
// Oracle (sound bounded-work): yaml.Unmarshal of arbitrary bytes into a generic
// value
//   - must not panic,
//   - must return within a generous wall-clock bound, and
//   - if it SUCCEEDS, the re-marshaled result must not be wildly larger than the
//     input (bounded expansion). A YAML anchor/alias "billion laughs" bomb that
//     the decoder EXPANDED instead of rejecting would blow this bound; yaml v4
//     caps alias expansion, so the oracle is here to notice a regression.
//
// What this oracle does NOT verify:
//   - NOT round-trip fidelity (Unmarshal∘Marshal∘Unmarshal equality) — YAML is
//     not canonical, so that is not a sound invariant here.
//   - NOT the schema/validation layer Keyorix applies on top (explicit_paths,
//     insecure_settings_aliases do their own structural checks, untested here).
//   - NOT memory/allocation volume directly: it bounds TIME and OUTPUT SIZE,
//     not peak heap, so a transient large allocation that is freed would pass.
//     True infinite hangs are caught by `go test`'s own fuzz timeout.
//   - NOT the decode into Keyorix's concrete config structs (only into a generic
//     map, which exercises the parser without Keyorix's field tags).
package yamlhostile

import (
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v4"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

const decodeDeadline = 2 * time.Second

// Bounded-output backstop. yaml v4's anti-"billion-laughs" protection is an
// ABSOLUTE alias-work budget, NOT a fixed expansion ratio: it rejects a document
// ("document contains excessive aliasing") once total alias resolution exceeds a
// threshold, so the maximum output an aliased small input can produce is bounded
// in ABSOLUTE terms (measured on v4: ~38 KiB, 38292 B, across a branch×depth
// sweep — see report §Findings), not as a ratio of input size. An input-relative ratio bound is the
// WRONG shape and false-positives on legitimately-budgeted expansions (two such
// were found and triaged during this campaign). So we bound output absolutely:
//
//	output <= len(input)*remarshalGrowth + aliasHeadroom
//
// remarshalGrowth covers ordinary re-serialisation growth of a NON-alias doc;
// aliasHeadroom (1 MiB, ~27x above the measured ~38 KiB ceiling) covers the
// alias budget's full legitimate contribution with wide margin. The bound never
// fires on yaml v4's sanctioned behaviour, and DOES fire if the alias budget is
// removed/grossly loosened (a few-level 9-way nest then amplifies a <1 KiB input
// to many MiB). It does NOT catch a SMALL loosening of the budget.
const (
	remarshalGrowth = 8
	aliasHeadroom   = 1 << 20
)

// aliasBomb is a classic YAML "billion laughs"; yaml v4 should REJECT it (its
// alias budget is exceeded), not expand it. Used as a seed to keep that path hot.
const aliasBomb = `
a: &a ["x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
`

func FuzzYAMLDecodeBoundedWork(f *testing.F) {
	f.Add([]byte("name: value\nlist:\n  - a\n  - b\n"))
	f.Add([]byte(aliasBomb))
	f.Add([]byte("{}"))
	f.Add([]byte(""))
	f.Add([]byte("- - - - - - - - - -")) // deep flow nesting
	// Triaged ARTIFACT seeds (see report §Findings): nested 9-way alias docs that
	// yaml v4 LEGITIMATELY expands (measured on v4: ~103x and ~313x
	// respectively, to ~11 KiB and ~32 KiB — both ABSOLUTELY bounded by yaml v4's alias budget, which rejects
	// deeper nests outright). Both exposed that an input-relative ratio bound is
	// the wrong shape; kept as regression seeds under the absolute bound. A
	// removal of yaml v4's alias budget would let these amplify to many MiB and
	// trip the bound.
	f.Add([]byte("0: &a\n1: &b [00,00,00,&0,&0,&0,&0,&0,00]\n2: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n7: [*c,*c,*c,*c,*c,*c,*c,*c,*c]"))
	f.Add([]byte("0: &a [0,0,0,0,0,0]\n1: &b [*a,*a,*a,*a,*a,*a,*a,*a]\n2: &c [*b,*b,*b,*b,*b,*b]\n7: [*c,*c,*c,*c,*c,*c,*c]"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			data = data[:1<<16]
		}
		start := time.Now()
		var v any
		err := decode(data, &v)
		if over, why := fuzzutil.OverDeadline(start, decodeDeadline); over {
			t.Fatalf("yaml decode %s on %d bytes — unbounded work", why, len(data))
		}
		if err != nil {
			return // rejection is fine (e.g. the alias bomb); no panic occurred
		}
		// Bounded expansion: re-marshal and bound the size.
		out, merr := yaml.Marshal(v)
		if merr != nil {
			return // can't bound; not a decoder defect
		}
		bound := len(data)*remarshalGrowth + aliasHeadroom
		if len(out) > bound {
			t.Fatalf("decoded value re-marshaled to %d bytes from %d input (> %d bound) — alias budget regressed?",
				len(out), len(data), bound)
		}
	})
}

// decode is factored out so the red-proof can plant a defect here in a scratch
// copy (e.g. `time.Sleep(decodeDeadline * 2)`, or lower the expansion bound) and
// watch the bounded-work assertion fire while the unmodified path stays green.
func decode(data []byte, v any) error {
	return yaml.Unmarshal(data, v)
}
