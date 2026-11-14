// Reachability-first fuzz harness for gopkg.in/yaml.v3, the YAML decoder
// Keyorix uses to read operator configuration and the CLI credential store.
//
// Live callers (traced from reachgen, prov=config):
//   - internal/config/explicit_paths.go:49        yaml.Unmarshal(data, &root)
//   - internal/config/insecure_settings_aliases.go yaml.Unmarshal(data, &root)
//   - cli/internal/credstore/file.go:101           yaml.NewDecoder(f).Decode(...)
//   - cli/internal/migrate/migrate.go              yaml.Unmarshal(data, &cfg)
//   `data` is the contents of an operator-provided config / credential file.
//
// Oracle (sound bounded-work): yaml.Unmarshal of arbitrary bytes into a generic
// value
//   - must not panic,
//   - must return within a generous wall-clock bound, and
//   - if it SUCCEEDS, the re-marshaled result must not be wildly larger than the
//     input (bounded expansion). A YAML anchor/alias "billion laughs" bomb that
//     the decoder EXPANDED instead of rejecting would blow this bound; yaml.v3
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

	"gopkg.in/yaml.v3"
)

const decodeDeadline = 2 * time.Second

// expansionFactor bounds decoded-then-remarshaled size per input byte. It is set
// ABOVE yaml.v3's own measured legitimate alias-expansion ceiling (~103x for
// small inputs; yaml.v3 rejects anything that would expand further with
// "document contains excessive aliasing" — confirmed, see report §Findings), so
// the bound never fires on yaml.v3's sanctioned behaviour but DOES fire if that
// alias budget regresses (a 3-level 9-way nest would then expand >500x).
const expansionFactor = 256

// aliasBomb is a classic YAML "billion laughs"; yaml.v3 should REJECT it (its
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
	// Triaged ARTIFACT seed (see report): a 2-level 9-way alias nest that
	// yaml.v3 LEGITIMATELY expands ~100x before its alias budget would reject a
	// deeper one ("document contains excessive aliasing" at 3 levels). Kept as a
	// regression seed: it must stay UNDER expansionFactor, and a removal of
	// yaml.v3's alias budget (which would let a 3+-level nest through at >500x)
	// must trip the bound.
	f.Add([]byte("0: &a\n1: &b [00,00,00,&0,&0,&0,&0,&0,00]\n2: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n7: [*c,*c,*c,*c,*c,*c,*c,*c,*c]"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			data = data[:1<<16]
		}
		start := time.Now()
		var v any
		err := decode(data, &v)
		if elapsed := time.Since(start); elapsed > decodeDeadline {
			t.Fatalf("yaml decode took %v (> %v) on %d bytes — unbounded work", elapsed, decodeDeadline, len(data))
		}
		if err != nil {
			return // rejection is fine (e.g. the alias bomb); no panic occurred
		}
		// Bounded expansion: re-marshal and bound the size.
		out, merr := yaml.Marshal(v)
		if merr != nil {
			return // can't bound; not a decoder defect
		}
		bound := len(data)*expansionFactor + 4096
		if len(out) > bound {
			t.Fatalf("decoded value re-marshaled to %d bytes from %d input (> %d bound) — alias/anchor expansion?",
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
