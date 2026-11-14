package auditverify

// FuzzParseHighWater feeds arbitrary bytes to ParseHighWater — the parser of
// the system_metadata "audit_checkpoint_highwater" value (checkpoint.go) — a
// value read back from a text column that an operator with database write
// access, or a corrupted store, can set to anything. The parser must fail
// closed (ok=false → "no mark", never a crash), and any value it DOES accept
// must be structurally well formed.
//
// ORACLE (fail-closed structural invariant): a value ParseHighWater accepts in
// the v2 (sealed) layout must carry a seal count >= 1 AND a non-empty seal
// digest. A v2 mark's signature covers Seals and SealDigest; accepting a v2
// value with a zero/absent count or an empty digest would let an unsealed or
// malformed mark be treated as a sealed one, perturbing HighWaterOrder's
// rollback ranking (a mark under more seals outranks one under fewer).
// Secondary: the parser never panics on any input.
//
// WHAT THIS DOES NOT VERIFY:
//   - No HMAC check: an accepted mark is parsed, not authenticated. A forged
//     but well-formed value is a correct parse; HighWaterSigMatches is what
//     rejects it, and is out of scope here.
//   - It does not assert byte-identity with internal/core.parseAuditHighWater
//     (unexported), only this package's own copy.
//   - It does not prove the v1 layout is exhaustively validated beyond the
//     field count / prefix / integer-parse checks the code already performs.
import (
	"testing"
)

func FuzzParseHighWater(f *testing.F) {
	sep := auditHighWaterSep
	f.Add("v1" + sep + "42" + sep + "100" + sep + "abc" + sep + "v3" + sep + "sig")
	f.Add("v2" + sep + "2" + sep + "digest" + sep + "7" + sep + "9" + sep + "h" + sep + "k" + sep + "s")
	f.Add("v2" + sep + "0" + sep + "digest" + sep + "7" + sep + "9" + sep + "h" + sep + "k" + sep + "s") // zero count
	f.Add("v2" + sep + "1" + sep + "" + sep + "7" + sep + "9" + sep + "h" + sep + "k" + sep + "s")       // empty digest
	f.Add("v1" + sep + "notanint" + sep + "9" + sep + "h" + sep + "k" + sep + "s")
	f.Add("")
	f.Add("garbage")
	f.Add(sep + sep + sep)

	f.Fuzz(func(t *testing.T, val string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseHighWater panicked on %q: %v", val, r)
			}
		}()

		cp, _, ok := ParseHighWater(val)
		if !ok {
			return // fail closed: a malformed value is "no mark", the safe outcome
		}
		// Accepted. A v2 (sealed) mark must be structurally well formed.
		if cp.Seals != 0 {
			if cp.Seals < 1 {
				t.Fatalf("ParseHighWater accepted a v2 mark with Seals=%d (<1) from %q", cp.Seals, val)
			}
			if cp.SealDigest == "" {
				t.Fatalf("ParseHighWater accepted a v2 mark with an empty SealDigest from %q", val)
			}
		}
	})
}
