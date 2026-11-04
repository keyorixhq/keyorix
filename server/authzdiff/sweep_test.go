package authzdiff

import (
	"os"
	"strings"
	"testing"
)

// Drivers.
//
//   - TestAuthzDiffSmoke (default go test): every op, its first target, as the
//     global admin and the no-role principal. Fails if an op's admin positive
//     control is not "allowed" on any layer it claims (a broken op definition
//     must be loud, never a silently empty oracle).
//   - TestAuthzDiffSweep (AUTHZDIFF_SWEEP=1): the deterministic exhaustive
//     sweep — every op x principal x target x grant-role arg, plus custom-role
//     permission-subset and scope variations for the custom and machine
//     principals. Records every case to $AUTHZDIFF_OUT and logs disagreements.
//     It does not fail on a disagreement (Phase 2 lists findings, it does not
//     gate on them); AUTHZDIFF_STRICT=1 makes any O1/O2 class fatal.
//   - FuzzAuthzDiff: the same case space, chosen by the fuzzer.

var allPerms = uint16(1<<len(customPermUniverse) - 1)

// variations for the principals whose grants depend on the custom role.
func variations(pk principalKind) []struct {
	mask   uint16
	global bool
} {
	type v = struct {
		mask   uint16
		global bool
	}
	if pk != pkCustom && pk != pkMachine {
		return []v{{allPerms, false}}
	}
	// all / none / each single permission; the custom user also at global scope.
	out := []v{{allPerms, false}, {0, false}}
	for i := range customPermUniverse {
		out = append(out, v{1 << i, false})
	}
	if pk == pkCustom {
		out = append(out, v{allPerms, true}, v{0, true})
		for i := range customPermUniverse {
			out = append(out, v{1 << i, true})
		}
	}
	return out
}

func argsFor(spec opSpec) []byte {
	if strings.Contains(spec.name, "role.assign") || spec.name == "invitation.create" || spec.name == "accessrequest.approve" {
		return []byte{0, 1, 2, 3}
	}
	return []byte{0}
}

func TestAuthzDiffSmoke(t *testing.T) {
	specs := withDerived(t, ops())
	for _, spec := range specs {
		t.Run(spec.name, func(t *testing.T) {
			tg := spec.targets[0]
			for _, l := range []layer{layerCore, layerREST, layerGRPC} {
				c := control(t, spec, l, tg, 0)
				if c.NA == "" && c.Outcome != Allowed {
					t.Errorf("admin positive control on %s: %s (%s) — op definition broken for this layer", l, c.Outcome, c.Detail)
				}
			}
			r := runCase(t, spec, caseKey{Op: spec.name, Principal: pkNone, Target: tg.String(), Mask: allPerms}, tg)
			sink.write(r)
			t.Log(r.line())
		})
	}
}

func TestAuthzDiffSweep(t *testing.T) {
	if os.Getenv("AUTHZDIFF_SWEEP") == "" {
		t.Skip("set AUTHZDIFF_SWEEP=1 for the exhaustive sweep (long)")
	}
	only := os.Getenv("AUTHZDIFF_OPS") // optional comma list of op names
	strict := os.Getenv("AUTHZDIFF_STRICT") != ""
	specs := withDerived(t, ops())
	var n, dis int
	for _, spec := range specs {
		if only != "" && !strings.Contains(","+only+",", ","+spec.name+",") {
			continue
		}
		for _, tg := range spec.targets {
			for _, arg := range argsFor(spec) {
				for _, pk := range allPrincipalKinds {
					for _, v := range variations(pk) {
						k := caseKey{Op: spec.name, Principal: pk, Target: tg.String(), Arg: arg, Mask: v.mask, CustomGlobal: v.global}
						r := runCase(t, spec, k, tg)
						sink.write(r)
						n++
						if r.disagreement() {
							dis++
							t.Log("DISAGREEMENT " + r.line())
							if strict {
								t.Fail()
							}
						}
					}
				}
			}
		}
	}
	t.Logf("sweep: %d cases, %d with an O1/O2 class", n, dis)
}

func FuzzAuthzDiff(f *testing.F) {
	f.Add(byte(0), byte(4), byte(0), byte(0), uint16(0xff), false)
	f.Add(byte(12), byte(4), byte(1), byte(1), uint16(0x80), true)
	f.Fuzz(func(t *testing.T, opSel, pSel, tSel, arg byte, mask uint16, global bool) {
		specs := withDerived(t, ops())
		spec := specs[int(opSel)%len(specs)]
		tg := spec.targets[int(tSel)%len(spec.targets)]
		pk := allPrincipalKinds[int(pSel)%len(allPrincipalKinds)]
		k := caseKey{Op: spec.name, Principal: pk, Target: tg.String(), Arg: arg % 4, Mask: mask & allPerms, CustomGlobal: global && pk == pkCustom}
		r := runCase(t, spec, k, tg)
		sink.write(r)
		if r.disagreement() {
			t.Log("DISAGREEMENT " + r.line())
			if os.Getenv("AUTHZDIFF_STRICT") != "" {
				t.Fail()
			}
		}
	})
}
