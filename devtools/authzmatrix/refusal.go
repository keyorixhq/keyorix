package main

import (
	"go/constant"

	"golang.org/x/tools/go/ssa"
)

// Refusal classification of a core entry point, derived from the refusal
// MECHANISM rather than from a list of guard names:
//
//   - typed: core can return an error matching core.ErrPermissionDenied. The
//     complete constructor set is defined in internal/core/errors_permission.go:
//     newPermissionSentinel (and every package-level var initialised from it),
//     markPermissionDenied, permissionDeniedf, and the ErrPermissionDenied var
//     itself; plus i18n.T("ErrorPermissionDenied"), which that file's doc says
//     TestEveryErrorPermissionDeniedRefusalIsTyped keeps wrapped.
//   - untyped: core can return a refusal errors_permission.go's own doc lists
//     as NOT matching ErrPermissionDenied (ErrBreakGlassListForbidden,
//     ErrAccessOutsideSchedule, ErrConnectRefNotPermitted, the SCIM
//     i18n "ErrorNotAuthorized"), plus errAdminAuthorityRequired (a plain
//     errors.New refusal from requireAdminAuthorityAt, found by reading it).
//   - neither: core performs no authorization refusal on this path; the
//     transport gate (router middleware / gRPC service code) is the only one.
//
// Not seen: a refusal built with fmt.Errorf/errors.New text and no sentinel
// (other than the listed ones). Those surface in Phase 2 as core=other while
// REST=denied and are classified as mapping gaps there.

var typedRefusalFuncs = map[string]bool{"newPermissionSentinel": true, "markPermissionDenied": true, "permissionDeniedf": true}

var untypedRefusalGlobals = map[string]bool{
	"ErrBreakGlassListForbidden": true, "ErrAccessOutsideSchedule": true,
	"ErrConnectRefNotPermitted": true, "errAdminAuthorityRequired": true,
}

type refusal struct{ typed, untyped bool }

func (a *analyzer) sentinelGlobals() map[*ssa.Global]bool {
	if a.sentinels != nil {
		return a.sentinels
	}
	a.sentinels = map[*ssa.Global]bool{}
	for _, p := range a.prog.AllPackages() {
		if p.Pkg.Path() != corePkg {
			continue
		}
		if g, ok := p.Members["ErrPermissionDenied"].(*ssa.Global); ok {
			a.sentinels[g] = true
		}
		init := p.Func("init")
		if init == nil {
			continue
		}
		for _, b := range init.Blocks {
			for _, ins := range b.Instrs {
				st, ok := ins.(*ssa.Store)
				if !ok {
					continue
				}
				g, ok := st.Addr.(*ssa.Global)
				if !ok {
					continue
				}
				if call, ok := st.Val.(*ssa.Call); ok {
					if cal := call.Common().StaticCallee(); cal != nil && cal.Name() == "newPermissionSentinel" {
						a.sentinels[g] = true
					}
				}
			}
		}
	}
	return a.sentinels
}

func (a *analyzer) refusalOf(fn *ssa.Function) refusal {
	if r, ok := a.refusalMemo[fn]; ok {
		return r
	}
	sent := a.sentinelGlobals()
	var r refusal
	var walk func(*ssa.Function)
	seen := map[*ssa.Function]bool{}
	walk = func(f *ssa.Function) {
		if f == nil || seen[f] || !a.isCore(f) {
			return
		}
		seen[f] = true
		for _, b := range f.Blocks {
			for _, ins := range b.Instrs {
				if ci, ok := ins.(ssa.CallInstruction); ok {
					c := ci.Common()
					if cal := c.StaticCallee(); cal != nil {
						if a.isCore(cal) && typedRefusalFuncs[cal.Name()] {
							r.typed = true
						}
						if cal.Pkg != nil && cal.Pkg.Pkg.Path() == modPath+"/internal/i18n" && cal.Name() == "T" && len(c.Args) > 0 {
							if k, ok := c.Args[0].(*ssa.Const); ok && k.Value != nil && k.Value.Kind() == constant.String {
								switch constant.StringVal(k.Value) {
								case "ErrorPermissionDenied":
									r.typed = true
								case "ErrorNotAuthorized":
									r.untyped = true
								}
							}
						}
						walk(cal)
					}
				}
				var buf []*ssa.Value
				for _, v := range ins.Operands(buf) {
					if v == nil || *v == nil {
						continue
					}
					switch x := (*v).(type) {
					case *ssa.Global:
						if sent[x] {
							r.typed = true
						}
						if x.Pkg != nil && x.Pkg.Pkg.Path() == corePkg && untypedRefusalGlobals[x.Name()] {
							r.untyped = true
						}
					case *ssa.Function:
						walk(x)
					}
				}
			}
		}
		for _, anon := range f.AnonFuncs {
			walk(anon)
		}
	}
	walk(fn)
	a.refusalMemo[fn] = r
	return r
}
