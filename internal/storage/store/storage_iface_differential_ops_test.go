package store_test

// The op table of FuzzStorageIfaceDifferential. Each op is one small scenario on one
// method family, driven by opParams. It renders only what the storage contract
// promises (handles instead of ids, sorted sets where order is not a contract) and adds
// the per-backend relations through e.meta.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ifaceFutureBase and ifacePastBase anchor generated instants around two fixed dates,
// so that methods which compare against the real clock see a fixed side of it.
var (
	ifaceFutureBase = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	ifacePastBase   = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
)

// at returns the program's instant for one of two anchors (b's low bit).
func (p opParams) at() time.Time {
	base := ifaceFutureBase
	if p.b&1 == 0 {
		base = ifacePastBase
	}
	return base.Add(p.instant.offset).In(ifaceZones[p.instant.zone%len(ifaceZones)])
}

var ifaceRoleScopeWord = []string{"global", "project", "any"}

func (s *ifaceSide) fixtureFatal(e *ifaceExec, kind string, err error) {
	e.t.Fatalf("HARNESS FIXTURE FAULT (not a divergence): create %s on %s: %v", kind, s.label, err)
}

func (s *ifaceSide) ensure(e *ifaceExec, kind string, i int, create func() (uint, error)) uint {
	if id, ok := s.h.get(kind, i); ok {
		return id
	}
	// Handles are sequential: reference i means 0..i are created in order.
	for len(s.h.m[kind]) <= i {
		id, err := create()
		if err != nil {
			s.fixtureFatal(e, kind, err)
		}
		s.h.add(kind, id)
	}
	id, _ := s.h.get(kind, i)
	return id
}

func (s *ifaceSide) project(e *ifaceExec, i int) uint {
	return s.ensure(e, "project", i, func() (uint, error) {
		n := len(s.h.m["project"])
		p, err := s.ls.CreateProject(e.ctx, &models.Project{Name: fmt.Sprintf("p%d", n)})
		if err != nil {
			return 0, err
		}
		return p.ID, nil
	})
}

func (s *ifaceSide) envIn(e *ifaceExec, i int) uint {
	pid := s.project(e, 0)
	return s.ensure(e, "env", i, func() (uint, error) {
		n := len(s.h.m["env"])
		en, err := s.ls.CreateEnvironment(e.ctx, &models.Environment{ProjectID: pid, Name: fmt.Sprintf("e%d", n)})
		if err != nil {
			return 0, err
		}
		return en.ID, nil
	})
}

func (s *ifaceSide) user(e *ifaceExec, i int) uint {
	return s.ensure(e, "user", i, func() (uint, error) {
		n := len(s.h.m["user"])
		un := fmt.Sprintf("u%d", n)
		fn, err := identity.NewFoldedName(un)
		if err != nil {
			return 0, err
		}
		em := un + "@x.io"
		ef, err := identity.NewFoldedName(em)
		if err != nil {
			return 0, err
		}
		u, err := s.ls.CreateUser(e.ctx, &models.User{Username: un, UsernameFolded: fn.Folded(), Email: em, EmailFolded: ef.Folded(), IsActive: true})
		if err != nil {
			return 0, err
		}
		return u.ID, nil
	})
}

func (s *ifaceSide) group(e *ifaceExec, i int) uint {
	return s.ensure(e, "group", i, func() (uint, error) {
		n := len(s.h.m["group"])
		name := fmt.Sprintf("g%d", n)
		fn, err := identity.NewFoldedName(name)
		if err != nil {
			return 0, err
		}
		g, err := s.ls.CreateGroup(e.ctx, &models.Group{Name: name, NameFolded: fn.Folded()})
		if err != nil {
			return 0, err
		}
		return g.ID, nil
	})
}

func (s *ifaceSide) role(e *ifaceExec, i int) uint {
	return s.ensure(e, "role", i, func() (uint, error) {
		n := len(s.h.m["role"])
		fn, err := identity.NewFoldedName(fmt.Sprintf("r%d", n))
		if err != nil {
			return 0, err
		}
		r, err := s.ls.CreateRole(e.ctx, fn, "")
		if err != nil {
			return 0, err
		}
		return r.ID, nil
	})
}

func (s *ifaceSide) perm(e *ifaceExec, i int) uint {
	return s.ensure(e, "perm", i, func() (uint, error) {
		n := len(s.h.m["perm"])
		name := fmt.Sprintf("w4.perm%d", n)
		pm, err := s.ls.CreatePermission(e.ctx, &models.Permission{Name: name, Resource: "w4", Action: fmt.Sprintf("a%d", n)})
		if err != nil {
			return 0, err
		}
		return pm.ID, nil
	})
}

func (s *ifaceSide) secret(e *ifaceExec, i int) uint {
	pid, eid := s.project(e, 0), s.envIn(e, 0)
	return s.ensure(e, "secret", i, func() (uint, error) {
		n := len(s.h.m["secret"])
		sn, err := s.ls.CreateSecret(e.ctx, &models.SecretNode{Name: fmt.Sprintf("s%d", n), ProjectID: pid, EnvironmentID: eid, OwnerID: diffFixedOwnerID, IsSecret: true})
		if err != nil {
			return 0, err
		}
		return sn.ID, nil
	})
}

// scope builds a storage.Scope from a byte: global, project-wide or environment-bound.
func (s *ifaceSide) scope(e *ifaceExec, b byte) storage.Scope {
	switch b % 3 {
	case 1:
		return storage.Scope{ProjectID: s.project(e, 0)}
	case 2:
		return storage.Scope{ProjectID: s.project(e, 0), EnvironmentID: s.envIn(e, 0)}
	}
	return storage.Scope{}
}

func (s *ifaceSide) scopeStr(sc storage.Scope) string {
	return s.h.name("project", sc.ProjectID) + "/" + s.h.name("env", sc.EnvironmentID)
}

func sortedRows(rows []string) string {
	rows = slices.Clone(rows)
	slices.Sort(rows)
	return strings.Join(rows, ifaceRowSep)
}

func orderedRows(rows []string) string { return strings.Join(rows, ifaceRowSep) }

func idsStr(s *ifaceSide, kind string, ids []uint) string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, s.h.name(kind, id))
	}
	return sortedRows(out)
}

// ---------------------------------------------------------------- op table -----------

var ifaceOps = []func(*ifaceExec, opParams){
	opEnv, opRole, opPerm, opUserRole, opGroupMember, opGroupRole,
	opMembership, opSession, opPAT, opSetupToken, opMFA, opSysMeta,
	opLoginAttempt, opNotification, opChannel, opTemplate, opACL,
	opShare, opConnector, opAudit, opRegressionExpiryPagination, opRegressionProjectName,
}

// Indices of ifaceOps, used by the seeds and the red-proof tests.
const (
	opIdxEnv = iota
	opIdxRole
	opIdxPerm
	opIdxUserRole
	opIdxGroupMember
	opIdxGroupRole
	opIdxMembership
	opIdxSession
	opIdxPAT
	opIdxSetupToken
	opIdxMFA
	opIdxSysMeta
	opIdxLoginAttempt
	opIdxNotification
	opIdxChannel
	opIdxTemplate
	opIdxACL
	opIdxShare
	opIdxConnector
	opIdxAudit
	opIdxRegressionExpiryPagination
	opIdxRegressionProjectName
)

func opEnv(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("Env(mode=%d,name=%q)", p.mode%4, p.name)
	e.both(label, func(s *ifaceSide) string {
		pid := s.project(e, pick(p.b, 2))
		var out string
		switch p.mode % 4 {
		case 0: // create + readback
			env, err := s.ls.CreateEnvironment(e.ctx, &models.Environment{ProjectID: pid, Name: p.name})
			out = ifaceClass(err)
			if err == nil {
				s.h.add("env", env.ID)
				g, gerr := s.ls.GetEnvironment(e.ctx, env.ID)
				e.meta(s, gerr == nil && g.Name == p.name && g.ProjectID == pid, "created environment does not read back: %v", gerr)
			}
		case 1: // delete
			id, ok := s.h.get("env", pick(p.a, 4))
			if !ok {
				return "noop"
			}
			out = ifaceClass(s.ls.DeleteEnvironment(e.ctx, id))
			live, _ := s.ls.ListEnvironmentsByProject(e.ctx, pid)
			for _, v := range live {
				e.meta(s, v.ID != id, "deleted environment still in ListEnvironmentsByProject")
			}
		case 2: // restore
			id, ok := s.h.get("env", pick(p.a, 4))
			if !ok {
				return "noop"
			}
			out = ifaceClass(s.ls.RestoreEnvironment(e.ctx, pid, id))
		}
		live, lerr := s.ls.ListEnvironmentsByProject(e.ctx, pid)
		all, aerr := s.ls.ListEnvironmentsByProjectIncludingDeleted(e.ctx, pid)
		var lives, alls []string
		for _, v := range live {
			lives = append(lives, v.Name)
		}
		for _, v := range all {
			alls = append(alls, fmt.Sprintf("%s/del=%v", v.Name, v.DeletedAt.Valid))
		}
		return fmt.Sprintf("%s live=%s/%s all=%s/%s", out, ifaceClass(lerr), sortedRows(lives), ifaceClass(aerr), sortedRows(alls))
	})
}

func fpRole(r *models.Role) string {
	if r == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%q/%q/%v/%s", r.Name, r.Description, r.BypassesPermissionChecks, r.AssignableScope)
}

func opRole(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("Role(mode=%d,name=%q,name2=%q)", p.mode%5, p.name, p.name2)
	e.both(label, func(s *ifaceSide) string {
		switch p.mode % 5 {
		case 0: // create + by-name lookup (exact display name)
			fn, ferr := identity.NewFoldedName(p.name)
			if ferr != nil {
				return "unfoldable"
			}
			r, err := s.ls.CreateRole(e.ctx, fn, p.name2)
			if err != nil {
				return "create:" + ifaceClass(err)
			}
			s.h.add("role", r.ID)
			g, gerr := s.ls.GetRoleByName(e.ctx, p.name)
			e.meta(s, gerr == nil && g.ID == r.ID, "created role does not read back by exact name: %v", gerr)
			return "created " + fpRole(g)
		case 1: // update description
			id, ok := s.h.get("role", pick(p.a, 4))
			if !ok {
				return "noop"
			}
			r, err := s.ls.GetRole(e.ctx, id)
			if err != nil {
				return "get:" + ifaceClass(err)
			}
			r.Description = p.name
			_, uerr := s.ls.UpdateRole(e.ctx, r)
			g, gerr := s.ls.GetRole(e.ctx, id)
			return fmt.Sprintf("%s %s %s", ifaceClass(uerr), ifaceClass(gerr), fpRole(g))
		case 2: // delete: cascade counts are part of the contract
			id, ok := s.h.get("role", pick(p.a, 4))
			if !ok {
				return "noop"
			}
			c, err := s.ls.DeleteRole(e.ctx, id)
			_, gerr := s.ls.GetRole(e.ctx, id)
			return fmt.Sprintf("%s users=%d groups=%d machines=%d after=%s", ifaceClass(err), c.UserAssignments, c.GroupAssignments, c.MachineAssignments, ifaceClass(gerr))
		case 3: // by-name lookup with a case or normalisation variant
			g, err := s.ls.GetRoleByName(e.ctx, p.name2)
			return fmt.Sprintf("%s %s", ifaceClass(err), fpRole(g))
		default:
			rs, err := s.ls.ListRoles(e.ctx)
			rows := make([]string, 0, len(rs))
			for _, r := range rs {
				rows = append(rows, fpRole(r))
			}
			return ifaceClass(err) + " " + sortedRows(rows)
		}
	})
}

func opPerm(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("Perm(mode=%d,name=%q)", p.mode%5, p.name)
	e.both(label, func(s *ifaceSide) string {
		switch p.mode % 5 {
		case 0: // create
			pm, err := s.ls.CreatePermission(e.ctx, &models.Permission{Name: p.name, Resource: "r", Action: p.name2})
			if err != nil {
				return "create:" + ifaceClass(err)
			}
			s.h.add("perm", pm.ID)
			g, gerr := s.ls.GetPermission(e.ctx, pm.ID)
			e.meta(s, gerr == nil && g.Name == p.name, "created permission does not read back: %v", gerr)
			return "created"
		case 1: // assign to a role, twice to reach the duplicate path
			rid, pid := s.role(e, pick(p.a, 3)), s.perm(e, pick(p.b, 3))
			e1 := s.ls.AssignPermissionToRole(e.ctx, rid, pid)
			e2 := s.ls.AssignPermissionToRole(e.ctx, rid, pid)
			return ifaceClass(e1) + "," + ifaceClass(e2)
		case 2:
			rid, pid := s.role(e, pick(p.a, 3)), s.perm(e, pick(p.b, 3))
			return ifaceClass(s.ls.RemovePermissionFromRole(e.ctx, rid, pid))
		case 3: // role set semantics
			rid := s.role(e, pick(p.a, 3))
			ps, err := s.ls.GetRolePermissions(e.ctx, rid)
			rows := make([]string, 0, len(ps))
			for _, pm := range ps {
				rows = append(rows, pm.Name)
			}
			has, herr := s.ls.RoleSetHasPermission(e.ctx, []uint{rid}, p.name)
			return fmt.Sprintf("%s %s has=%v/%s", ifaceClass(err), sortedRows(rows), has, ifaceClass(herr))
		default:
			ps, err := s.ls.ListPermissions(e.ctx)
			rows := make([]string, 0, len(ps))
			for _, pm := range ps {
				rows = append(rows, pm.Name+"|"+pm.Resource+"|"+pm.Action)
			}
			return ifaceClass(err) + " " + sortedRows(rows)
		}
	})
}

func opUserRole(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("UserRole(mode=%d)", p.mode%8)
	e.both(label, func(s *ifaceSide) string {
		uid, rid := s.user(e, pick(p.a, 3)), s.role(e, pick(p.b, 3))
		sc := s.scope(e, p.a>>2)
		switch p.mode % 8 {
		case 0:
			return "assign:" + ifaceClass(s.ls.AssignRole(e.ctx, uid, rid, sc))
		case 1:
			at := p.at()
			return "assignexp:" + ifaceClass(s.ls.AssignRoleWithExpiry(e.ctx, uid, rid, sc, at))
		case 2:
			return "remove:" + ifaceClass(s.ls.RemoveRole(e.ctx, uid, rid, sc))
		case 3:
			atIDs, e1 := s.ls.GetUserRoleIDsAt(e.ctx, uid, sc)
			exact, e2 := s.ls.GetUserRoleIDsExact(e.ctx, uid, sc)
			return fmt.Sprintf("at=%s/%s exact=%s/%s", ifaceClass(e1), idsStr(s, "role", atIDs), ifaceClass(e2), idsStr(s, "role", exact))
		case 4:
			gs, err := s.ls.ListUserRoleGrants(e.ctx, uid)
			rows := make([]string, 0, len(gs))
			for _, g := range gs {
				rows = append(rows, fmt.Sprintf("%s|%s|%v|%v", s.h.name("role", g.RoleID), s.scopeStr(storage.Scope{ProjectID: g.ProjectID, EnvironmentID: g.EnvironmentID}), g.ViaGroup, g.Bypass))
			}
			return ifaceClass(err) + " " + sortedRows(rows)
		case 5:
			rs, err := s.ls.ListAllUserRoleGrants(e.ctx)
			rows := make([]string, 0, len(rs))
			for _, r := range rs {
				rows = append(rows, fmt.Sprintf("%s|%s|%s|%s", s.h.name("user", r.UserID), s.h.name("role", r.RoleID), s.scopeStr(storage.Scope{ProjectID: r.ProjectID, EnvironmentID: r.EnvironmentID}), fpTime(r.ExpiresAt)))
			}
			return ifaceClass(err) + " " + sortedRows(rows)
		case 6:
			rs, err := s.ls.ListExpiringUserRoles(e.ctx, p.at())
			rows := make([]string, 0, len(rs))
			for _, r := range rs {
				rows = append(rows, fmt.Sprintf("%s|%s|%s", s.h.name("user", r.UserID), s.h.name("role", r.RoleID), fpTime(r.ExpiresAt)))
			}
			return ifaceClass(err) + " " + sortedRows(rows)
		default:
			rs, err := s.ls.DeleteExpiredRoleGrants(e.ctx, p.at())
			rows := make([]string, 0, len(rs))
			for _, r := range rs {
				rows = append(rows, fmt.Sprintf("%s|%s|%s", r.PrincipalType, s.h.name(map[string]string{"user": "user", "group": "group"}[r.PrincipalType], r.PrincipalID), s.h.name("role", r.RoleID)))
			}
			return ifaceClass(err) + " " + sortedRows(rows)
		}
	})
}

func opGroupMember(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("GroupMember(mode=%d)", p.mode%7)
	e.both(label, func(s *ifaceSide) string {
		uid, gid := s.user(e, pick(p.a, 3)), s.group(e, pick(p.b, 2))
		sc := s.scope(e, p.a>>2)
		switch p.mode % 7 {
		case 0:
			return "add:" + ifaceClass(s.ls.AddUserToGroup(e.ctx, uid, gid, sc.ProjectID))
		case 1:
			return "remove:" + ifaceClass(s.ls.RemoveUserFromGroup(e.ctx, uid, gid, sc.ProjectID))
		case 2:
			us, err := s.ls.ListGroupMembers(e.ctx, gid)
			return ifaceClass(err) + " " + usersStr(us)
		case 3:
			us, err := s.ls.ListGroupMembersAt(e.ctx, gid, sc)
			return ifaceClass(err) + " " + usersStr(us)
		case 4:
			gs, err := s.ls.GetUserGroups(e.ctx, uid)
			return ifaceClass(err) + " " + groupsStr(gs)
		case 5:
			ms, err := s.ls.ListAllUserGroupMemberships(e.ctx)
			rows := make([]string, 0, len(ms))
			for _, m := range ms {
				rows = append(rows, fmt.Sprintf("%s|%s", s.h.name("user", m.UserID), s.h.name("group", m.GroupID)))
			}
			return ifaceClass(err) + " " + sortedRows(rows)
		default: // delete then restore: membership rows survive the soft delete
			derr := s.ls.DeleteGroup(e.ctx, gid)
			rerr := s.ls.RestoreGroup(e.ctx, gid)
			us, lerr := s.ls.ListGroupMembers(e.ctx, gid)
			return fmt.Sprintf("del=%s rest=%s %s %s", ifaceClass(derr), ifaceClass(rerr), ifaceClass(lerr), usersStr(us))
		}
	})
}

func usersStr(us []*models.User) string {
	rows := make([]string, 0, len(us))
	for _, u := range us {
		rows = append(rows, u.Username)
	}
	return sortedRows(rows)
}

func groupsStr(gs []*models.Group) string {
	rows := make([]string, 0, len(gs))
	for _, g := range gs {
		rows = append(rows, g.Name)
	}
	return sortedRows(rows)
}

func opGroupRole(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("GroupRole(mode=%d)", p.mode%6)
	e.both(label, func(s *ifaceSide) string {
		gid, rid := s.group(e, pick(p.a, 2)), s.role(e, pick(p.b, 3))
		sc := s.scope(e, p.a>>2)
		switch p.mode % 6 {
		case 0:
			return "assign:" + ifaceClass(s.ls.AssignRoleToGroup(e.ctx, gid, rid, sc))
		case 1:
			return "assignexp:" + ifaceClass(s.ls.AssignRoleToGroupWithExpiry(e.ctx, gid, rid, sc, p.at()))
		case 2:
			return "remove:" + ifaceClass(s.ls.RemoveRoleFromGroup(e.ctx, gid, rid, sc))
		case 3:
			rs, err := s.ls.GetGroupRoles(e.ctx, gid)
			gr, gerr := s.ls.GetGroupRoleGrants(e.ctx, gid)
			rows := make([]string, 0, len(gr))
			for _, x := range gr {
				rows = append(rows, fmt.Sprintf("%s|%s|%s", x.Name, s.scopeStr(storage.Scope{ProjectID: x.ProjectID, EnvironmentID: x.EnvironmentID}), fpTime(x.ExpiresAt)))
			}
			names := make([]string, 0, len(rs))
			for _, r := range rs {
				names = append(names, r.Name)
			}
			return fmt.Sprintf("%s %s %s %s", ifaceClass(err), sortedRows(names), ifaceClass(gerr), sortedRows(rows))
		case 4:
			ra, err := s.ls.ListGroupRoleAssignments(e.ctx, gid)
			rows := make([]string, 0, len(ra))
			for _, a := range ra {
				rows = append(rows, fmt.Sprintf("%s|%s|%s", a.PrincipalType, s.h.name("role", a.RoleID), s.scopeStr(storage.Scope{ProjectID: a.ProjectID, EnvironmentID: a.EnvironmentID})))
			}
			return ifaceClass(err) + " " + sortedRows(rows)
		default:
			uid := s.user(e, pick(p.b, 3))
			ids, err := s.ls.GetUserGroupRoleIDsAt(e.ctx, uid, sc)
			gs, gerr := s.ls.GetUserGroupsAt(e.ctx, uid, sc)
			return fmt.Sprintf("%s %s %s %s", ifaceClass(err), idsStr(s, "role", ids), ifaceClass(gerr), groupsStr(gs))
		}
	})
}

var ifaceMemberStates = []string{"invited", "identity_verified", "provisioned", "active", "revoked"}

func opMembership(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("Membership(mode=%d,state=%s)", p.mode%6, ifaceMemberStates[pick(p.b, 5)])
	e.both(label, func(s *ifaceSide) string {
		pid, uid := s.project(e, pick(p.a, 2)), s.user(e, pick(p.b, 3))
		state := ifaceMemberStates[pick(p.b, 5)]
		switch p.mode % 6 {
		case 0: // create: partial unique index on (project, user) for non-revoked rows
			m, err := s.ls.CreateProjectMembership(e.ctx, &models.ProjectMembership{ProjectID: pid, UserID: uid, Role: p.name, State: state,
				InvitedAt: ifacePastBase.Add(time.Duration(e.step) * time.Second)})
			if err != nil {
				return "create:" + ifaceClass(err)
			}
			s.h.add("member", m.ID)
			g, gerr := s.ls.GetProjectMembership(e.ctx, m.ID)
			e.meta(s, gerr == nil && g.State == state && g.Role == p.name, "created membership does not read back: %v", gerr)
			return "created"
		case 1: // conditional transition on the current state
			id, ok := s.h.get("member", pick(p.a, 3))
			if !ok {
				return "noop"
			}
			cur, err := s.ls.GetProjectMembership(e.ctx, id)
			if err != nil {
				return "get:" + ifaceClass(err)
			}
			from := cur.State
			cur.State = state
			won, terr := s.ls.TransitionProjectMembershipState(e.ctx, cur, from)
			again, aerr := s.ls.TransitionProjectMembershipState(e.ctx, cur, from)
			return fmt.Sprintf("%s won=%v %s %v", ifaceClass(terr), won, ifaceClass(aerr), again)
		case 2: // ordered by invited_at DESC; the op's own step keeps the keys distinct
			ms, err := s.ls.ListProjectMemberships(e.ctx, pid)
			return ifaceClass(err) + " " + orderedRows(membershipRows(s, ms))
		case 3:
			g, err := s.ls.GetActiveProjectMembership(e.ctx, pid, uid)
			if err != nil {
				return "get:" + ifaceClass(err)
			}
			return strings.Join(membershipRows(s, []*models.ProjectMembership{g}), "")
		case 4:
			ms, err := s.ls.ListStaleInvitedMemberships(e.ctx, p.at())
			return ifaceClass(err) + " " + orderedRows(membershipRows(s, ms))
		default:
			cs, err := s.ls.CountProjectMembershipsByUsers(e.ctx, []uint{uid, s.user(e, pick(p.a, 3))})
			mem, merr := s.ls.IsProjectMember(e.ctx, uid, pid)
			am, aerr := s.ls.ProjectMembershipsAmong(e.ctx, uid, []uint{pid, s.project(e, 0)})
			pms, perr := s.ls.ListUserProjectMemberships(e.ctx, uid)
			return fmt.Sprintf("%s counts=%+v %s %v %s %v %s %s", ifaceClass(err), cs[uid], ifaceClass(merr), mem, ifaceClass(aerr), am[pid], ifaceClass(perr), orderedRows(membershipRows(s, pms)))
		}
	})
}

func membershipRows(s *ifaceSide, ms []*models.ProjectMembership) []string {
	rows := make([]string, 0, len(ms))
	for _, m := range ms {
		rows = append(rows, fmt.Sprintf("%s|%s|%q|%s", s.h.name("project", m.ProjectID), s.h.name("user", m.UserID), m.Role, m.State))
	}
	return rows
}

func opSession(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("Session(mode=%d)", p.mode%8)
	e.both(label, func(s *ifaceSide) string {
		uid := s.user(e, pick(p.a, 2))
		tok := "tok-" + p.name
		switch p.mode % 8 {
		case 0: // create; a duplicate token hash collides
			exp := p.at()
			sn, err := s.ls.CreateSession(e.ctx, &models.Session{UserID: uid, SessionToken: tok, ExpiresAt: &exp, FamilyID: "fam-" + p.name2})
			if err != nil {
				return "create:" + ifaceClass(err)
			}
			s.h.add("session", sn.ID)
			return "created"
		case 1:
			sn, err := s.ls.GetSession(e.ctx, tok)
			a, aerr := s.ls.GetSessionAny(e.ctx, tok)
			return fmt.Sprintf("%s %s %s %s", ifaceClass(err), fpSession(s, sn), ifaceClass(aerr), fpSession(s, a))
		case 2:
			rows, err := s.ls.ListSessionsByUser(e.ctx, uid)
			out := make([]string, 0, len(rows))
			for _, r := range rows {
				out = append(out, fpSession(s, r))
			}
			return ifaceClass(err) + " " + sortedRows(out)
		case 3:
			id, ok := s.h.get("session", pick(p.b, 4))
			if !ok {
				return "noop"
			}
			terr := s.ls.TouchSession(e.ctx, id, p.at(), time.Duration(p.a)*time.Second)
			g, gerr := s.ls.GetSessionByID(e.ctx, id)
			last := "nil"
			if g != nil {
				last = fpTime(g.LastSeenAt)
			}
			return fmt.Sprintf("%s %s last=%s", ifaceClass(terr), ifaceClass(gerr), last)
		case 4:
			id, ok := s.h.get("session", pick(p.b, 4))
			if !ok {
				return "noop"
			}
			exp := p.at()
			created, won, err := s.ls.RotateSession(e.ctx, id, &models.Session{UserID: uid, SessionToken: "rot-" + p.name, ExpiresAt: &exp}, p.at())
			if created != nil {
				s.h.add("session", created.ID)
			}
			return fmt.Sprintf("%s won=%v", ifaceClass(err), won)
		case 5:
			return "enforce:" + ifaceClass(s.ls.EnforceSessionLimit(e.ctx, uid, pick(p.b, 3)))
		case 6:
			return "cleanup:" + ifaceClass(s.ls.CleanupExpiredSessions(e.ctx))
		default:
			hs, err := s.ls.ListSessionTokenHashesByFamily(e.ctx, "fam-"+p.name2)
			derr := s.ls.DeleteSessionsByFamily(e.ctx, "fam-"+p.name2)
			return fmt.Sprintf("%s %s del=%s", ifaceClass(err), sortedRows(hs), ifaceClass(derr))
		}
	})
}

func fpSession(s *ifaceSide, sn *models.Session) string {
	if sn == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s|%q|%s|%v", s.h.name("user", sn.UserID), sn.FamilyID, fpTime(sn.ExpiresAt), sn.RotatedAt != nil)
}

func opPAT(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("PAT(mode=%d,name=%q)", p.mode%6, p.name)
	e.both(label, func(s *ifaceSide) string {
		uid := s.user(e, pick(p.a, 2))
		hash := "pat-" + p.name
		switch p.mode % 6 {
		case 0:
			t := &models.PersonalAccessToken{UserID: uid, Name: p.name2, TokenHash: hash}
			if p.b&2 != 0 {
				exp := p.at()
				t.ExpiresAt = &exp
			}
			c, err := s.ls.CreatePersonalAccessToken(e.ctx, t)
			if err != nil {
				return "create:" + ifaceClass(err)
			}
			s.h.add("pat", c.ID)
			g, gerr := s.ls.GetPersonalAccessTokenByHash(e.ctx, hash)
			e.meta(s, gerr == nil && g.ID == c.ID, "created PAT does not read back by hash: %v", gerr)
			return "created"
		case 1:
			g, err := s.ls.GetPersonalAccessTokenByHash(e.ctx, hash)
			return fmt.Sprintf("%s %s", ifaceClass(err), fpPAT(s, g))
		case 2:
			ts, err := s.ls.ListPersonalAccessTokensByUser(e.ctx, uid)
			out := make([]string, 0, len(ts))
			for _, t := range ts {
				out = append(out, fpPAT(s, t))
			}
			return ifaceClass(err) + " " + sortedRows(out)
		case 3:
			id, ok := s.h.get("pat", pick(p.b, 4))
			if !ok {
				return "noop"
			}
			rerr := s.ls.RevokePersonalAccessToken(e.ctx, id)
			g, gerr := s.ls.GetPersonalAccessTokenByID(e.ctx, id)
			return fmt.Sprintf("%s %s %s", ifaceClass(rerr), ifaceClass(gerr), fpPAT(s, g))
		case 4:
			before := p.at()
			ex, err := s.ls.ListExpiringPATs(e.ctx, before)
			out := make([]string, 0, len(ex))
			for i := range ex {
				out = append(out, fpPAT(s, &ex[i]))
			}
			exp2, err2 := s.ls.ListExpiredPATsByUser(e.ctx, uid, before)
			out2 := make([]string, 0, len(exp2))
			for _, t := range exp2 {
				out2 = append(out2, fpPAT(s, t))
			}
			return fmt.Sprintf("%s %s / %s %s", ifaceClass(err), sortedRows(out), ifaceClass(err2), sortedRows(out2))
		default:
			hs, err := s.ls.BulkRevokeExpiredPATsByUser(e.ctx, uid, p.at())
			return ifaceClass(err) + " " + sortedRows(hs)
		}
	})
}

func fpPAT(s *ifaceSide, t *models.PersonalAccessToken) string {
	if t == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s|%q|rev=%v|%s", s.h.name("user", t.UserID), t.Name, t.Revoked, fpTime(t.ExpiresAt))
}

func opSetupToken(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("SetupToken(mode=%d,purpose=%d,email=%q)", p.mode%5, pick(p.a, 3), p.name2)
	e.both(label, func(s *ifaceSide) string {
		purpose := []string{"invitation_accept", "account_setup", "password_reset_link"}[pick(p.a, 3)]
		hash := "st-" + p.name
		switch p.mode % 5 {
		case 0:
			t, err := s.ls.CreateSetupToken(e.ctx, &models.SetupToken{TokenHash: hash, Purpose: purpose, SubjectEmail: p.name2, ExpiresAt: p.at()})
			if err != nil {
				return "create:" + ifaceClass(err)
			}
			s.h.add("setup", t.ID)
			return "created"
		case 1:
			t, err := s.ls.GetSetupTokenByHash(e.ctx, hash)
			if err != nil {
				return "get:" + ifaceClass(err)
			}
			return fmt.Sprintf("%s|%q|%s|%s", t.Purpose, t.SubjectEmail, t.State, t.ExpiresAt.UTC().Format(time.RFC3339Nano))
		case 2: // supersede is scoped by purpose and exact email
			err := s.ls.SupersedeActiveSetupTokens(e.ctx, purpose, p.name2, nil)
			t, gerr := s.ls.GetSetupTokenByHash(e.ctx, hash)
			state := "-"
			if t != nil {
				state = t.State
			}
			return fmt.Sprintf("%s %s %s", ifaceClass(err), ifaceClass(gerr), state)
		case 3:
			id, ok := s.h.get("setup", pick(p.b, 4))
			if !ok {
				return "noop"
			}
			won, err := s.ls.MarkSetupTokenConsumed(e.ctx, id, p.at())
			again, err2 := s.ls.MarkSetupTokenConsumed(e.ctx, id, p.at())
			return fmt.Sprintf("%s %v %s %v", ifaceClass(err), won, ifaceClass(err2), again)
		default:
			n, err := s.ls.CountSetupTokensSince(e.ctx, purpose, p.name2, p.at())
			return fmt.Sprintf("%s %d", ifaceClass(err), n)
		}
	})
}

func opMFA(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("MFA(mode=%d)", p.mode%10)
	e.both(label, func(s *ifaceSide) string {
		uid := s.user(e, pick(p.a, 2))
		switch p.mode % 10 {
		case 0: // conditional upsert: only an unactivated row may be replaced
			err := s.ls.UpsertMFASecret(e.ctx, &models.MFASecret{UserID: uid, SecretEnc: []byte(p.name), SecretMeta: []byte(p.name2)})
			g, gerr := s.ls.GetMFASecret(e.ctx, uid)
			return fmt.Sprintf("%s %s %s", ifaceClass(err), ifaceClass(gerr), fpMFA(g))
		case 1:
			ok, err := s.ls.ActivateMFASecret(e.ctx, uid, []byte(p.name))
			g, gerr := s.ls.GetMFASecret(e.ctx, uid)
			return fmt.Sprintf("%s %v %s %s", ifaceClass(err), ok, ifaceClass(gerr), fpMFA(g))
		case 2: // replay guard: a step at or below the last accepted one is refused
			step := int64(p.b) - 128
			ok, err := s.ls.MarkTOTPStepUsed(e.ctx, uid, step)
			g, _ := s.ls.GetMFASecret(e.ctx, uid)
			return fmt.Sprintf("%s %v %s", ifaceClass(err), ok, fpMFA(g))
		case 3:
			step := int64(p.b) - 128
			ok, err := s.ls.ReleaseTOTPStepIfUnchanged(e.ctx, uid, step)
			g, _ := s.ls.GetMFASecret(e.ctx, uid)
			return fmt.Sprintf("%s %v %s", ifaceClass(err), ok, fpMFA(g))
		case 4:
			err := s.ls.CreateMFARecoveryCodes(e.ctx, uid, []string{"rc-" + p.name, "rc-" + p.name2})
			n, cerr := s.ls.CountUnusedMFARecoveryCodes(e.ctx, uid)
			return fmt.Sprintf("%s %s %d", ifaceClass(err), ifaceClass(cerr), n)
		case 5:
			ok, err := s.ls.ConsumeMFARecoveryCode(e.ctx, uid, "rc-"+p.name, p.at())
			again, aerr := s.ls.ConsumeMFARecoveryCode(e.ctx, uid, "rc-"+p.name, p.at())
			n, cerr := s.ls.CountUnusedMFARecoveryCodes(e.ctx, uid)
			return fmt.Sprintf("%s %v %s %v %s %d", ifaceClass(err), ok, ifaceClass(aerr), again, ifaceClass(cerr), n)
		case 6: // upsert with a caller-supplied expiry, in any zone
			err := s.ls.UpsertMFAStepupToken(e.ctx, uid, p.at())
			h, herr := s.ls.HasActiveMFAStepup(e.ctx, uid)
			return fmt.Sprintf("%s %s %v", ifaceClass(err), ifaceClass(herr), h)
		case 7:
			err := s.ls.CreateMFAChallenge(e.ctx, &models.MFAChallenge{UserID: uid, TokenHash: "ch-" + p.name, ExpiresAt: p.at()})
			c, cerr := s.ls.ConsumeMFAChallenge(e.ctx, "ch-"+p.name, p.at())
			got := "nil"
			if c != nil {
				got = s.h.name("user", c.UserID)
			}
			return fmt.Sprintf("%s %s %s", ifaceClass(err), ifaceClass(cerr), got)
		case 8:
			g := &models.MFAStepUpGrant{UserID: uid, Purpose: models.MFAStepUpPurpose("w4." + p.name), ExpiresAt: p.at()}
			err := s.ls.CreateMFAStepUpGrant(e.ctx, g)
			active, aerr := s.ls.GetActiveMFAStepUpGrant(e.ctx, uid, g.Purpose, p.at())
			return fmt.Sprintf("%s %s %v", ifaceClass(err), ifaceClass(aerr), active != nil)
		default:
			n, err := s.ls.PruneMFAStepUpGrants(e.ctx, p.at())
			return fmt.Sprintf("%s %d", ifaceClass(err), n)
		}
	})
}

func fpMFA(g *models.MFASecret) string {
	if g == nil {
		return "<nil>"
	}
	step := "nil"
	if g.LastUsedStep != nil {
		step = fmt.Sprint(*g.LastUsedStep)
	}
	return fmt.Sprintf("activated=%v step=%s enc=%d/%x", g.Activated, step, len(g.SecretEnc), g.SecretEnc)
}

func opSysMeta(e *ifaceExec, p opParams) {
	key, value := "w4k-"+p.name, p.name2
	label := fmt.Sprintf("SysMeta(mode=%d,key=%q,value=%q)", p.mode%4, key, value)
	e.both(label, func(s *ifaceSide) string {
		switch p.mode % 4 {
		case 0: // last write wins
			err := s.ls.SetSystemMetadata(e.ctx, key, value)
			g, found, gerr := s.ls.GetSystemMetadata(e.ctx, key)
			e.meta(s, err != nil || (gerr == nil && found && g == value), "set then get did not return the value: %v", gerr)
			return ifaceClass(err)
		case 1:
			g, found, err := s.ls.GetSystemMetadata(e.ctx, key)
			return fmt.Sprintf("%s %v %q", ifaceClass(err), found, g)
		case 2: // compare-and-swap with the current value
			cur, found, gerr := s.ls.GetSystemMetadata(e.ctx, key)
			if gerr != nil {
				return "get:" + ifaceClass(gerr)
			}
			swapped, err := s.ls.CompareAndSetSystemMetadata(e.ctx, key, cur, found, value)
			again, aerr := s.ls.CompareAndSetSystemMetadata(e.ctx, key, cur, found, value)
			return fmt.Sprintf("%s %v %s %v", ifaceClass(err), swapped, ifaceClass(aerr), again)
		default: // compare-and-swap with a stale value is refused
			swapped, err := s.ls.CompareAndSetSystemMetadata(e.ctx, key, "w4-stale", true, value)
			return fmt.Sprintf("%s %v", ifaceClass(err), swapped)
		}
	})
}

func opLoginAttempt(e *ifaceExec, p opParams) {
	ip := p.name
	label := fmt.Sprintf("LoginAttempt(mode=%d,ip=%q)", p.mode%4, ip)
	key := p.name2
	if len(key) > 64 {
		key = key[:64]
	}
	e.both(label, func(s *ifaceSide) string {
		switch p.mode % 4 {
		case 0:
			err := s.ls.RecordLoginAttempt(e.ctx, ip, p.at())
			n, cerr := s.ls.CountRecentLoginAttempts(e.ctx, ip, p.at())
			return fmt.Sprintf("%s %s %d", ifaceClass(err), ifaceClass(cerr), n)
		case 1: // reservation: a second reserve under the same key is a no-op
			id, err := s.ls.ReserveLoginAttempt(e.ctx, ip, p.at(), key)
			id2, err2 := s.ls.ReserveLoginAttempt(e.ctx, ip, p.at(), key)
			if err == nil {
				s.h.add("attempt", id)
			}
			n, cerr := s.ls.CountRecentLoginAttempts(e.ctx, ip, ifacePastBase.Add(-time.Hour))
			return fmt.Sprintf("%s %s same=%v %s %d", ifaceClass(err), ifaceClass(err2), err == nil && err2 == nil && id == id2, ifaceClass(cerr), n)
		case 2:
			id, ok := s.h.get("attempt", pick(p.b, 4))
			if !ok {
				return "noop"
			}
			return "release:" + ifaceClass(s.ls.ReleaseLoginAttempt(e.ctx, id))
		default:
			n, err := s.ls.PruneLoginAttempts(e.ctx, p.at())
			return fmt.Sprintf("%s %d", ifaceClass(err), n)
		}
	})
}

// ifaceNotificationTypes pairs the two reminder types caught by the partial unique index
// with one ordinary type; 0 = not a reminder.
var ifaceNotificationTypes = []string{"w4.note", "secret_expiring", "rotation_reminder"}

func opNotification(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("Notification(mode=%d)", p.mode%6)
	e.both(label, func(s *ifaceSide) string {
		uid := s.user(e, pick(p.a, 2))
		pid := s.project(e, pick(p.b, 2))
		switch p.mode % 6 {
		case 0: // distinct created_at per step: the list's ORDER BY has no ties to resolve
			projID := &pid
			if p.a&4 != 0 {
				projID = nil
			}
			n, err := s.ls.CreateNotification(e.ctx, &models.Notification{UserID: uid, ProjectID: projID, Type: ifaceNotificationTypes[pick(p.b, 3)],
				Title: p.name, Message: p.name2, CreatedAt: ifacePastBase.Add(time.Duration(e.step) * time.Second)})
			if err != nil {
				return "create:" + ifaceClass(err)
			}
			s.h.add("notif", n.ID)
			return "created"
		case 1: // boundary limits: 0/negative/over-200 fall back to the default
			limit := []int{0, -1, 1, 2, 201}[pick(p.b, 5)]
			ns, err := s.ls.ListNotifications(e.ctx, uid, p.a&1 == 0, limit)
			rows := make([]string, 0, len(ns))
			for _, n := range ns {
				rows = append(rows, fpNotif(n))
			}
			return fmt.Sprintf("limit=%d %s %s", limit, ifaceClass(err), orderedRows(rows))
		case 2:
			c, err := s.ls.CountUnreadNotifications(e.ctx, uid)
			has, herr := s.ls.HasUnreadNotification(e.ctx, uid, ifaceNotificationTypes[pick(p.b, 3)], pid)
			g, gerr := s.ls.GetUnreadNotification(e.ctx, uid, ifaceNotificationTypes[pick(p.b, 3)], pid)
			got := "<nil>"
			if g != nil {
				got = fpNotif(g)
			}
			return fmt.Sprintf("%s %d %s %v %s %s", ifaceClass(err), c, ifaceClass(herr), has, ifaceClass(gerr), got)
		case 3:
			id, ok := s.h.get("notif", pick(p.b, 4))
			if !ok {
				return "noop"
			}
			err := s.ls.MarkNotificationRead(e.ctx, id, uid)
			c, cerr := s.ls.CountUnreadNotifications(e.ctx, uid)
			return fmt.Sprintf("%s %s %d", ifaceClass(err), ifaceClass(cerr), c)
		case 4: // project-scoped feed: rows with no project are never in scope
			sc := storage.NotificationScope{ProjectID: pid}
			ns, err := s.ls.ListScopedNotifications(e.ctx, uid, sc, false, 0)
			c, cerr := s.ls.CountUnreadScopedNotifications(e.ctx, uid, sc)
			mrerr := s.ls.MarkAllScopedNotificationsRead(e.ctx, uid, sc)
			rows := make([]string, 0, len(ns))
			for _, n := range ns {
				rows = append(rows, fpNotif(n))
			}
			return fmt.Sprintf("%s %s %s %d %s", ifaceClass(err), orderedRows(rows), ifaceClass(cerr), c, ifaceClass(mrerr))
		default:
			return "markall:" + ifaceClass(s.ls.MarkAllNotificationsRead(e.ctx, uid))
		}
	})
}

func fpNotif(n *models.Notification) string {
	return fmt.Sprintf("%q|%q|%q|read=%v|sev=%d", n.Type, n.Title, n.Message, n.IsRead, n.Severity)
}

func opChannel(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("Channel(mode=%d,name=%q)", p.mode%5, p.name)
	e.both(label, func(s *ifaceSide) string {
		switch p.mode % 5 {
		case 0:
			ch := &models.NotificationChannel{Name: p.name, Type: "webhook", Enabled: p.a&1 == 0, URLEnc: []byte(p.name2), Events: "e"}
			err := s.ls.CreateNotificationChannel(e.ctx, ch)
			if err != nil {
				return "create:" + ifaceClass(err)
			}
			s.h.add("chan", ch.ID)
			g, gerr := s.ls.GetNotificationChannelByName(e.ctx, p.name)
			e.meta(s, gerr == nil && g != nil && g.ID == ch.ID, "created channel does not read back by name: %v", gerr)
			return "created"
		case 1: // the by-name lookup is an exact match, on any case or normalisation variant
			g, err := s.ls.GetNotificationChannelByName(e.ctx, p.name)
			return fmt.Sprintf("%s %s", ifaceClass(err), fpChannel(g))
		case 2:
			id, ok := s.h.get("chan", pick(p.a, 4))
			if !ok {
				return "noop"
			}
			err := s.ls.UpdateNotificationChannel(e.ctx, &models.NotificationChannel{ID: id, Name: p.name, Type: "email", Email: p.name2, Enabled: p.b&1 == 0, Events: "f"})
			g, gerr := s.ls.GetNotificationChannel(e.ctx, id)
			return fmt.Sprintf("%s %s %s", ifaceClass(err), ifaceClass(gerr), fpChannel(g))
		case 3:
			id, ok := s.h.get("chan", pick(p.a, 4))
			if !ok {
				return "noop"
			}
			rerr := s.ls.UpdateNotificationRetryPolicy(e.ctx, id, int(p.a), int(p.b)*1000)
			derr := s.ls.DeleteNotificationChannel(e.ctx, id)
			_, gerr := s.ls.GetNotificationChannel(e.ctx, id)
			return fmt.Sprintf("%s %s %s", ifaceClass(rerr), ifaceClass(derr), ifaceClass(gerr))
		default: // ORDER BY id ASC: handle order, compared as ordered
			rows, err := s.ls.ListNotificationChannels(e.ctx)
			out := make([]string, 0, len(rows))
			for _, g := range rows {
				out = append(out, fpChannel(g))
			}
			return ifaceClass(err) + " " + orderedRows(out)
		}
	})
}

func fpChannel(g *models.NotificationChannel) string {
	if g == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%q|%s|%v|%q|%q|%d|%d|%d", g.Name, g.Type, g.Enabled, g.Email, g.Events, g.MaxRetries, g.RetryBackoffMs, len(g.URLEnc))
}

func opTemplate(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("Template(mode=%d,name=%q,textorder=1)", p.mode%5, p.name)
	e.both(label, func(s *ifaceSide) string {
		switch p.mode % 5 {
		case 0:
			t := &models.SecretTemplate{Name: p.name, Description: p.name2, DefaultTags: p.name2}
			err := s.ls.CreateSecretTemplate(e.ctx, t)
			if err != nil {
				return "create:" + ifaceClass(err)
			}
			s.h.add("tmpl", t.ID)
			g, gerr := s.ls.GetSecretTemplateByName(e.ctx, p.name)
			e.meta(s, gerr == nil && g.ID == t.ID, "created template does not read back by name: %v", gerr)
			return "created"
		case 1:
			g, err := s.ls.GetSecretTemplateByName(e.ctx, p.name)
			if err != nil {
				return "get:" + ifaceClass(err)
			}
			return fpTemplate(g)
		case 2:
			id, ok := s.h.get("tmpl", pick(p.a, 4))
			if !ok {
				return "noop"
			}
			matched, err := s.ls.UpdateSecretTemplateFields(e.ctx, id, storage.SecretTemplateFieldUpdate{Name: p.name, Description: p.name2, RotationHintDays: int(p.b)}, ifacePastBase)
			g, gerr := s.ls.GetSecretTemplate(e.ctx, id)
			got := "<nil>"
			if g != nil {
				got = fpTemplate(g)
			}
			return fmt.Sprintf("%s %v %s %s", ifaceClass(err), matched, ifaceClass(gerr), got)
		case 3:
			id, ok := s.h.get("tmpl", pick(p.a, 4))
			if !ok {
				return "noop"
			}
			err := s.ls.DeleteSecretTemplate(e.ctx, id)
			_, gerr := s.ls.GetSecretTemplate(e.ctx, id)
			return fmt.Sprintf("%s %s", ifaceClass(err), ifaceClass(gerr))
		default: // ORDER BY name: compared in order only on a bytewise-collated PG
			ts, err := s.ls.ListSecretTemplates(e.ctx)
			out := make([]string, 0, len(ts))
			for _, g := range ts {
				out = append(out, fpTemplate(g))
			}
			return ifaceClass(err) + " " + orderedRows(out)
		}
	})
}

func fpTemplate(g *models.SecretTemplate) string {
	return fmt.Sprintf("%q|%q|%q|%d", g.Name, g.Description, g.DefaultTags, g.RotationHintDays)
}

func opACL(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("ACL(mode=%d)", p.mode%6)
	e.both(label, func(s *ifaceSide) string {
		sid, uid := s.secret(e, pick(p.a, 2)), s.user(e, pick(p.b, 3))
		switch p.mode % 6 {
		case 0: // upsert on (secret_id, user_id)
			acl := &models.SecretACL{SecretID: sid, UserID: uid, Permissions: p.name, GrantedBy: diffFixedOwnerID}
			if err := s.ls.CreateOrUpdateSecretACL(e.ctx, acl); err != nil {
				return "upsert:" + ifaceClass(err)
			}
			g, gerr := s.ls.GetSecretACL(e.ctx, sid, uid)
			e.meta(s, gerr == nil && g.Permissions == p.name, "ACL upsert does not read back: %v", gerr)
			return "ok " + fpACL(s, g)
		case 1:
			g, err := s.ls.GetSecretACL(e.ctx, sid, uid)
			if err != nil {
				return "get:" + ifaceClass(err)
			}
			return fpACL(s, g)
		case 2:
			rows, err := s.ls.ListSecretACLs(e.ctx, sid)
			out := make([]string, 0, len(rows))
			for _, a := range rows {
				out = append(out, fpACL(s, a))
			}
			return ifaceClass(err) + " " + orderedRows(out)
		case 3:
			rows, err := s.ls.ListSecretACLsByUser(e.ctx, uid)
			out := make([]string, 0, len(rows))
			for _, a := range rows {
				out = append(out, fpACL(s, a))
			}
			return ifaceClass(err) + " " + orderedRows(out)
		case 4:
			g, gerr := s.ls.GetSecretACL(e.ctx, sid, uid)
			if gerr != nil {
				return "get:" + ifaceClass(gerr)
			}
			derr := s.ls.DeleteSecretACL(e.ctx, g.ID)
			_, after := s.ls.GetSecretACL(e.ctx, sid, uid)
			e.meta(s, derr != nil || after != nil, "deleted ACL still reads back")
			return fmt.Sprintf("%s %s", ifaceClass(derr), ifaceClass(after))
		default:
			return "delbyproj:" + ifaceClass(s.ls.DeleteSecretACLsByUserAndProject(e.ctx, uid, s.project(e, 0)))
		}
	})
}

func fpACL(s *ifaceSide, a *models.SecretACL) string {
	return fmt.Sprintf("%s|%s|%q", s.h.name("secret", a.SecretID), s.h.name("user", a.UserID), a.Permissions)
}

func opShare(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("Share(mode=%d)", p.mode%8)
	e.both(label, func(s *ifaceSide) string {
		sid := s.secret(e, pick(p.a, 2))
		uid := s.user(e, pick(p.b, 3))
		switch p.mode % 8 {
		case 0: // create, optionally time-bound; validity of the expiry is part of the class
			sh := &models.ShareRecord{SecretID: sid, OwnerID: diffFixedOwnerID, RecipientID: uid, Permission: "read"}
			if p.a&2 != 0 {
				exp := p.at()
				sh.ExpiresAt = &exp
			}
			c, err := s.ls.CreateShareRecord(e.ctx, sh)
			if err != nil {
				return "create:" + ifaceClass(err)
			}
			s.h.add("share", c.ID)
			return "created"
		case 1:
			id, ok := s.h.get("share", pick(p.b, 4))
			if !ok {
				return "noop"
			}
			g, err := s.ls.GetShareRecord(e.ctx, id)
			if err != nil {
				return "get:" + ifaceClass(err)
			}
			return fpShare(s, g)
		case 2:
			id, ok := s.h.get("share", pick(p.b, 4))
			if !ok {
				return "noop"
			}
			exp := p.at()
			_, err := s.ls.UpdateShareRecord(e.ctx, &models.ShareRecord{ID: id, Permission: "write", ExpiresAt: &exp})
			g, gerr := s.ls.GetShareRecord(e.ctx, id)
			got := "<nil>"
			if g != nil {
				got = fpShare(s, g)
			}
			return fmt.Sprintf("%s %s %s", ifaceClass(err), ifaceClass(gerr), got)
		case 3:
			id, ok := s.h.get("share", pick(p.b, 4))
			if !ok {
				return "noop"
			}
			err := s.ls.DeleteShareRecord(e.ctx, id)
			_, gerr := s.ls.GetShareRecord(e.ctx, id)
			return fmt.Sprintf("%s %s", ifaceClass(err), ifaceClass(gerr))
		case 4:
			now := p.at()
			rows, err := s.ls.ListSharesBySecret(e.ctx, sid, now)
			return fmt.Sprintf("%s %s", ifaceClass(err), sharesStr(s, rows))
		case 5:
			now := p.at()
			rows, err := s.ls.ListSharesByUser(e.ctx, uid, now)
			perm, perr := s.ls.CheckSharePermission(e.ctx, sid, uid, now)
			secrets, serr := s.ls.ListSharedSecrets(e.ctx, uid, now)
			names := make([]string, 0, len(secrets))
			for _, n := range secrets {
				names = append(names, n.Name)
			}
			return fmt.Sprintf("%s %s %s %q %s %s", ifaceClass(err), sharesStr(s, rows), ifaceClass(perr), perm, ifaceClass(serr), sortedRows(names))
		case 6:
			rows, err := s.ls.DeleteExpiredShareRecords(e.ctx, p.at())
			return fmt.Sprintf("%s %s", ifaceClass(err), sharesStr(s, rows))
		default:
			n, err := s.ls.ReassignSecretShareOwner(e.ctx, sid, 998)
			return fmt.Sprintf("%s %d", ifaceClass(err), n)
		}
	})
}

func fpShare(s *ifaceSide, g *models.ShareRecord) string {
	return fmt.Sprintf("%s|%s|%s|%s", s.h.name("secret", g.SecretID), s.h.name("user", g.RecipientID), g.Permission, fpTime(g.ExpiresAt))
}

func sharesStr(s *ifaceSide, rows []*models.ShareRecord) string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fpShare(s, r))
	}
	return sortedRows(out)
}

func opConnector(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("Connector(mode=%d,name=%q,textorder=1)", p.mode%5, p.name)
	e.both(label, func(s *ifaceSide) string {
		switch p.mode % 5 {
		case 0: // unique (role, connector, ref_prefix)
			rid := s.role(e, pick(p.a, 2))
			g, err := s.ls.CreateConnectRefGrant(e.ctx, &models.ConnectRefGrant{RoleID: rid, Connector: p.name, RefPrefix: p.name2})
			if err != nil {
				return "create:" + ifaceClass(err)
			}
			s.h.add("grant", g.ID)
			return "created"
		case 1: // ORDER BY connector, role_id, ref_prefix on a unique key
			rows, err := s.ls.ListConnectRefGrantsByConnector(e.ctx, p.name)
			return ifaceClass(err) + " " + orderedRows(grantRows(s, rows))
		case 2:
			rows, err := s.ls.ListConnectRefGrants(e.ctx)
			return ifaceClass(err) + " " + orderedRows(grantRows(s, rows))
		case 3:
			id, ok := s.h.get("grant", pick(p.b, 4))
			if !ok {
				return "noop"
			}
			return "del:" + ifaceClass(s.ls.DeleteConnectRefGrant(e.ctx, id))
		default:
			pid := s.project(e, pick(p.b, 2))
			b, err := s.ls.CreateConnectorProjectBinding(e.ctx, &models.ConnectorProjectBinding{Connector: p.name, ProjectID: pid, ProjectName: p.name2})
			g, gerr := s.ls.GetConnectorProjectBinding(e.ctx, p.name)
			if err == nil && gerr == nil {
				e.meta(s, g.ID == b.ID && g.ProjectName == p.name2, "created binding does not read back")
			}
			return fmt.Sprintf("%s %s", ifaceClass(err), ifaceClass(gerr))
		}
	})
}

func grantRows(s *ifaceSide, rows []*models.ConnectRefGrant) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%q|%s|%q", r.Connector, s.h.name("role", r.RoleID), r.RefPrefix))
	}
	return out
}

var ifaceAuditTypes = []string{"secret.read", "secret.created", "user.login", "project.deleted", "secret_backup.read"}

func auditResourceTerm(p opParams) string {
	return []string{"secret", "SECRET", "Secret", "user", "secret_backup", p.name}[pick(p.b, 6)]
}

func opAudit(e *ifaceExec, p opParams) {
	mode := p.mode % 6
	// The foldterm= marker names the search term for rule FOLD-CTYPE-C.
	term := diffTerm(p.name, p.name2, p.a)
	label := fmt.Sprintf("Audit(mode=%d,foldterm=%s,resource=%q,textorder=1)", mode, term, auditResourceTerm(p))
	e.both(label, func(s *ifaceSide) string {
		switch mode {
		case 0: // append with an explicit event time; the hash chain must keep up
			uid := s.user(e, pick(p.a, 2))
			succ := p.a&2 == 0
			ev := &models.AuditEvent{EventType: ifaceAuditTypes[pick(p.b, 5)], UserID: &uid, IPAddress: p.name2,
				Success: &succ, Description: p.name, EventTime: ifacePastBase.Add(time.Duration(e.step) * time.Second)}
			return "log:" + ifaceClass(s.ls.LogAuditEvent(e.ctx, ev))
		case 1: // actor search through the folded-contains clause
			return s.auditWalk(e, &storage.AuditFilter{ActorUsername: &term})
		case 2: // resource prefix, the LIKE path
			r := auditResourceTerm(p)
			return s.auditWalk(e, &storage.AuditFilter{ResourceType: &r})
		case 3: // time window plus success flag, bounds in any zone
			start, end := p.at(), p.at().Add(48*time.Hour)
			succ := p.a&2 == 0
			return s.auditWalk(e, &storage.AuditFilter{StartTime: &start, EndTime: &end, Success: &succ})
		case 4: // keyset cursor walk from the first page
			return s.auditKeyset(e)
		default: // ascending, as the SIEM export reads
			start := p.at()
			return s.auditAscending(e, &start)
		}
	})
}

func fpAudit(s *ifaceSide, ev *models.AuditEvent) string {
	uid := uint(0)
	if ev.UserID != nil {
		uid = *ev.UserID
	}
	success := "nil"
	if ev.Success != nil {
		success = fmt.Sprint(*ev.Success)
	}
	return fmt.Sprintf("%s|%s|%s|%q|%q|%s", ev.EventType, s.h.name("user", uid), ev.EventTime.UTC().Format(time.RFC3339Nano), ev.IPAddress, ev.Description, success)
}

func (s *ifaceSide) auditWalk(e *ifaceExec, f *storage.AuditFilter) string {
	f.PageSize = 2
	var walked []string
	var total int64
	for page := 1; page <= 20; page++ {
		ff := *f
		ff.Page = page
		rows, tot, err := s.ls.GetAuditLogs(e.ctx, &ff)
		if err != nil {
			return "err:" + ifaceClass(err)
		}
		total = tot
		for _, r := range rows {
			walked = append(walked, fpAudit(s, r))
		}
		if len(rows) < 2 {
			break
		}
	}
	// The page walk is order-stable: every row appears once and the count matches.
	dedup := slices.Clone(walked)
	slices.Sort(dedup)
	e.meta(s, len(slices.Compact(dedup)) == len(walked), "audit page walk returned a row twice: %d rows", len(walked))
	e.meta(s, int64(len(walked)) == total, "audit page walk found %d rows, total says %d", len(walked), total)
	return fmt.Sprintf("total=%d %s", total, orderedRows(walked))
}

func (s *ifaceSide) auditKeyset(e *ifaceExec) string {
	var cursor *storage.AuditCursor
	var out []string
	for range 20 {
		rows, _, err := s.ls.GetAuditLogs(e.ctx, &storage.AuditFilter{PageSize: 2, Before: cursor})
		if err != nil {
			return "err:" + ifaceClass(err)
		}
		for _, r := range rows {
			out = append(out, fpAudit(s, r))
		}
		if len(rows) < 2 {
			break
		}
		last := rows[len(rows)-1]
		cursor = &storage.AuditCursor{EventTime: last.EventTime, ID: last.ID}
	}
	return orderedRows(out)
}

func (s *ifaceSide) auditAscending(e *ifaceExec, start *time.Time) string {
	rows, total, err := s.ls.GetAuditLogs(e.ctx, &storage.AuditFilter{StartTime: start, Ascending: true, PageSize: 100})
	if err != nil {
		return "err:" + ifaceClass(err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fpAudit(s, r))
	}
	return fmt.Sprintf("total=%d %s", total, orderedRows(out))
}

// opRegressionExpiryPagination drives the #4022 shape (equal expirations, offset paging
// through ListSecrets) on both backends through the interface. Reappearance is a finding.
func opRegressionExpiryPagination(e *ifaceExec, p opParams) {
	e.both(fmt.Sprintf("ExpiryPagination(n=%d)", pick(p.a, 8)+2), func(s *ifaceSide) string {
		n := pick(p.a, 8) + 2
		pid, eid := s.project(e, 0), s.envIn(e, 0)
		exp := ifaceFutureBase.Add(time.Hour)
		for i := range n {
			if _, err := s.ls.CreateSecret(e.ctx, &models.SecretNode{Name: fmt.Sprintf("pag%d", i), ProjectID: pid, EnvironmentID: eid, OwnerID: diffFixedOwnerID, IsSecret: true, Expiration: &exp}); err != nil {
				return "seed:" + ifaceClass(err)
			}
		}
		pageSize := pick(p.b, 3) + 1
		before := exp.Add(time.Hour)
		seen := map[string]int{}
		var names []string
		var total int64
		for page := 1; page <= n+2; page++ {
			rows, tot, err := s.ls.ListSecrets(e.ctx, &storage.SecretFilter{ProjectID: &pid, Page: page, PageSize: pageSize, ExpiresBefore: &before})
			if err != nil {
				return "list:" + ifaceClass(err)
			}
			total = tot
			for _, r := range rows {
				seen[r.Name]++
				names = append(names, r.Name)
			}
			if len(rows) < pageSize {
				break
			}
		}
		e.meta(s, int64(len(names)) == total, "ExpiresBefore page walk: %d rows, total %d", len(names), total)
		for _, c := range seen {
			e.meta(s, c == 1, "ExpiresBefore page walk returned a row %d times (#4022 shape)", c)
		}
		return fmt.Sprintf("total=%d %s", total, orderedRows(names))
	})
}

// opRegressionProjectName drives the #4027 shape: two names that fold together (case and
// NFC/NFD) in one project namespace, and reuse after a delete. Reappearance is a finding.
func opRegressionProjectName(e *ifaceExec, p opParams) {
	label := fmt.Sprintf("ProjectNameUnique(%q,%q,mode=%d)", p.name, p.name2, p.mode%3)
	e.both(label, func(s *ifaceSide) string {
		ctx := context.WithoutCancel(e.ctx)
		a, err := s.ls.CreateProject(ctx, &models.Project{Name: p.name})
		first := ifaceClass(err)
		if err == nil {
			s.h.add("project", a.ID)
		}
		if p.mode%3 == 1 && err == nil {
			first += "/del=" + ifaceClass(s.ls.DeleteProject(ctx, a.ID))
		}
		b, err2 := s.ls.CreateProject(ctx, &models.Project{Name: p.name2})
		second := ifaceClass(err2)
		if err2 == nil {
			s.h.add("project", b.ID)
		}
		g, gerr := s.ls.GetProjectByName(ctx, p.name2)
		got := ""
		if g != nil {
			got = g.Name
		}
		return fmt.Sprintf("%s %s get=%s %q", first, second, ifaceClass(gerr), got)
	})
}
