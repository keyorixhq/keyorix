package authzdiff

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// Stateful sequence fuzzing (see SEQUENCE.md).
//
// The single-step harness answers "is THIS operation authorised the same way
// on every layer from a fresh seeded world". This file answers what a single
// step cannot: after a SEQUENCE of grants, revocations, suspensions and
// membership changes, does every layer still agree with the grant tables, and
// did every revocation actually revoke?
//
// One world per layer (core, REST, gRPC), all cloned from the same template.
// Each step runs on all three, then:
//
//	O-S  the step's layers agree, and for grant/revoke the step's outcome equals
//	     the reference model's decision taken on the world BEFORE the step.
//	O-E  effect: an allowed step left the state it names (the revoked grant is
//	     gone, the granted one is there, the account is suspended/active, the
//	     group row exists/is gone); a denied step changed nothing (authz-table
//	     snapshot equal).
//	O-P  probe: after every step, every principal reads the secret value of
//	     every project on every layer. Each layer's answer must equal the
//	     reference model on that layer's own database (isolation + revocation:
//	     a revoked principal's next read is denied on all routes; nobody reads
//	     where they hold nothing), and the layers must agree.
//
// The model reads the grant tables, so O-P alone cannot see a revoke that did
// not delete; O-E is the independent intent check that closes that gap.

type seqKind int

const (
	skGrant seqKind = iota
	skRevoke
	skSuspend
	skReactivate
	skGroupAdd
	skGroupRemove
	skPermToggle
	skExpire
	numSeqKinds
)

var seqKindNames = [numSeqKinds]string{
	"role.grant", "role.revoke", "user.suspend", "user.reactivate",
	"group.add", "group.remove", "custom.perm.toggle", "grant.expire",
}

var (
	seqActors   = []principalKind{pkGlobalAdmin, pkProjAdmin, pkCustom, pkViewer, pkNone}
	seqSubjects = []principalKind{pkNone, pkViewer, pkCustom, pkProjAdmin, pkExpired}
	seqProbes   = []principalKind{pkNone, pkViewer, pkProjAdmin, pkGlobalAdmin, pkCustom, pkMachine, pkExpired, pkSuspended}
	seqTargets  = []tgt{tA, tB, tGlobal}
)

const (
	seqMaxSteps = 8
	seqStepLen  = 5
)

type seqStep struct {
	Kind    seqKind
	Actor   principalKind
	Subject principalKind
	T       tgt
	Role    byte // granted role index (grantRoles) / group choice
	Bit     byte // custom permission index
}

func (s seqStep) String() string {
	return fmt.Sprintf("%s actor=%s subject=%s scope=%s role=%d bit=%d", seqKindNames[s.Kind], s.Actor, s.Subject, s.T, s.Role, s.Bit)
}

func decodeSeq(data []byte) []seqStep {
	var out []seqStep
	for i := 0; i+seqStepLen <= len(data) && len(out) < seqMaxSteps; i += seqStepLen {
		b := data[i : i+seqStepLen]
		out = append(out, seqStep{
			Kind:    seqKind(int(b[0]) % int(numSeqKinds)),
			Actor:   seqActors[int(b[1])%len(seqActors)],
			Subject: seqSubjects[int(b[2])%len(seqSubjects)],
			T:       seqTargets[int(b[3])%len(seqTargets)],
			Role:    b[4] % 4,
			Bit:     b[4] / 4,
		})
	}
	return out
}

// ---------- world: one leg per layer ----------

type seqWorld struct {
	legs map[layer]*leg
	fx   *fixtures
	// pr holds one principal copy per layer. The auth cache is process-global
	// and tombstones a suspended user's token hash, so worlds must not share
	// token strings: every subject kind logs in afresh on each leg.
	pr map[layer]map[principalKind]*principal
}

func (w *seqWorld) p(l layer, k principalKind) *principal { return w.pr[l][k] }

// login gives principal k on layer l a fresh session token; false if it cannot.
func (w *seqWorld) login(l layer, k principalKind) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	q := w.pr[l][k]
	tok, _ := mustLogin(context.Background(), w.legs[l].c, q.username)
	q.token = tok
	return true
}

var seqLayers = []layer{layerCore, layerREST, layerGRPC}

func newSeqWorld(tb testing.TB) *seqWorld {
	tb.Helper()
	_, fx := template(tb)
	w := &seqWorld{legs: map[layer]*leg{}, fx: fx, pr: map[layer]map[principalKind]*principal{}}
	for _, l := range seqLayers {
		w.legs[l] = newLeg(tb, l)
		w.pr[l] = map[principalKind]*principal{}
		for k, q := range fx.principals {
			c := *q
			w.pr[l][k] = &c
		}
		for _, k := range seqSubjects {
			if !w.login(l, k) {
				tb.Fatalf("fresh login for %s on %s failed", k, l)
			}
		}
	}
	return w
}

func (w *seqWorld) close() {
	for _, lg := range w.legs {
		lg.close()
	}
}

// ---------- a mutating step ----------

type seqCall struct {
	core           func(ctx context.Context, lg *leg, p *principal) error
	rest           func() restReq
	grpc           func(ctx context.Context, lg *leg) error // nil: no gRPC RPC for this step
	globalHandler  bool                                     // REST route served through a package-level handler global
	coreRecordOnly bool                                     // transport-enforced: the core leg is state-synced, not an oracle leg
	req            *requirement                             // nil: outside the model's domain
	effect         func(db *gorm.DB) (bool, string)         // nil: no intent check
}

func countRows(db *gorm.DB, q string, args ...any) int64 {
	var n int64
	db.Raw(q, args...).Scan(&n)
	return n
}

// buildCall binds one step to its calls. Whether the core leg is an oracle is
// derived from matrix.json (core_refusal), as in the single-step harness: an
// operation whose authorisation lives in the transport (ID-2) is not run on
// core with the real actor; its core leg only mirrors an allowed outcome.
func buildCall(tb testing.TB, fx *fixtures, st seqStep) *seqCall {
	c := buildCallRaw(fx, st)
	if c != nil && !c.coreRecordOnly {
		row := map[seqKind]string{skGrant: "AssignUserRole", skRevoke: "RemoveUserRole", skGroupAdd: "AddUserToGroup", skGroupRemove: "RemoveUserFromGroup"}[st.Kind]
		c.coreRecordOnly = coreRefusal(tb, row) == "none"
	}
	return c
}

func buildCallRaw(fx *fixtures, st seqStep) *seqCall {
	subj := fx.principals[st.Subject]
	proj := pid(fx, st.T)
	_, rid := grantRole(fx, st.Role)
	scope := core.Scope{ProjectID: proj}
	pidp := uint32(proj)
	switch st.Kind {
	case skGrant:
		return &seqCall{
			core: func(ctx context.Context, lg *leg, p *principal) error {
				return lg.c.AssignUserRole(ctx, p.userID, subj.userID, rid, scope, p.isMachine())
			},
			rest: func() restReq {
				return restReq{http.MethodPost, "/api/v1/user-roles", map[string]any{"user_id": subj.userID, "role_id": rid, "project_id": proj}}
			},
			grpc: func(ctx context.Context, lg *leg) error {
				_, err := pb.NewRoleServiceClient(lg.conn).AssignRole(ctx, &pb.AssignRoleRequest{UserId: uint32(subj.userID), RoleId: uint32(rid), ProjectId: &pidp})
				return err
			},
			req: &requirement{perms: []string{"roles.assign"}, scope: proj, ceiling: []roleAt{{rid, proj}}},
			effect: func(db *gorm.DB) (bool, string) {
				n := countRows(db, `SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND project_id = ? AND environment_id = 0`, subj.userID, rid, proj)
				return n >= 1, "granted-row-missing"
			},
		}
	case skRevoke:
		return &seqCall{
			core: func(ctx context.Context, lg *leg, p *principal) error {
				return lg.c.RemoveUserRole(ctx, p.userID, subj.userID, rid, scope)
			},
			rest: func() restReq {
				return restReq{http.MethodDelete, "/api/v1/user-roles", map[string]any{"user_id": subj.userID, "role_id": rid, "project_id": proj}}
			},
			grpc: func(ctx context.Context, lg *leg) error {
				_, err := pb.NewRoleServiceClient(lg.conn).RemoveRole(ctx, &pb.RemoveRoleRequest{UserId: uint32(subj.userID), RoleId: uint32(rid), ProjectId: &pidp})
				return err
			},
			req: &requirement{perms: []string{"roles.assign"}, scope: proj},
			effect: func(db *gorm.DB) (bool, string) {
				n := countRows(db, `SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND project_id = ? AND environment_id = 0`, subj.userID, rid, proj)
				return n == 0, "revoked-row-still-present"
			},
		}
	case skSuspend, skReactivate:
		suspend := st.Kind == skSuspend
		verb, want := "reactivate", "active"
		if suspend {
			verb, want = "suspend", "suspended"
		}
		return &seqCall{
			core: func(ctx context.Context, lg *leg, p *principal) error {
				if suspend {
					return lg.c.SuspendUser(ctx, p.userID, subj.userID)
				}
				return lg.c.ReactivateUser(ctx, p.userID, subj.userID)
			},
			rest: func() restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/users/%d/%s", subj.userID, verb), nil}
			},
			globalHandler:  true,
			coreRecordOnly: true,
			effect: func(db *gorm.DB) (bool, string) {
				var s string
				db.Raw(`SELECT account_state FROM users WHERE id = ?`, subj.userID).Scan(&s)
				return s == want, "account-state-not-" + want
			},
		}
	case skGroupAdd:
		gid := []uint{fx.groupID, fx.customGroupID}[int(st.Role)%2]
		return &seqCall{
			core: func(ctx context.Context, lg *leg, p *principal) error {
				return lg.c.AddUserToGroup(ctx, p.userID, p.isMachine(), subj.userID, gid, proj)
			},
			rest: func() restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/members", gid), map[string]any{"user_id": subj.userID, "project_id": proj}}
			},
			grpc: func(ctx context.Context, lg *leg) error {
				if proj != 0 {
					return errLayerAbsent
				}
				_, err := pb.NewGroupServiceClient(lg.conn).AddGroupMember(ctx, &pb.GroupMemberRequest{GroupId: uint32(gid), UserId: uint32(subj.userID)})
				return err
			},
			effect: func(db *gorm.DB) (bool, string) {
				n := countRows(db, `SELECT COUNT(*) FROM user_groups WHERE user_id = ? AND group_id = ? AND project_id = ?`, subj.userID, gid, proj)
				return n == 1, "group-row-missing"
			},
		}
	case skGroupRemove:
		gid := []uint{fx.groupID, fx.customGroupID}[int(st.Role)%2]
		return &seqCall{
			core: func(ctx context.Context, lg *leg, p *principal) error {
				return lg.c.RemoveUserFromGroup(ctx, p.userID, subj.userID, gid, 0)
			},
			rest: func() restReq {
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/groups/%d/members/%d", gid, subj.userID), nil}
			},
			grpc: func(ctx context.Context, lg *leg) error {
				_, err := pb.NewGroupServiceClient(lg.conn).RemoveGroupMember(ctx, &pb.GroupMemberRequest{GroupId: uint32(gid), UserId: uint32(subj.userID)})
				return err
			},
			effect: func(db *gorm.DB) (bool, string) {
				n := countRows(db, `SELECT COUNT(*) FROM user_groups WHERE user_id = ? AND group_id = ? AND project_id = 0`, subj.userID, gid)
				return n == 0, "group-row-still-present"
			},
		}
	}
	return nil
}

// applyStateStep runs the steps that are state changes rather than API calls:
// toggling one permission of the custom role (through the store's mutators, so
// the role->permission cache generation moves), and expiring a subject's
// direct grants (the fake clock: time moves past the grant).
func (w *seqWorld) applyStateStep(st seqStep) {
	past := time.Now().UTC().Add(-time.Hour)
	for _, lg := range w.legs {
		switch st.Kind {
		case skPermToggle:
			name := customPermUniverse[int(st.Bit)%len(customPermUniverse)]
			pidv := lg.fx.permIDs[name]
			held := countRows(lg.db, `SELECT COUNT(*) FROM role_permissions WHERE role_id = ? AND permission_id = ?`, lg.fx.customRoleID, pidv) > 0
			if held {
				_ = lg.ls.RemovePermissionFromRole(context.Background(), lg.fx.customRoleID, pidv)
			} else {
				_ = lg.ls.AssignPermissionToRole(context.Background(), lg.fx.customRoleID, pidv)
			}
		case skExpire:
			lg.db.Exec(`UPDATE user_roles SET expires_at = ? WHERE user_id = ? AND environment_id = 0`, past, lg.fx.principals[st.Subject].userID)
		}
	}
}

// authzSnapshot is a digest of every table authorisation reads, plus account
// state. A denied step must leave it unchanged.
func authzSnapshot(db *gorm.DB) string {
	h := sha256.New()
	for _, q := range []string{
		`SELECT user_id, role_id, project_id, environment_id, expires_at FROM user_roles ORDER BY user_id, role_id, project_id, environment_id`,
		`SELECT group_id, role_id, project_id, environment_id, expires_at FROM group_roles ORDER BY group_id, role_id, project_id, environment_id`,
		`SELECT user_id, group_id, project_id FROM user_groups ORDER BY user_id, group_id, project_id`,
		`SELECT machine_identity_id, role_id, project_id, environment_id FROM machine_identity_roles ORDER BY machine_identity_id, role_id, project_id, environment_id`,
		`SELECT role_id, permission_id FROM role_permissions ORDER BY role_id, permission_id`,
		`SELECT id, account_state FROM users ORDER BY id`,
	} {
		rows, err := db.Raw(q).Rows()
		if err != nil {
			_, _ = fmt.Fprintf(h, "ERR %v\n", err)
			continue
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			_ = rows.Scan(ptrs...)
			_, _ = fmt.Fprintln(h, vals...)
		}
		_ = rows.Close()
	}
	return fmt.Sprintf("%x", h.Sum(nil)[:8])
}
