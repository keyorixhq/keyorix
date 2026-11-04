package authzdiff

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	httpserver "github.com/keyorixhq/keyorix/server/http"
)

// World construction. A TEMPLATE SQLite file is seeded once per test binary
// (production migration via fuzzworld.Bootstrap, then principals and fixtures
// through core/storage), closed, and held as bytes. Every leg of every case
// gets its OWN byte copy of that file with a fresh core (+ router or gRPC
// server) on top — a fresh seeded store per leg, so a mutating op on one layer
// can never change what another layer or the next case sees.
//
// Synthetic only: every name, email, password and secret value below is
// made up for this harness; secret values are never printed.
//
// Encryption is not wired (core's dev/test plaintext mode), so a copied file
// decrypts under any core instance. Authorization does not depend on it.

const fxPassword = "Az9!synthetic-only-Q7"

type principalKind string

const (
	pkNone        principalKind = "no-role"
	pkViewer      principalKind = "viewer@A"
	pkProjAdmin   principalKind = "project-admin@A"
	pkGlobalAdmin principalKind = "global-admin"
	pkCustom      principalKind = "custom-role" // FIX-1 shape: real permissions, non-canonical name
	pkMachine     principalKind = "machine-token"
	pkActor0      principalKind = "actor-0"
	pkExpired     principalKind = "expired-grant"
)

var allPrincipalKinds = []principalKind{pkNone, pkViewer, pkProjAdmin, pkGlobalAdmin, pkCustom, pkMachine, pkActor0, pkExpired}

type principal struct {
	kind            principalKind
	userID          uint
	machineID       uint
	token           string
	username        string
	systemActor     bool // actor id 0: core only (ID-1)
	unauthenticated bool
}

func (p *principal) coreOnly() bool  { return p.systemActor }
func (p *principal) isMachine() bool { return p.machineID != 0 }

// perProject holds the fixtures that exist once in each of project A and B.
type perProject struct {
	projectID, envID uint
	projectName      string
	secretID         uint
	secretRef        string // "<project>/<env>/<name>"
	machineID        uint   // target machine identity (not the principal)
	machineCredID    uint   // an issued credential on it (revoke target)
	invitationID     uint
	accessRequestID  uint
	membershipID     uint
	aclID            uint // ACL entry on secretID for targetUser
	secrets          [4]fixtureSecret
}

// fixtureSecret is one of the four per-project secrets selected by an op arg
// (opSpec.secretArgs). aclID is the ACL entry the acl.revoke op removes.
type fixtureSecret struct {
	id    uint
	ref   string
	aclID uint
}

type fixtures struct {
	adminID          uint
	A, B             perProject
	targetUserID     uint // recipient/member/invitee target
	aclRecipientID   uint // ACL-grant recipient (member of A and B, no ACL yet)
	targetUserEmail  string
	groupID          uint // target group: has targetUser as member and roleViewer@A
	roleIDs          map[string]uint
	customRoleID     uint
	permIDs          map[string]uint
	principals       map[principalKind]*principal
	customGrantProjA uint // project the custom role is granted at by default (A)
}

func (f *fixtures) proj(sel byte) *perProject {
	if sel%2 == 1 {
		return &f.B
	}
	return &f.A
}

// customPermUniverse is the permission set the custom role's subset is drawn
// from: every catalog permission an op in this harness gates on.
var customPermUniverse = []string{
	"secrets.read", "secrets.write", "secrets.delete", "secrets.manage",
	"users.read", "users.write", "roles.read", "roles.assign",
}

var (
	tmplOnce  sync.Once
	tmplBytes []byte
	tmplFx    *fixtures
	tmplErr   error
)

// template returns the seeded template's bytes and fixtures, building them on
// first use.
func template(tb testing.TB) ([]byte, *fixtures) {
	tb.Helper()
	tmplOnce.Do(func() { tmplBytes, tmplFx, tmplErr = buildTemplate(tb) })
	if tmplErr != nil {
		tb.Fatalf("template: %v", tmplErr)
	}
	return tmplBytes, tmplFx
}

func buildTemplate(tb testing.TB) ([]byte, *fixtures, error) {
	if err := i18n.InitializeForTesting(); err != nil {
		return nil, nil, err
	}
	dir, err := os.MkdirTemp("", "authzdiff-tmpl-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "template.db")
	db := fuzzworld.OpenSQLite(tb, path, 1)
	fuzzworld.Bootstrap(tb, db)
	fx, err := seed(context.Background(), db)
	if err != nil {
		return nil, nil, err
	}
	sqlDB, _ := db.DB()
	if err := sqlDB.Close(); err != nil {
		return nil, nil, err
	}
	b, err := os.ReadFile(path)
	return b, fx, err
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func seed(ctx context.Context, db *gorm.DB) (fx *fixtures, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("seed: %v", r)
		}
	}()
	ls := store.NewLocalStorage(db)
	c := newCore(ls)
	c.SetBootstrapToken("authzdiff-bootstrap")
	must(c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "kxadmin", Email: "kxadmin@example.invalid", Password: fxPassword, DisplayName: "Admin", Token: "authzdiff-bootstrap",
	}))
	fx = &fixtures{roleIDs: map[string]uint{}, permIDs: map[string]uint{}, principals: map[principalKind]*principal{}}
	adminSess, admin := mustLogin(ctx, c, "kxadmin")
	fx.adminID = admin.ID
	fx.principals[pkGlobalAdmin] = &principal{kind: pkGlobalAdmin, userID: admin.ID, token: adminSess, username: "kxadmin"}
	fx.principals[pkActor0] = &principal{kind: pkActor0, systemActor: true}

	// secrets.manage gates ACLs but is not in the seeded catalog: add it so a
	// custom role can hold it.
	var perms []models.Permission
	db.Find(&perms)
	for _, p := range perms {
		fx.permIDs[p.Name] = p.ID
	}
	if _, ok := fx.permIDs["secrets.manage"]; !ok {
		p := models.Permission{Name: "secrets.manage", Resource: "secrets", Action: "manage"}
		if e := db.Create(&p).Error; e != nil {
			return nil, e
		}
		fx.permIDs[p.Name] = p.ID
	}
	var roles []models.Role
	db.Find(&roles)
	for _, r := range roles {
		fx.roleIDs[r.Name] = r.ID
	}
	custom := models.Role{Name: "release-manager", NameFolded: "release-manager", Description: "custom role, non-canonical name"}
	if e := db.Create(&custom).Error; e != nil {
		return nil, e
	}
	fx.customRoleID = custom.ID
	fx.roleIDs[custom.Name] = custom.ID

	mkProject := func(name string) perProject {
		p := must(ls.CreateProject(ctx, &models.Project{Name: name}))
		e := must(ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p.ID}))
		return perProject{projectID: p.ID, envID: e.ID, projectName: name}
	}
	fx.A, fx.B = mkProject("proja"), mkProject("projb")
	fx.customGrantProjA = fx.A.projectID
	// The admin owns every fixture secret; sharing needs the owner to be a
	// project MEMBER (ErrShareOwnerNotMember: a global role is not membership).
	for _, pp := range []uint{fx.A.projectID, fx.B.projectID} {
		if e := db.Create(&models.UserRole{UserID: admin.ID, RoleID: fx.roleIDs["project_admin"], ProjectID: pp}).Error; e != nil {
			return nil, e
		}
	}

	mkUser := func(uname string) *models.User {
		return must(c.CreateUser(ctx, &core.CreateUserRequest{Username: uname, Email: uname + "@example.invalid", DisplayName: uname, Password: fxPassword}))
	}
	grant := func(userID, roleID, projectID uint, expires *time.Time) {
		if e := db.Create(&models.UserRole{UserID: userID, RoleID: roleID, ProjectID: projectID, ExpiresAt: expires}).Error; e != nil {
			panic(e)
		}
	}
	addUserPrincipal := func(kind principalKind, uname string) *principal {
		u := mkUser(uname)
		tok, _ := mustLogin(ctx, c, uname)
		p := &principal{kind: kind, userID: u.ID, token: tok, username: uname}
		fx.principals[kind] = p
		return p
	}
	none := addUserPrincipal(pkNone, "p-none")
	db.Exec("DELETE FROM user_roles WHERE user_id = ?", none.userID) // truly no role (CreateUser's baseline removed)
	viewer := addUserPrincipal(pkViewer, "p-viewer")
	grant(viewer.userID, fx.roleIDs["project_viewer"], fx.A.projectID, nil)
	padmin := addUserPrincipal(pkProjAdmin, "p-padmin")
	grant(padmin.userID, fx.roleIDs["project_admin"], fx.A.projectID, nil)
	cust := addUserPrincipal(pkCustom, "p-custom")
	grant(cust.userID, custom.ID, fx.A.projectID, nil)
	exp := addUserPrincipal(pkExpired, "p-expired")
	past := time.Now().UTC().Add(-time.Hour)
	grant(exp.userID, fx.roleIDs["project_admin"], fx.A.projectID, &past)

	target := mkUser("u-target")
	fx.targetUserID, fx.targetUserEmail = target.ID, target.Email
	requesterA, requesterB := mkUser("u-req-a"), mkUser("u-req-b")
	// share and ACL recipients must be members of the secret's project.
	aclRcpt := mkUser("u-acl")
	fx.aclRecipientID = aclRcpt.ID
	for _, uid := range []uint{target.ID, aclRcpt.ID} {
		grant(uid, fx.roleIDs["project_viewer"], fx.A.projectID, nil)
		grant(uid, fx.roleIDs["project_viewer"], fx.B.projectID, nil)
	}

	// machine principal: in project A, holds the custom role at A.
	m := must(c.CreateMachineIdentity(ctx, fx.A.projectID, "m-principal", "service", "", "", admin.ID, 0))
	if e := db.Create(&models.MachineIdentityRole{MachineIdentityID: m.ID, RoleID: custom.ID, ProjectID: fx.A.projectID}).Error; e != nil {
		return nil, e
	}
	mt := must(c.IssueMachineToken(ctx, fx.A.projectID, m.ID, admin.ID, core.IssueMachineTokenParams{Name: "principal-token"}))
	fx.principals[pkMachine] = &principal{kind: pkMachine, machineID: m.ID, token: mt.PlainToken, username: "m-principal"}

	for i, pp := range []*perProject{&fx.A, &fx.B} {
		sec := must(c.CreateSecret(ctx, &core.CreateSecretRequest{
			Name: "s", Value: []byte(fmt.Sprintf("synthetic-%d", i)), ProjectID: pp.projectID, EnvironmentID: pp.envID,
			Type: "password", CreatedBy: "kxadmin", OwnerID: admin.ID,
		}))
		pp.secretID, pp.secretRef = sec.ID, pp.projectName+"/prod/s"
		mi := must(c.CreateMachineIdentity(ctx, pp.projectID, "m-target", "service", "", "", admin.ID, 0))
		pp.machineID = mi.ID
		cred := must(c.IssueMachineToken(ctx, pp.projectID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "target-token"}))
		pp.machineCredID = cred.Credential.ID
		inv, _ := mustInvite(c.InviteToProjectWithLink(ctx, pp.projectID, fmt.Sprintf("invitee-%d@example.invalid", i), "project_viewer", admin.ID, 0))
		pp.invitationID = inv.ID
		req := requesterA
		if i == 1 {
			req = requesterB
		}
		ar := must(c.RequestProjectAccess(ctx, pp.projectID, req.ID, "project_viewer", "synthetic"))
		pp.accessRequestID = ar.ID
		mem := must(c.InviteMember(ctx, pp.projectID, target.ID, "project_viewer", admin.ID, 0, false))
		pp.membershipID = mem.ID
		if e := c.GrantSecretACL(ctx, admin.ID, sec.ID, target.ID, []string{"secrets.read"}); e != nil {
			return nil, fmt.Errorf("acl fixture: %w", e)
		}
		var acl models.SecretACL
		if e := db.Where("secret_id = ? AND user_id = ?", sec.ID, target.ID).First(&acl).Error; e != nil {
			return nil, fmt.Errorf("acl fixture read: %w", e)
		}
		pp.aclID = acl.ID
		pp.secrets[0] = fixtureSecret{id: sec.ID, ref: pp.secretRef, aclID: acl.ID}

		// s1: owned by the viewer principal (a member of A, NOT of B).
		// s2: admin-owned, write share -> viewer, read share -> custom (A only).
		// s3: admin-owned, ACL secrets.write -> viewer, secrets.read -> custom (A only).
		// Every one also carries the target user's ACL, the acl.revoke target (ACLs
		// are additive, secret_acl.go, so it does not affect any probed principal).
		viewerID, customID := fx.principals[pkViewer].userID, fx.principals[pkCustom].userID
		for n := 1; n <= 3; n++ {
			owner := admin.ID
			if n == 1 {
				owner = viewerID
			}
			name := fmt.Sprintf("s%d", n)
			s := must(c.CreateSecret(ctx, &core.CreateSecretRequest{
				Name: name, Value: []byte(fmt.Sprintf("synthetic-%d-%d", i, n)), ProjectID: pp.projectID, EnvironmentID: pp.envID,
				Type: "password", CreatedBy: "kxadmin", OwnerID: owner,
			}))
			if e := c.GrantSecretACL(ctx, admin.ID, s.ID, target.ID, []string{"secrets.read"}); e != nil {
				return nil, fmt.Errorf("acl fixture s%d: %w", n, e)
			}
			var a models.SecretACL
			if e := db.Where("secret_id = ? AND user_id = ?", s.ID, target.ID).First(&a).Error; e != nil {
				return nil, fmt.Errorf("acl fixture read s%d: %w", n, e)
			}
			pp.secrets[n] = fixtureSecret{id: s.ID, ref: pp.projectName + "/prod/" + name, aclID: a.ID}
			if pp.projectID != fx.A.projectID {
				continue // B: shares/ACLs "off" (probed principals are not members of B)
			}
			switch n {
			case 2:
				for _, sh := range []struct {
					uid  uint
					perm string
				}{{viewerID, "write"}, {customID, "read"}} {
					if _, e := c.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: s.ID, RecipientID: sh.uid, Permission: sh.perm, SharedBy: admin.ID}); e != nil {
						return nil, fmt.Errorf("share fixture: %w", e)
					}
				}
			case 3:
				if e := c.GrantSecretACL(ctx, admin.ID, s.ID, viewerID, []string{"secrets.write"}); e != nil {
					return nil, fmt.Errorf("acl fixture viewer: %w", e)
				}
				if e := c.GrantSecretACL(ctx, admin.ID, s.ID, customID, []string{"secrets.read"}); e != nil {
					return nil, fmt.Errorf("acl fixture custom: %w", e)
				}
			}
		}
	}

	g := must(c.CreateGroup(ctx, admin.ID, &core.CreateGroupRequest{Name: "g-target", Description: "synthetic"}))
	fx.groupID = g.ID
	// two members: removing a group's LAST member is a 409, which would fail
	// the admin positive control for group.member.remove.
	for _, uid := range []uint{target.ID, requesterA.ID} {
		if e := c.AddUserToGroup(ctx, admin.ID, false, uid, g.ID, 0); e != nil {
			return nil, fmt.Errorf("group member fixture: %w", e)
		}
	}
	// project_auditor: deliberately not one of grantRoles, so group.role.assign
	// never collides (409) with the fixture's existing grant.
	if e := c.AssignRoleToGroup(ctx, admin.ID, g.ID, fx.roleIDs["project_auditor"], core.Scope{ProjectID: fx.A.projectID}, false); e != nil {
		return nil, fmt.Errorf("group role fixture: %w", e)
	}
	return fx, nil
}

// newCore builds a core the way the server wires one for these ops: with an
// out-of-band credential-delivery channel (nil deliverer: the setup link is
// returned, never sent) and a synthetic base URL, which invitation and
// setup-link creation require (server/wire_credential_delivery.go does this
// at startup in production).
func newCore(ls *store.LocalStorage) *core.KeyorixCore {
	c := core.NewKeyorixCore(ls)
	c.SetCredentialDelivery(nil, "https://keyorix.example.invalid")
	return c
}

func mustLogin(ctx context.Context, c *core.KeyorixCore, uname string) (string, *models.User) {
	sess, u, err := c.Login(ctx, &core.LoginRequest{Username: uname, Password: fxPassword})
	if err != nil {
		panic(fmt.Errorf("login %s: %w", uname, err))
	}
	return sess.SessionToken, u
}

func mustInvite(inv *models.ProjectInvitation, _ *core.ProvisionSetupResult, err error) (*models.ProjectInvitation, error) {
	if err != nil {
		panic(fmt.Errorf("invitation fixture: %w", err))
	}
	return inv, nil
}

// leg is one freshly-cloned world for ONE layer of ONE case.
type leg struct {
	db     *gorm.DB
	ls     *store.LocalStorage
	c      *core.KeyorixCore
	router http.Handler
	conn   *grpc.ClientConn
	fx     *fixtures
}

type layer string

const (
	layerCore layer = "core"
	layerREST layer = "rest"
	layerGRPC layer = "grpc"
)

// newLeg clones the template and builds exactly the surface the layer needs.
func newLeg(tb testing.TB, l layer) *leg {
	tb.Helper()
	b, fx := template(tb)
	path := filepath.Join(tb.TempDir(), "leg.db")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		tb.Fatalf("clone: %v", err)
	}
	db := fuzzworld.OpenSQLite(tb, path, 1)
	tb.Cleanup(func() {
		if s, e := db.DB(); e == nil {
			_ = s.Close()
		}
	})
	ls := store.NewLocalStorage(db)
	c := newCore(ls)
	lg := &leg{db: db, ls: ls, c: c, fx: fx}
	switch l {
	case layerREST:
		r, err := httpserver.NewRouter(&config.Config{}, c)
		if err != nil {
			tb.Fatalf("router: %v", err)
		}
		lg.router = r
	case layerGRPC:
		srv, err := keyorixgrpc.NewServer(&config.Config{}, c)
		if err != nil {
			tb.Fatalf("grpc server: %v", err)
		}
		lis := bufconn.Listen(1 << 20)
		go func() { _ = srv.Serve(lis) }()
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			tb.Fatalf("grpc dial: %v", err)
		}
		tb.Cleanup(func() { _ = conn.Close(); srv.Stop() })
		lg.conn = conn
	}
	return lg
}

// applyVariation sets the custom role's permission subset (bit i of mask =
// customPermUniverse[i]) and the scope the custom principal and the machine
// hold it at (A, or global for the user; a machine is always project-scoped).
// Goes through the store's mutators so the role->permission cache generation
// moves with the change.
func (lg *leg) applyVariation(tb testing.TB, mask uint16, customGlobal bool) {
	tb.Helper()
	ctx := context.Background()
	fx := lg.fx
	for i, name := range customPermUniverse {
		pid := fx.permIDs[name]
		var err error
		if mask&(1<<i) != 0 {
			err = lg.ls.AssignPermissionToRole(ctx, fx.customRoleID, pid)
		} else {
			err = lg.ls.RemovePermissionFromRole(ctx, fx.customRoleID, pid)
		}
		_ = err // assigning an already-held / removing an absent permission may error; the model reads the result
	}
	if customGlobal {
		cust := fx.principals[pkCustom]
		lg.db.Exec("UPDATE user_roles SET project_id = 0 WHERE user_id = ? AND role_id = ?", cust.userID, fx.customRoleID)
	}
}
