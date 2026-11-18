package authzdiff

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	pkSuspended   principalKind = "suspended" // project_admin@A, account suspended after login
	pkPAT         principalKind = "pat-restricted"
	// pkPATFull is a PAT whose owner holds roles.assign plus full coverage of the
	// target machine's permissions, but whose token carries a least-privilege
	// permission allowlist that still includes the op's own gate. Unlike pkPAT
	// (restricted to secrets.read, which fails the roles.assign gate), it passes
	// the gate AND the target-coverage ceiling, so machine.token.issue reaches the
	// #4332 restricted-PAT refusal (machine_token.go) as the SOLE denier — the one
	// path that exercises the model's `if p.pat != nil` line on a token-mint.
	pkPATFull principalKind = "pat-full-coverage"
	// pkRequester is the author of project A's pending access request. Not a
	// probed principal: it is the positive control for requester-only ops
	// (accessrequest.withdraw), whose rule no other principal can satisfy.
	pkRequester principalKind = "requester-A"
)

// namedPrincipalKinds are the fixed principals, each testing a mechanism a
// permission set cannot express (no role, built-in/admin roles, expiry, actor
// 0, account state, PAT restriction). The custom-role and machine principals
// are NOT here: their permission sets are generated per operation
// (genVariations), replacing the old hand-picked subsets.
var namedPrincipalKinds = []principalKind{pkNone, pkViewer, pkProjAdmin, pkGlobalAdmin, pkActor0, pkExpired, pkSuspended, pkPAT, pkPATFull}

// allPrincipalKinds is every principal the fuzz target may pick.
var allPrincipalKinds = []principalKind{pkNone, pkViewer, pkProjAdmin, pkGlobalAdmin, pkCustom, pkMachine, pkActor0, pkExpired, pkSuspended, pkPAT, pkPATFull}

type principal struct {
	kind            principalKind
	userID          uint
	machineID       uint
	token           string
	username        string
	systemActor     bool // actor id 0: core only (ID-1)
	unauthenticated bool
	suspended       bool                 // account suspended (model: denied everywhere)
	pat             *core.PATRestriction // non-nil: the token is a restricted PAT
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
	deletedEnvID     uint   // soft-deleted environment (env.restore target)
	oidcBindingID    uint   // OIDC binding on machineID (oidc.delete target)
	migrateUsername  string // a user migrate-from-user may convert (keep_user=true)
	machineRoleID    uint   // role held by machineID at this project (role.remove target)
	// breakGlassActivationID is an ACTIVE break-glass activation in this project
	// (activated by u-bg, a dedicated member), the breakglass.revoke target (V5EXT).
	breakGlassActivationID uint

	// V5EXT2: access-review and break-glass review fixtures.
	//
	// accessReviewDecision is a decision for u-target's project_viewer grant at
	// this project, used by accessreview.attest and accessreview.revoke. The
	// reviewer (any probed principal) is never u-target, so reviewer-independence
	// always passes.
	accessReviewDecision core.AccessReviewDecision

	// campaignProjectID is a minimal project (only u-target, project_viewer) for
	// campaign.decide and campaign.close. Using A/B directly brings in many
	// principals, complicating the fully-decided state for closeCampaignID.
	campaignProjectID uint

	// decideCampaignID is an open campaign on campaignProjectID with one pending
	// item (u-target's project_viewer grant). The reviewer (any probed principal)
	// is never u-target → reviewer-independence always passes.
	decideCampaignID     uint
	decideCampaignItemID uint

	// closeCampaignID is an open campaign on campaignProjectID with 0 pending
	// items (u-target's item was pre-decided by admin). Close with force=false
	// succeeds for any roles.assign@campaignProjectID holder.
	closeCampaignID uint

	// reviewBGActivationID is a REVOKED break-glass activation (activated by u-bg,
	// then revoked by admin in the seed). Different from breakGlassActivationID
	// (which is ACTIVE). ReviewBreakGlass requires the activation to be concluded
	// and the reviewer to be independent of the activator (u-bg).
	reviewBGActivationID uint

	sx secretFixtures
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
	customGroupID    uint // g-custom: the custom user is its only member; holds the custom role on the "group" route
	deletedGroupID   uint // soft-deleted group holding project_viewer@A (group.restore target)
	projCID          uint // soft-deleted project (project.restore target)
	freshUserID      uint // no role, no membership anywhere (invite/add-member target)
	freshUserID2     uint // a second one (membership.invite vs member.add must not collide)
	requesterIDs     [2]uint
	ux               userFixtures
	// pendingRiskExceptionID is a global, PENDING, non-SoD risk exception whose
	// creator (riskCreatorID) is a dedicated non-probed user. It is the target of
	// the riskexception.approve binding (V8b): dual control (creator != approver,
	// human-only) is satisfied for every probed principal by construction, so the
	// only authorization that varies by principal is the router's system.write@global
	// gate. See v8RiskExceptionApproveOps.
	pendingRiskExceptionID uint
	riskCreatorID          uint
	// riskExceptionID is a governed risk acceptance created by the NON-probed
	// u-risk-creator, left un-approved and un-revoked: the riskexception.delete
	// target (V5EXT). riskexception.approve is bound by V8b on
	// pendingRiskExceptionID.
	riskExceptionID uint
}

func (f *fixtures) proj(sel byte) *perProject {
	if sel%2 == 1 {
		return &f.B
	}
	return &f.A
}

// customPermUniverse is the permission set generated permission sets are drawn
// from: every catalog permission a covered op gates on or a grantable role
// bundles (project_auditor carries audit.read), plus system.read/system.write as
// distractors. A requirement outside it fails TestRequirementsWithinUniverse.
var customPermUniverse = []string{
	"secrets.read", "secrets.write", "secrets.delete", "secrets.manage",
	"users.read", "users.write", "users.delete", "roles.read", "roles.write", "roles.assign",
	"audit.read", "system.read", "system.write",
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
	defer func() { _ = os.RemoveAll(dir) }()
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

	// suspended: project_admin@A, logged in, THEN suspended (the session token is
	// whatever suspension leaves of it — the transports decide).
	susp := addUserPrincipal(pkSuspended, "p-suspended")
	grant(susp.userID, fx.roleIDs["project_admin"], fx.A.projectID, nil)
	if e := c.SuspendUser(ctx, admin.ID, susp.userID); e != nil {
		return nil, fmt.Errorf("suspend fixture: %w", e)
	}
	susp.suspended = true

	// PAT-restricted: owner is project_admin@A; the PAT allows only secrets.read
	// in project A (rules.PATRestriction).
	patOwner := addUserPrincipal(pkPAT, "p-pat")
	grant(patOwner.userID, fx.roleIDs["project_admin"], fx.A.projectID, nil)
	pr := must(c.CreateOwnPAT(ctx, patOwner.userID, "restricted", nil, []string{"secrets.read"}, fx.A.projectID, 0, nil))
	patOwner.token = pr.PlainToken
	patOwner.pat = &core.PATRestriction{Permissions: []string{"secrets.read"}, ProjectID: fx.A.projectID}

	// PAT-full-coverage: owner is project_admin at BOTH projects, so it fully
	// covers either target machine's project_auditor role (and holds
	// roles.assign). The PAT is confined to a least-privilege permission allowlist
	// that still includes machine.token.issue's own gate (roles.assign) and the
	// target's permissions — so, unlike pkPAT, it PASSES the gate and the
	// target-coverage ceiling. It carries NO project/environment/CIDR confinement:
	// a CIDR restriction is enforced fail-closed at the transports against the
	// request source IP, which the bufconn gRPC leg cannot supply, and an
	// environment restriction is denied at the project-level roles.assign gate
	// itself — so neither can reach the #4332 refusal on all three layers, whereas
	// a permission allowlist that Allows the gate does (and is modelled by
	// PATRestriction.Allows). The result: machine.token.issue is denied ONLY by
	// the restricted-PAT refusal (machine_token.go), the one path exercising the
	// model's `if p.pat != nil` token-mint line. See model_test.go / plants_test.go
	// (fix-4332-pat-refusal-removed) and the HF3 report for the full analysis.
	patFullScopes := []string{"roles.assign", "secrets.read", "users.read", "audit.read"}
	patFull := addUserPrincipal(pkPATFull, "p-pat-full")
	grant(patFull.userID, fx.roleIDs["project_admin"], fx.A.projectID, nil)
	grant(patFull.userID, fx.roleIDs["project_admin"], fx.B.projectID, nil)
	prFull := must(c.CreateOwnPAT(ctx, patFull.userID, "full-coverage", nil, patFullScopes, 0, 0, nil))
	patFull.token = prFull.PlainToken
	patFull.pat = &core.PATRestriction{Permissions: patFullScopes}

	// g-custom: the "group" route of a generated permission set.
	gc := must(c.CreateGroup(ctx, admin.ID, &core.CreateGroupRequest{Name: "g-custom", Description: "synthetic"}))
	fx.customGroupID = gc.ID
	if e := c.AddUserToGroup(ctx, admin.ID, false, cust.userID, gc.ID, 0); e != nil {
		return nil, fmt.Errorf("custom group fixture: %w", e)
	}

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
	// ---- Phase 4 fixtures (families coverage) ----
	fx.requesterIDs = [2]uint{requesterA.ID, requesterB.ID}
	reqTok, _ := mustLogin(ctx, c, "u-req-a")
	fx.principals[pkRequester] = &principal{kind: pkRequester, userID: requesterA.ID, token: reqTok, username: "u-req-a"}
	fx.freshUserID = mkUser("u-fresh").ID
	fx.freshUserID2 = mkUser("u-fresh2").ID
	db.Exec("DELETE FROM user_roles WHERE user_id IN (?, ?)", fx.freshUserID, fx.freshUserID2)

	gd := must(c.CreateGroup(ctx, admin.ID, &core.CreateGroupRequest{Name: "g-deleted", Description: "synthetic"}))
	if e := c.AssignRoleToGroup(ctx, admin.ID, gd.ID, fx.roleIDs["project_viewer"], core.Scope{ProjectID: fx.A.projectID}, false); e != nil {
		return nil, fmt.Errorf("deleted-group role: %w", e)
	}
	if e := c.DeleteGroup(ctx, admin.ID, gd.ID); e != nil {
		return nil, fmt.Errorf("delete group fixture: %w", e)
	}
	fx.deletedGroupID = gd.ID

	pc := must(ls.CreateProject(ctx, &models.Project{Name: "projc"}))
	if e := c.DeleteProject(ctx, admin.ID, pc.ID, true); e != nil {
		return nil, fmt.Errorf("delete project fixture: %w", e)
	}
	fx.projCID = pc.ID

	for i, pp := range []*perProject{&fx.A, &fx.B} {
		env := must(c.CreateEnvironment(ctx, pp.projectID, "staging"))
		if e := c.DeleteEnvironment(ctx, env.ID); e != nil {
			return nil, fmt.Errorf("delete env fixture: %w", e)
		}
		pp.deletedEnvID = env.ID
		pp.machineRoleID = fx.roleIDs["project_auditor"] // not a grantRoles choice: machine.role.assign must not 409
		if e := c.AssignMachineRole(ctx, pp.machineID, pp.machineRoleID, core.Scope{ProjectID: pp.projectID}, admin.ID, false); e != nil {
			return nil, fmt.Errorf("target machine role fixture: %w", e)
		}
		b := must(c.CreateOIDCBinding(ctx, pp.projectID, pp.machineID, "https://issuer.example.invalid", fmt.Sprintf("subject-%d", i), admin.ID))
		pp.oidcBindingID = b.ID
		pp.migrateUsername = fmt.Sprintf("u-mig-%d", i)
		mkUser(pp.migrateUsername)
	}
	// Pending risk exception for the riskexception.approve binding (V8b). Created
	// through core (CreateRiskException performs NO permission check — matrix
	// core_refusal:"none" — it enforces only human-only + a bounded sunset + the
	// SoD-live-violation check for category=="sod"), so a plain human user with no
	// role can leave a pending, non-SoD exception. The creator is a DEDICATED user,
	// NOT any probed principal and NOT the admin: so the dual-control rule
	// (actorID != CreatedBy) and the human-only rule are satisfied for every
	// principal the approve binding probes, and the only authorization that varies
	// is the router's system.write@global gate. The admin positive control holds
	// system.write@global (install-wide admin) and is a different human, so it
	// approves successfully.
	riskCreator := mkUser("u-risk-creator")
	db.Exec("DELETE FROM user_roles WHERE user_id = ?", riskCreator.ID) // no role: proves create needs none
	fx.riskCreatorID = riskCreator.ID
	re := must(c.CreateRiskException(ctx, riskCreator.ID, false,
		"synthetic-pending-title", "other", "synthetic-ref", "synthetic-justification-text",
		time.Now().UTC().Add(24*time.Hour)))
	fx.pendingRiskExceptionID = re.ID

	if e := seedSecretFixtures(ctx, c, fx); e != nil {
		return nil, e
	}
	if e := seedUserFixtures(ctx, c, fx); e != nil {
		return nil, e
	}

	// ---- V5EXT fixtures (risk-exception approve/delete, break-glass revoke) ----
	//
	// A risk exception created by a NON-probed user (u-risk-creator), left
	// un-approved and un-revoked. riskexception.approve is gated system.write@global
	// at the router and refuses the creator (dual control, core); keeping the
	// creator out of the probed set makes the self-approval rule never fire for a
	// probed principal, so the oracle sees only the router gate. riskexception.delete
	// is gated system.write@global at the router, but core independently enforces
	// creator-OR-admin-tier (core_refusal:"typed"); with a non-probed creator the
	// effective gate for every probed principal is an admin role at global scope,
	// which the model's globalAdminRole requirement expresses.
	reDel := must(c.CreateRiskException(ctx, riskCreator.ID, false,
		"synthetic-fixture-exception", "other", "synthetic-ref", "synthetic-justification-text",
		riskExceptionExpiry()))
	fx.riskExceptionID = reDel.ID

	// An ACTIVE break-glass activation per project, activated by a dedicated
	// member (u-bg: project_viewer@A and @B). The emergency-role grant the
	// activation creates lands on u-bg, which no probed principal is, so it
	// perturbs no other fixture. breakglass.revoke (roles.assign@project at the
	// REST router AND the gRPC interceptor; core_refusal:"none") acts on it.
	bgUser := mkUser("u-bg")
	grant(bgUser.ID, fx.roleIDs["project_viewer"], fx.A.projectID, nil)
	grant(bgUser.ID, fx.roleIDs["project_viewer"], fx.B.projectID, nil)
	for _, pp := range []*perProject{&fx.A, &fx.B} {
		act := must(c.ActivateBreakGlass(ctx, pp.projectID, bgUser.ID, "emergency-access-justification-fixture", ""))
		pp.breakGlassActivationID = act.ID
	}

	// ---- V5EXT2 fixtures (access-review attest/revoke, campaign decide/close, break-glass review) ----
	//
	// accessReviewDecision: u-target has project_viewer@A and @B (seeded above).
	// The decision body references u-target's role grant — not a probed principal,
	// so reviewer-independence always passes for any probed reviewer.
	for _, pp := range []*perProject{&fx.A, &fx.B} {
		pp.accessReviewDecision = core.AccessReviewDecision{
			Source:        "role",
			PrincipalType: "user",
			PrincipalID:   fx.targetUserID,
			RoleID:        fx.roleIDs["project_viewer"],
		}
	}

	// Campaign projects: a minimal project per A/B with only u-target as
	// project_viewer. Using A/B directly brings in many principals (including the
	// admin), complicating the fully-decided state for closeCampaignID. The
	// campaign project allows the admin to decide u-target's one item without any
	// self-certification issue, leaving the close campaign with 0 pending items.
	for i, pp := range []*perProject{&fx.A, &fx.B} {
		campProj := must(ls.CreateProject(ctx, &models.Project{Name: fmt.Sprintf("projcamp-%d", i)}))
		must(ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: campProj.ID}))
		grant(fx.targetUserID, fx.roleIDs["project_viewer"], campProj.ID, nil)
		pp.campaignProjectID = campProj.ID

		// decide-campaign: open with one pending item (u-target's project_viewer@campProj).
		decideCamp := must(c.OpenAccessReviewCampaign(ctx, admin.ID, 0, campProj.ID, "decide-campaign"))
		pp.decideCampaignID = decideCamp.Campaign.ID
		decideDetail := must(c.GetAccessReviewCampaign(ctx, campProj.ID, decideCamp.Campaign.ID))
		for _, item := range decideDetail.Items {
			if item.PrincipalID == fx.targetUserID {
				pp.decideCampaignItemID = item.ID
				break
			}
		}
		if pp.decideCampaignItemID == 0 {
			return nil, fmt.Errorf("seed: no pending item for u-target in decide-campaign for proj %d", campProj.ID)
		}

		// close-campaign: open with one pending item, then admin decides it (attest).
		// With force=false, close succeeds for any roles.assign@campaignProjectID holder.
		closeCamp := must(c.OpenAccessReviewCampaign(ctx, admin.ID, 0, campProj.ID, "close-campaign"))
		pp.closeCampaignID = closeCamp.Campaign.ID
		closeDetail := must(c.GetAccessReviewCampaign(ctx, campProj.ID, closeCamp.Campaign.ID))
		for _, item := range closeDetail.Items {
			if err := c.DecideAccessReviewItem(ctx, admin.ID, campProj.ID, closeCamp.Campaign.ID, item.ID, "attest", ""); err != nil {
				return nil, fmt.Errorf("seed: pre-decide close-campaign item: %w", err)
			}
		}
	}

	// break-glass review: a REVOKED activation per project. ReviewBreakGlass
	// refuses a still-active activation (and bgUser already has one via
	// breakGlassActivationID above), so we use a second dedicated member u-bg2.
	// Activated then immediately revoked by admin — leaves a REVOKED state. Every
	// probed principal passes reviewer-independence (none is u-bg2).
	bg2User := mkUser("u-bg2")
	grant(bg2User.ID, fx.roleIDs["project_viewer"], fx.A.projectID, nil)
	grant(bg2User.ID, fx.roleIDs["project_viewer"], fx.B.projectID, nil)
	for _, pp := range []*perProject{&fx.A, &fx.B} {
		reviewAct := must(c.ActivateBreakGlass(ctx, pp.projectID, bg2User.ID, "emergency-access-justification-review-fixture-seed", ""))
		if err := c.RevokeBreakGlass(ctx, admin.ID, 0, pp.projectID, reviewAct.ID); err != nil {
			return nil, fmt.Errorf("seed: revoke break-glass review fixture: %w", err)
		}
		pp.reviewBGActivationID = reviewAct.ID
	}

	// Resend is throttled per (purpose, email) on setup-token age; backdate the
	// seeded tokens so the copies are never inside the 60s window.
	db.Exec("UPDATE setup_tokens SET created_at = ?", time.Now().UTC().Add(-2*time.Hour))

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
	// Self-service emergency access, wired the way the server does from config
	// (server start → SetBreakGlassPolicy). Enabled with a CONTAINED emergency
	// role (project_developer: no roles.assign, not admin-bypass — the role
	// config_access.go's own comment names as the safe choice), so the
	// break-glass activate binding (v5) exercises core's real gate
	// (ErrBreakGlassDisabled would otherwise mask it). Disabled cores still exist
	// nowhere the harness probes — no bound op reads this policy except
	// breakglass.activate.
	c.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: "project_developer", DefaultTTL: time.Hour, MaxTTL: time.Hour,
	})
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

	closers   []func()
	closeOnce sync.Once
}

type layer string

const (
	layerCore layer = "core"
	layerREST layer = "rest"
	layerGRPC layer = "grpc"
)

// legsCreated counts newLeg calls in this test binary; the sweep logs it next
// to the template size so the bytes cloned per sweep can be computed
// (legs x template bytes) without fs tracing.
var legsCreated atomic.Int64

// newLeg clones the template and builds exactly the surface the layer needs.
func newLeg(tb testing.TB, l layer) *leg {
	tb.Helper()
	b, fx := template(tb)
	legsCreated.Add(1)
	// Each leg owns a private in-memory database restored from the template
	// image (nothing touches the disk: a file copy per leg wrote ~1 MB x
	// 166k legs per sweep) and is released by close() as soon as its case
	// ends — NOT at the end of the (parallel) op subtest, which would let
	// thousands of database copies accumulate at once.
	db := fuzzworld.OpenSQLiteFromImage(tb, b)
	ls := store.NewLocalStorage(db)
	c := newCore(ls)
	lg := &leg{db: db, ls: ls, c: c, fx: fx}
	lg.closers = append(lg.closers, func() {
		if s, e := db.DB(); e == nil {
			_ = s.Close()
		}
	})
	// Deliberately NO tb.Cleanup(lg.close) fallback: a cleanup closure keeps the
	// whole leg (router, core, DB handle) reachable until the op subtest ends,
	// which retained ~0.3 MB per REST leg and got long sweeps killed under
	// memory pressure. Every caller closes its leg explicitly.
	switch l {
	case layerREST:
		// NewRouter re-points package-level handler globals (handlers.InitCoreHandlers
		// sets defaultUserHandler); routerMu keeps that from racing a globalHandler
		// op's request on another leg (see runLayer).
		routerMu.Lock()
		r, err := httpserver.NewRouter(&config.Config{}, c)
		routerMu.Unlock()
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
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithUnaryInterceptor(recordRPC))
		if err != nil {
			tb.Fatalf("grpc dial: %v", err)
		}
		// stop the server before the DB closes (closers run in reverse order)
		lg.closers = append(lg.closers, func() { _ = conn.Close(); srv.Stop() })
		lg.conn = conn
	}
	return lg
}

// close releases the leg's server, database and files. Idempotent.
func (lg *leg) close() {
	lg.closeOnce.Do(func() {
		for _, c := range slices.Backward(lg.closers) {
			c()
		}
	})
}

// variation is how the custom role is held for one case: its permission set
// (bit i of Mask = customPermUniverse[i]), the grant route, and the scope.
//
//   - Route "user": the custom user holds it directly (user_roles).
//   - Route "group": the custom user holds it only via g-custom (group_roles).
//   - Route "machine": the machine principal holds it (machine_identity_roles);
//     never at global scope (a machine role is always project-scoped).
//
// Named principals run with defaultVariation (custom user, all permissions, at
// A) — that only matters for ops that grant the custom role itself.
type variation struct {
	Mask  uint16 `json:"mask"`
	Route string `json:"route"`
	Scope string `json:"scope"` // "global" | "A" | "B"
}

var allPerms = uint16(1<<len(customPermUniverse) - 1)

var defaultVariation = variation{Mask: allPerms, Route: "user", Scope: "A"}

// scopeProject maps a variation scope token to its project. Besides "A"/"B"/
// "global", a token "A@prod"/"A@stg" (and the B forms) names a project PLUS an
// environment (see scopeEnv) — the project part is the same "A"/"B".
func (fx *fixtures) scopeProject(s string) uint {
	switch scopeProjectToken(s) {
	case "A":
		return fx.A.projectID
	case "B":
		return fx.B.projectID
	}
	return 0
}

// scopeProjectToken strips an "@env" suffix, leaving the project token.
func scopeProjectToken(s string) string {
	proj, _, _ := strings.Cut(s, "@")
	return proj
}

// scopeEnv maps an environment-scoped variation token to its environment id. A
// token with no "@env" suffix is project-wide (environment 0, the wildcard).
//
//	"<proj>@prod" -> that project's prod environment (perProject.envID)
//	"<proj>@stg"  -> that project's second environment ("staging2", sx.targetEnvID)
func (fx *fixtures) scopeEnv(s string) uint {
	_, env, found := strings.Cut(s, "@")
	if !found {
		return 0
	}
	pp := &fx.A
	if scopeProjectToken(s) == "B" {
		pp = &fx.B
	}
	switch env {
	case "prod":
		return pp.envID
	case "stg":
		return pp.sx.targetEnvID
	}
	return 0
}

// applyVariation installs v. Role permissions go through the store's mutators
// so the role->permission cache generation moves with the change; the grant
// rows are written directly (synthetic fixture state, read back by the model).
func (lg *leg) applyVariation(tb testing.TB, v variation) {
	tb.Helper()
	ctx := context.Background()
	fx := lg.fx
	for i, name := range customPermUniverse {
		pid := fx.permIDs[name]
		var err error
		if v.Mask&(1<<i) != 0 {
			err = lg.ls.AssignPermissionToRole(ctx, fx.customRoleID, pid)
		} else {
			err = lg.ls.RemovePermissionFromRole(ctx, fx.customRoleID, pid)
		}
		_ = err // assigning an already-held / removing an absent permission may error; the model reads the result
	}
	proj := fx.scopeProject(v.Scope)
	env := fx.scopeEnv(v.Scope) // non-zero only for an "@prod"/"@stg" token (V5b)
	cust := fx.principals[pkCustom]
	lg.db.Exec("DELETE FROM user_roles WHERE user_id = ? AND role_id = ?", cust.userID, fx.customRoleID)
	lg.db.Exec("DELETE FROM group_roles WHERE group_id = ?", fx.customGroupID)
	switch v.Route {
	case "user":
		if e := lg.db.Create(&models.UserRole{UserID: cust.userID, RoleID: fx.customRoleID, ProjectID: proj, EnvironmentID: env}).Error; e != nil {
			tb.Fatalf("variation user grant: %v", e)
		}
	case "group":
		if e := lg.db.Create(&models.GroupRole{GroupID: fx.customGroupID, RoleID: fx.customRoleID, ProjectID: proj, EnvironmentID: env}).Error; e != nil {
			tb.Fatalf("variation group grant: %v", e)
		}
	case "machine":
		if proj == 0 {
			tb.Fatalf("variation: a machine role cannot be global")
		}
		lg.db.Exec("UPDATE machine_identity_roles SET project_id = ?, environment_id = ? WHERE machine_identity_id = ? AND role_id = ?", proj, env, fx.principals[pkMachine].machineID, fx.customRoleID)
	}
}

// rpcRecorder, when set, receives the full method name of every unary RPC a
// leg's client makes. Coverage uses it to DERIVE which gRPC operations an op
// exercises, instead of hand-listing them.
var (
	rpcRecorderMu sync.Mutex
	rpcRecorder   func(method string)
)

func recordRPC(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	rpcRecorderMu.Lock()
	rec := rpcRecorder
	rpcRecorderMu.Unlock()
	if rec != nil {
		rec(method)
	}
	return invoker(ctx, method, req, reply, cc, opts...)
}

// routerMu serialises router construction with globalHandler requests.
// server/http/handlers keeps one package-level handler for the /users routes
// (defaultUserHandler, set by InitCoreHandlers from every NewRouter). Production
// builds one router, so it is harmless there; with one router per leg, a /users
// request could otherwise be served by whichever leg's core was wired last.
var routerMu sync.Mutex
