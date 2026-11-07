package authzdiff

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Phase 5 fixtures: the per-project secrets the secret-family ops act on, and
// the users/roles the user-family ops act on. Every one is admin-owned and
// carries no share/ACL for a probed principal unless the comment says so, so the
// reference model's RBAC rule decides them.

// secretFixtures exist once in each of project A and B, all in env "prod".
type secretFixtures struct {
	certID      uint // Type "certificate", value a synthetic self-signed PEM
	deletedID   uint // soft-deleted (restore target)
	suspendedID uint // suspended (resume target)
	multiVerID  uint // two versions (rollback / comment target)
	v1ID        uint // multiVerID's version 1 (SecretVersion.ID)
	commentID   uint // a comment on v1
	depEdgeID   uint // dependency edge: certID depends on multiVerID
	expiringID  uint // expires in 10 days (extend-expiring)
	folderID    uint // a folder in prod (move target)
	targetEnvID uint // live, empty environment "staging2" (copy / clone target)
	shareID     uint // multiVerID shared read -> the ACL recipient
	plainID     uint // a plain admin-owned secret the metadata ops edit
}

// userFixtures are install-wide.
type userFixtures struct {
	acctUserID    uint // active, holds only the CreateUser baseline (system_viewer@global)
	deletedUserID uint // soft-deleted user (restore target)
	opsRoleID     uint // custom role "ops-role" (project scope): secrets.read
	permAddID     uint // permission role.perm.add adds to ops-role (secrets.write)
	permRemoveID  uint // permission role.perm.remove removes from ops-role (secrets.read)
}

func seedSecretFixtures(ctx context.Context, c *core.KeyorixCore, fx *fixtures) error {
	certPEM, err := syntheticCertPEM()
	if err != nil {
		return err
	}
	for i, pp := range []*perProject{&fx.A, &fx.B} {
		mk := func(name, typ string, val []byte, exp *time.Time) (uint, error) {
			s, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
				Name: name, Value: val, ProjectID: pp.projectID, EnvironmentID: pp.envID,
				Type: typ, CreatedBy: "kxadmin", OwnerID: fx.adminID, Expiration: exp,
			})
			if err != nil {
				return 0, fmt.Errorf("secret fixture %s: %w", name, err)
			}
			return s.ID, nil
		}
		sx := &pp.sx
		if sx.certID, err = mk("cert", "certificate", certPEM, nil); err != nil {
			return err
		}
		if sx.deletedID, err = mk("gone", "password", fmt.Appendf(nil, "synthetic-gone-%d", i), nil); err != nil {
			return err
		}
		if err := c.DeleteSecret(ctx, sx.deletedID); err != nil {
			return fmt.Errorf("delete secret fixture: %w", err)
		}
		if sx.suspendedID, err = mk("paused", "password", fmt.Appendf(nil, "synthetic-paused-%d", i), nil); err != nil {
			return err
		}
		if _, err := c.SuspendSecret(ctx, sx.suspendedID, fx.adminID, "synthetic"); err != nil {
			return fmt.Errorf("suspend secret fixture: %w", err)
		}
		if sx.multiVerID, err = mk("multi", "password", fmt.Appendf(nil, "synthetic-v1-%d", i), nil); err != nil {
			return err
		}
		if _, err := c.RotateSecret(ctx, sx.multiVerID, fmt.Appendf(nil, "synthetic-v2-%d", i), fx.adminID, "kxadmin"); err != nil {
			return fmt.Errorf("rotate secret fixture: %w", err)
		}
		vs, err := c.GetSecretVersions(ctx, sx.multiVerID)
		if err != nil {
			return fmt.Errorf("versions fixture: %w", err)
		}
		for _, v := range vs {
			if v.VersionNumber == 1 {
				sx.v1ID = v.ID
			}
		}
		if sx.v1ID == 0 || len(vs) < 2 {
			return fmt.Errorf("versions fixture: want 2 versions with a v1, got %d", len(vs))
		}
		cm, err := c.CreateSecretVersionComment(ctx, core.CreateVersionCommentRequest{
			SecretID: sx.multiVerID, VersionID: sx.v1ID, Comment: "synthetic", UserID: fx.adminID, Username: "kxadmin",
		})
		if err != nil {
			return fmt.Errorf("comment fixture: %w", err)
		}
		sx.commentID = cm.ID
		dep, err := c.AddSecretDependency(ctx, core.ActorTypeUser, fx.adminID, sx.certID, sx.multiVerID, "synthetic", 0)
		if err != nil {
			return fmt.Errorf("dependency fixture: %w", err)
		}
		sx.depEdgeID = dep.ID
		soon := time.Now().UTC().Add(10 * 24 * time.Hour)
		if sx.expiringID, err = mk("expiring", "password", fmt.Appendf(nil, "synthetic-exp-%d", i), &soon); err != nil {
			return err
		}
		f, err := c.CreateFolder(ctx, fx.adminID, "folder", pp.projectID, pp.envID, nil)
		if err != nil {
			return fmt.Errorf("folder fixture: %w", err)
		}
		sx.folderID = f.ID
		env, err := c.CreateEnvironment(ctx, pp.projectID, "staging2")
		if err != nil {
			return fmt.Errorf("target env fixture: %w", err)
		}
		sx.targetEnvID = env.ID
		sh, err := c.ShareSecret(ctx, &core.ShareSecretRequest{SecretID: sx.multiVerID, RecipientID: fx.aclRecipientID, Permission: "read", SharedBy: fx.adminID})
		if err != nil {
			return fmt.Errorf("share fixture: %w", err)
		}
		sx.shareID = sh.ID
		if sx.plainID, err = mk("plain", "password", fmt.Appendf(nil, "synthetic-plain-%d", i), nil); err != nil {
			return err
		}
	}
	return nil
}

func seedUserFixtures(ctx context.Context, c *core.KeyorixCore, fx *fixtures) error {
	mk := func(uname string) (*models.User, error) {
		return c.CreateUser(ctx, &core.CreateUserRequest{Username: uname, Email: uname + "@example.invalid", DisplayName: uname, Password: fxPassword})
	}
	acct, err := mk("u-acct")
	if err != nil {
		return fmt.Errorf("acct user fixture: %w", err)
	}
	fx.ux.acctUserID = acct.ID
	del, err := mk("u-deleted")
	if err != nil {
		return fmt.Errorf("deleted user fixture: %w", err)
	}
	if err := c.DeleteUser(ctx, fx.adminID, del.ID); err != nil {
		return fmt.Errorf("delete user fixture: %w", err)
	}
	fx.ux.deletedUserID = del.ID
	fx.ux.permRemoveID, fx.ux.permAddID = fx.permIDs["secrets.read"], fx.permIDs["secrets.write"]
	r, _, err := c.CreateRoleWithScope(ctx, fx.adminID, "ops-role", "synthetic", []uint{fx.ux.permRemoveID}, "project")
	if err != nil {
		return fmt.Errorf("ops-role fixture: %w", err)
	}
	fx.ux.opsRoleID = r.ID
	fx.roleIDs[r.Name] = r.ID
	return nil
}

// syntheticCertPEM is a throwaway self-signed certificate generated at seed
// time (never stored in the tree), valid 2000-2099 so it cannot clock-bomb.
func syntheticCertPEM() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "authzdiff.example.invalid"},
		NotBefore:    time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
