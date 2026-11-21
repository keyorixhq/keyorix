// local_secret_acl.go — SecretACL persistence (RBAC Phase 3).
// Each row grants a specific user access to one secret, independently of project RBAC.
// For the remote equivalent see remote_secret_acl.go.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// CreateOrUpdateSecretACL upserts a SecretACL row on the (secret_id, user_id) unique index.
//
// #2649: the upsert and a lockLiveParent re-read of the live secret node (FOR SHARE on
// Postgres) run in one transaction, which rolls back if the node is gone. Without it, a
// DeleteSecret committing between the caller's liveness check and this upsert ran its
// CWE-284 ACL cascade before the grant existed, and the grant then committed on the
// deleted secret and reactivated on RestoreSecret (INV-STORE-21).
//
// #4533: the same transaction also re-checks that the grantee is still a member of the
// node's project (storage.ErrSecretACLGranteeNotMember when not). The second variant
// of #2649: RemoveProjectMember's CWE-284 cascade (DeleteSecretACLsByUserAndProject)
// committing between the caller's membership check and this upsert never saw the
// grant, which then committed for a removed member and came back live on re-add.
//
// The order is: lock the grantee's live direct grants at the project FOR SHARE
// (lockDirectProjectGrants), write, lock the node, then ask the membership question.
// The membership lock comes FIRST because RemoveProjectMember locks in the same order
// (it DELETEs the user_roles rows before it touches owned secret_nodes and the ACL
// rows). Taken after the write instead (REVIEW-4557-DEEP-1 MEDIUM-1), it closed a
// cycle on Postgres: a re-grant held the existing ACL row (or, for a grantee who owns
// the secret, the node FOR SHARE) and waited for user_roles while the removal held
// user_roles and waited for that row, and the deadlock detector could abort the
// removal. The check still comes after the write, for the reason lockLiveParent's doc
// gives: a check before the write misses a removal that runs entirely between the two.
func (ls *LocalStorage) CreateOrUpdateSecretACL(ctx context.Context, acl *models.SecretACL) error {
	// UTC: the model has no BeforeSave hook, so a caller-set time would be stored in its own zone.
	acl.CreatedAt, acl.UpdatedAt = acl.CreatedAt.UTC(), acl.UpdatedAt.UTC()
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		projectID, found, err := secretNodeProjectID(tx, acl.SecretID)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		if !found {
			return fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		now := ls.rbacEffectiveNow(time.Now().UTC())
		if err := lockDirectProjectGrants(tx, acl.UserID, projectID, now); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		result := tx.
			Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "secret_id"}, {Name: "user_id"}},
				DoUpdates: clause.AssignmentColumns([]string{"permissions", "granted_by", "updated_at"}),
			}).
			Create(acl)
		if result.Error != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
		}
		live, err := lockLiveParent(tx, &models.SecretNode{}, sqlWhereID, acl.SecretID)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		if !live {
			return fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		// The node is locked FOR SHARE now, so its project_id cannot move under this
		// read. The membership lock above was taken for the project read before the
		// node lock: refuse rather than check membership of a project that lock did
		// not cover (MoveSecret is a project-internal move, but the argument should
		// not depend on that).
		lockedProjectID, found, err := secretNodeProjectID(tx, acl.SecretID)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		if !found {
			return fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		if lockedProjectID != projectID {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), errSecretACLProjectMoved)
		}
		member, err := ls.isProjectMemberOn(tx, acl.UserID, projectID)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		if !member {
			return fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), storage.ErrSecretACLGranteeNotMember)
		}
		return nil
	})
}

// errSecretACLProjectMoved: the secret's project changed between the read the
// membership lock was taken for and the node lock. Not reachable through MoveSecret
// today (a project-internal move); the grant is rolled back.
var errSecretACLProjectMoved = errors.New("the secret's project changed while the grant was being written")

// secretNodeProjectID reads the live node's project_id through tx (found is false when
// the node does not exist or is soft-deleted).
func secretNodeProjectID(tx *gorm.DB, secretID uint) (projectID uint, found bool, err error) {
	var projectIDs []uint
	if err := tx.Model(&models.SecretNode{}).Where(sqlWhereID, secretID).Limit(1).
		Pluck("project_id", &projectIDs).Error; err != nil {
		return 0, false, err
	}
	if len(projectIDs) != 1 {
		return 0, false, nil
	}
	return projectIDs[0], true, nil
}

// lockDirectProjectGrants takes SELECT ... FOR SHARE on the user_roles rows of
// (userID, projectID) that are live at now, inside tx: the membership counterpart of
// lockLiveParent, for a child (an ACL grant) whose "parent" is the grantee's project
// membership rather than a soft-deletable row. On SQLite there is no row lock and the
// write transaction alone serializes (single process), the same split lockLiveParent
// makes.
//
// Why it is sound (READ COMMITTED). RemoveProjectMember's transaction DELETEs these
// rows (RemoveAllProjectRoleGrants) BEFORE it clears owned secrets and runs its ACL
// cascade (DeleteSecretACLsByUserAndProject). Called BEFORE the caller's ACL write and
// node lock, with the membership check after both:
//   - the removal's DELETE ran first: this read blocks until the removal commits, then
//     sees no live rows (Postgres re-checks the WHERE against the committed version),
//     and the membership check after the write refuses and rolls the write back;
//   - this read ran first: the removal's DELETE blocks until this transaction commits,
//     so its later cascade statement (a fresh snapshot) sees the committed ACL row and
//     sweeps it;
//   - the grantee had no live direct rows: nothing is locked, and the membership check
//     after the write decides.
//
// Both transactions take user_roles first, so neither can hold the ACL row or the node
// while it waits for the other's user_roles (REVIEW-4557-DEEP-1 MEDIUM-1: the deadlock
// the lock-after-write order had). Expired rows are not locked: they confer no
// membership, so a removal deleting one has nothing to be ordered against.
//
// What it does NOT cover: a grantee who is a member only through a group. Those rows
// are not touched by RemoveProjectMember (which refuses a group-only member as not a
// member), and a group-membership removal has no ACL cascade at all; that is a
// separate, pre-existing gap, not this race.
func lockDirectProjectGrants(tx *gorm.DB, userID, projectID uint, now time.Time) error {
	if tx.Dialector.Name() != "postgres" {
		return nil
	}
	var ids []uint
	if err := tx.Model(&models.UserRole{}).
		Where("user_id = ? AND project_id = ?", userID, projectID).
		Where(sqlWhereURNotExpired, now.UTC()).
		Clauses(clause.Locking{Strength: "SHARE"}).
		Pluck("role_id", &ids).Error; err != nil {
		return fmt.Errorf("failed to lock the grantee's project grants: %w", err)
	}
	return nil
}

// ListSecretACLs returns all ACL grants for the given secret.
func (ls *LocalStorage) ListSecretACLs(ctx context.Context, secretID uint) ([]*models.SecretACL, error) {
	var rows []*models.SecretACL
	if err := ls.db.WithContext(ctx).Where("secret_id = ?", secretID).Order(sqlOrderIDAsc).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// ListSecretACLsByUser returns all ACL rows for the given user across all secrets.
func (ls *LocalStorage) ListSecretACLsByUser(ctx context.Context, userID uint) ([]*models.SecretACL, error) {
	var rows []*models.SecretACL
	if err := ls.db.WithContext(ctx).Where("user_id = ?", userID).Order(sqlOrderIDAsc).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// GetSecretACL returns the ACL for the given (secret, user) pair. A missing row
// wraps storage.ErrSecretACLNotFound (same text as before: gorm's "record not
// found"); any other failure (DB outage, cancelled context) is a retrieval failure
// that does NOT match it, so the authorization check cannot read an outage as "no
// grant" (ERRLOSS-ACL-1).
func (ls *LocalStorage) GetSecretACL(ctx context.Context, secretID, userID uint) (*models.SecretACL, error) {
	var row models.SecretACL
	if err := ls.db.WithContext(ctx).Where("secret_id = ? AND user_id = ?", secretID, userID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), storage.ErrSecretACLNotFound)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &row, nil
}

// DeleteSecretACL deletes the ACL row with the given ID.
func (ls *LocalStorage) DeleteSecretACL(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.SecretACL{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

// DeleteSecretACLsByUserAndProject removes all ACL grants for userID on secrets
// that belong to projectID. Used by RemoveProjectMember to prevent stale
// per-secret ACL grants from persisting after a user is offboarded (CWE-284).
func (ls *LocalStorage) DeleteSecretACLsByUserAndProject(ctx context.Context, userID, projectID uint) error {
	result := ls.db.WithContext(ctx).
		Where("user_id = ? AND secret_id IN (SELECT id FROM secret_nodes WHERE project_id = ?)", userID, projectID).
		Delete(&models.SecretACL{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return nil
}
