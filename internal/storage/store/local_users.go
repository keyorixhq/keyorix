// local_users.go — User and Group operations for LocalStorage.
//
// Covers: CreateUser, GetUser, GetUserByEmail, GetUserByUsername, UpdateUser,
//
//	DeleteUser, RestoreUser, ListUsers, GetUserGroups,
//	CreateGroup, GetGroup, UpdateGroup, DeleteGroup, ListGroups,
//	AddUserToGroup, RemoveUserFromGroup, ListGroupMembers.
//
// All operations use direct GORM queries.
// For the remote (HTTP) equivalent see remote_users.go.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// likeEscaper escapes the LIKE/ILIKE metacharacters so a user-supplied search term is
// matched literally, not as a wildcard. Paired with an explicit ESCAPE '\' clause.
var likeEscaper = strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`)

// escapeLike neutralizes %, _, and \ in a user search string so `?q=%` can't turn the
// filter into a match-all / full-table scan.
func escapeLike(s string) string { return likeEscaper.Replace(s) }

// isDuplicateEmailViolation reports whether err is a unique-constraint violation on
// specifically the partial users-email index (uniq_users_email_active, #117), as
// distinct from any other unique constraint on the users table (e.g. the username
// index) or elsewhere. Both SQLite and Postgres include the violated index/constraint
// name in the driver-native error text for an expression index like this one (SQLite:
// `UNIQUE constraint failed: index 'uniq_users_email_active'`; Postgres: `duplicate key
// value violates unique constraint "uniq_users_email_active"`), so matching the index
// name — rather than the generic isUniqueViolation substrings used for
// single-unique-index tables like project_memberships — avoids mis-attributing a
// username collision (or any future users-table unique index) to email. Neither
// dialector wraps a typed error here (that needs the gorm.Config{TranslateError: true}
// opt-in, which this codebase doesn't set), so this is driver-native text matching, the
// same approach already used for "not found"/unique-violation detection elsewhere (e.g.
// sso.go, users.go, scim.go, local_memberships.go).
func isDuplicateEmailViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "uniq_users_email_active")
}

// --- Users ---

// CreateUser ignores the optional plaintextPassword variadic (#499): user
// already carries its final PasswordHash by the time core calls this, and
// LocalStorage has no wire format to leak the plaintext into — it is simply
// never read here, matching the interface doc's no-op requirement.
func (ls *LocalStorage) CreateUser(ctx context.Context, user *models.User, _ ...string) (*models.User, error) {
	if err := ls.db.WithContext(ctx).Create(user).Error; err != nil {
		if isDuplicateEmailViolation(err) {
			// The partial unique index uniq_users_email_active (#117) caught a concurrent
			// duplicate: another create/signup/invite-accept/SCIM-provision for the
			// identical (case-insensitive) email committed first. Translate to the
			// sentinel so callers can surface a clean "email already in use" error
			// instead of a raw constraint-violation message.
			return nil, fmt.Errorf("%w: %v", storage.ErrDuplicateEmail, err)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return user, nil
}

// CreateUserWithRoleGrants creates the user and every role grant inside one
// transaction (ADR-028). If any grant insert fails, the user is rolled back too,
// so a create never leaves a half-provisioned account.
func (ls *LocalStorage) CreateUserWithRoleGrants(ctx context.Context, user *models.User, grants []storage.RoleGrant) (*models.User, error) {
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			if isDuplicateEmailViolation(err) {
				return fmt.Errorf("%w: %v", storage.ErrDuplicateEmail, err)
			}
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		for _, g := range grants {
			ur := models.UserRole{
				UserID:        user.ID,
				RoleID:        g.RoleID,
				ProjectID:     g.Scope.ProjectID,
				EnvironmentID: g.Scope.EnvironmentID,
			}
			if err := tx.Create(&ur).Error; err != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (ls *LocalStorage) GetUser(ctx context.Context, id uint) (*models.User, error) {
	var user models.User
	if err := ls.db.WithContext(ctx).First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Wrap the typed sentinel so callers can distinguish "absent" from a
			// transient failure (e.g. ownership-transfer recovery must fail closed).
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), storage.ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &user, nil
}

// LockUserForUpdate re-reads a user, adding SELECT … FOR UPDATE on Postgres so a
// read-modify-write inside a transaction serializes against concurrent writers of the
// same row (the login-lockout failed-attempt counter relies on this — see
// recordFailedLogin). SQLite has no row-level lock, so the clause is omitted there and
// the caller serializes in-process; SQLite is always single-process, so that suffices.
func (ls *LocalStorage) LockUserForUpdate(ctx context.Context, id uint) (*models.User, error) {
	q := ls.db.WithContext(ctx)
	if ls.db.Dialector.Name() == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var user models.User
	if err := q.First(&user, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), storage.ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &user, nil
}

func (ls *LocalStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	// Case-insensitive: email addresses are not case-sensitive in practice, and an
	// exact match let the ADR-028 invite-accept "account already exists" guard be
	// evaded by case (Bob@x vs bob@x), minting a duplicate identity. LOWER() on both
	// sides matches regardless of stored casing (covers legacy mixed-case rows).
	if err := ls.db.WithContext(ctx).Where("LOWER(email) = LOWER(?)", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Wrap the typed sentinel (matching GetUser/LockUserForUpdate, #504) so
			// callers can detect "genuinely absent" via
			// errors.Is/storage.IsUserNotFound instead of matching this i18n text,
			// which is a rendering detail, not a contract.
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), storage.ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &user, nil
}

func (ls *LocalStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	if err := ls.db.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), storage.ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &user, nil
}

func (ls *LocalStorage) GetUserByExternalID(ctx context.Context, externalID string) (*models.User, error) {
	var user models.User
	if err := ls.db.WithContext(ctx).Where("external_id = ?", externalID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), storage.ErrUserNotFound)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &user, nil
}

func (ls *LocalStorage) UpdateUser(ctx context.Context, user *models.User) (*models.User, error) {
	if err := ls.db.WithContext(ctx).Save(user).Error; err != nil {
		if isDuplicateEmailViolation(err) {
			// The partial unique index uniq_users_email_active (#117) caught a concurrent
			// duplicate: another update (e.g. a racing UpdateSCIMUser, #120/#218) already
			// committed the identical (case-insensitive) email to a different user before
			// this write landed. Translate to the sentinel so callers surface a clean
			// "email already in use" error instead of a raw constraint-violation message.
			return nil, fmt.Errorf("%w: %v", storage.ErrDuplicateEmail, err)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return user, nil
}

// UpdateUserIfActiveStateMatches persists user's full row via a conditional
// UPDATE gated on the row's CURRENT is_active still being fromActive (closing
// the IsActive TOCTOU race described in the storage.Storage interface doc —
// see internal/core/storage/interface.go). Mirrors
// TransitionMachineIdentityState's `WHERE id = ? AND state = ?` + `Select("*")`
// shape exactly, so every field UpdateUser mutated on user in memory (Username,
// Email, DisplayName, IsActive, UpdatedAt, ...) is persisted in the same
// statement, not just a hardcoded column subset.
func (ls *LocalStorage) UpdateUserIfActiveStateMatches(ctx context.Context, user *models.User, fromActive bool) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ? AND is_active = ?", user.ID, fromActive).
		Select("*").
		Updates(user)
	if res.Error != nil {
		if isDuplicateEmailViolation(res.Error) {
			// Same translation UpdateUser applies (#117/#120/#218): a concurrent
			// update already committed the identical (case-insensitive) email to a
			// different user before this write landed.
			return false, fmt.Errorf("%w: %v", storage.ErrDuplicateEmail, res.Error)
		}
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

// UpdateLastLogin stamps last_login_at for a single user. Uses UpdateColumn so
// only that column is written — no updated_at bump, no clobbering of other fields.
func (ls *LocalStorage) UpdateLastLogin(ctx context.Context, userID uint, loginAt time.Time) error {
	if err := ls.db.WithContext(ctx).Model(&models.User{}).
		Where(sqlWhereID, userID).
		UpdateColumn("last_login_at", loginAt).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// SetAccountState persists ONLY account_state (and updated_at) via a direct column
// update, rather than a full-row Save — see the storage.Storage interface doc comment
// (#454) for why this narrower primitive exists alongside the generic UpdateUser.
func (ls *LocalStorage) SetAccountState(ctx context.Context, id uint, state string, updatedAt time.Time) error {
	result := ls.db.WithContext(ctx).Model(&models.User{}).Where(sqlWhereID, id).
		Updates(map[string]interface{}{"account_state": state, "updated_at": updatedAt})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil))
	}
	return nil
}

// SetPasswordHash persists ONLY password_hash and password_changed_at (plus
// updated_at) via a direct column update — see the storage.Storage interface doc
// comment (#484/#454) for why this narrower primitive exists alongside the generic
// UpdateUser.
func (ls *LocalStorage) SetPasswordHash(ctx context.Context, id uint, hash string, changedAt time.Time) error {
	result := ls.db.WithContext(ctx).Model(&models.User{}).Where(sqlWhereID, id).
		Updates(map[string]interface{}{
			"password_hash":       hash,
			"password_changed_at": changedAt,
			"updated_at":          changedAt,
		})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil))
	}
	return nil
}

// UpdateLoginLockoutState persists ONLY the four login-lockout accounting columns via a
// direct column update — see the storage.Storage interface doc comment (#454).
func (ls *LocalStorage) UpdateLoginLockoutState(ctx context.Context, id uint, attempts int, lastFailedAt, lockedUntil *time.Time, lockoutCount int) error {
	result := ls.db.WithContext(ctx).Model(&models.User{}).Where(sqlWhereID, id).
		Updates(map[string]interface{}{
			"failed_login_attempts": attempts,
			"last_failed_login_at":  lastFailedAt,
			"login_locked_until":    lockedUntil,
			"login_lockout_count":   lockoutCount,
		})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil))
	}
	return nil
}

// ListUsersInStateBefore returns users whose account_state equals state and who
// were created before the cutoff, oldest first (ADR-025 stale-account warnings).
// Legacy rows with an empty account_state normalise to "active" at the read
// boundary, so they never match a restricted state like pending_first_login.
func (ls *LocalStorage) ListUsersInStateBefore(ctx context.Context, state string, before time.Time) ([]*models.User, error) {
	// G81 (User.CreatedAt): normalize internally — see GetAuditLogs.
	before = before.UTC()
	var users []*models.User
	err := ls.db.WithContext(ctx).
		Where("account_state = ? AND created_at < ?", state, before).
		Order("created_at ASC").
		Limit(maxUnboundedListRows).
		Find(&users).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return users, nil
}

// ListInactiveUsers returns all live (non-deleted) users who have not logged in
// since threshold: (last_login_at IS NULL AND created_at < threshold) OR
// (last_login_at < threshold). Ordered by ID ascending for stable pagination.
func (ls *LocalStorage) ListInactiveUsers(ctx context.Context, threshold time.Time) ([]*models.User, error) {
	// G81 (User.LastLoginAt, also covers CreatedAt): normalize internally — see
	// GetAuditLogs.
	threshold = threshold.UTC()
	var users []*models.User
	err := ls.db.WithContext(ctx).
		Where("(last_login_at IS NULL AND created_at < ?) OR last_login_at < ?", threshold, threshold).
		Order("id ASC").
		Limit(maxUnboundedListRows).
		Find(&users).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return users, nil
}

func (ls *LocalStorage) DeleteUser(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.User{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil))
	}
	return nil
}

func (ls *LocalStorage) RestoreUser(ctx context.Context, id uint) error {
	// Use Unscoped to find and update the soft-deleted row.
	result := ls.db.WithContext(ctx).Unscoped().Model(&models.User{}).Where("id = ? AND deleted_at IS NOT NULL", id).Update("deleted_at", nil)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		// Wrap the typed sentinel (#504) so RestoreUser's "not found" is detectable
		// the same way as the other user lookups, instead of only via i18n text.
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), storage.ErrUserNotFound)
	}
	return nil
}

func (ls *LocalStorage) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	query := ls.db.WithContext(ctx).Model(&models.User{})
	if filter.IncludeDeleted {
		query = query.Unscoped()
	}

	if filter.Search != nil {
		pattern := "%" + escapeLike(*filter.Search) + "%"
		query = query.Where("username ILIKE ? ESCAPE '\\' OR email ILIKE ? ESCAPE '\\' OR display_name ILIKE ? ESCAPE '\\'", pattern, pattern, pattern)
	}
	if filter.Username != nil {
		query = query.Where("username LIKE ? ESCAPE '\\'", "%"+escapeLike(*filter.Username)+"%")
	}
	if filter.Email != nil {
		query = query.Where("email LIKE ? ESCAPE '\\'", "%"+escapeLike(*filter.Email)+"%")
	}
	if filter.IsActive != nil {
		query = query.Where("is_active = ?", *filter.IsActive)
	}
	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", *filter.CreatedAfter)
	}
	if filter.InactiveSince != nil {
		// G81 (User.LastLoginAt): normalize internally — see GetAuditLogs.
		query = query.Where("last_login_at IS NULL OR last_login_at < ?", filter.InactiveSince.UTC())
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	pageSize := clampPageSize(filter.PageSize)
	page := clampPage(filter.Page)
	offset := (page - 1) * pageSize
	if filter.Offset > 0 {
		offset = filter.Offset
	}
	query = query.Offset(offset).Limit(pageSize)

	var users []*models.User
	if err := query.Find(&users).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return users, total, nil
}

// GetUserGroups retrieves all groups a user is a member of.
func (ls *LocalStorage) GetUserGroups(ctx context.Context, userID uint) ([]*models.Group, error) {
	var groups []*models.Group
	err := ls.db.WithContext(ctx).Model(&models.Group{}).
		Joins("JOIN user_groups ON user_groups.group_id = groups.id").
		Where("user_groups.user_id = ?", userID).
		Find(&groups).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return groups, nil
}

// ListAllUserGroupMemberships returns every user_groups row in the
// deployment, unfiltered by project scope — see the storage.Storage interface
// doc (#G44) for why this exists alongside GetUserGroups.
func (ls *LocalStorage) ListAllUserGroupMemberships(ctx context.Context) ([]storage.UserGroupMembership, error) {
	var rows []storage.UserGroupMembership
	err := ls.db.WithContext(ctx).Model(&models.UserGroup{}).
		Select("user_id", "group_id").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// --- Groups ---

func (ls *LocalStorage) CreateGroup(ctx context.Context, group *models.Group) (*models.Group, error) {
	if err := ls.db.WithContext(ctx).Create(group).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return group, nil
}

func (ls *LocalStorage) GetGroup(ctx context.Context, id uint) (*models.Group, error) {
	var group models.Group
	if err := ls.db.WithContext(ctx).First(&group, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s", i18n.T("ErrorGroupNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &group, nil
}

func (ls *LocalStorage) UpdateGroup(ctx context.Context, group *models.Group) (*models.Group, error) {
	if err := ls.db.WithContext(ctx).Save(group).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return group, nil
}

// DeleteGroup cascades: removes GroupRole and UserGroup join rows before deleting the group.
func (ls *LocalStorage) DeleteGroup(ctx context.Context, id uint) error {
	if _, err := ls.GetGroup(ctx, id); err != nil {
		return err
	}
	// Soft-delete the group (DeletedAt), keeping its role grants and memberships so a
	// restore brings the group back intact. A soft-deleted group authorizes nothing:
	// the role-inheritance and group-share enforcement queries exclude deleted groups.
	result := ls.db.WithContext(ctx).Delete(&models.Group{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorGroupNotFound", nil))
	}
	return nil
}

// RestoreGroup clears a soft-deleted group's deleted_at, bringing it back with the
// role grants and memberships it had at deletion.
func (ls *LocalStorage) RestoreGroup(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Unscoped().Model(&models.Group{}).
		Where("id = ? AND deleted_at IS NOT NULL", id).Update("deleted_at", nil)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("group not found or not deleted")
	}
	return nil
}

func (ls *LocalStorage) ListGroups(ctx context.Context) ([]*models.Group, error) {
	var groups []*models.Group
	if err := ls.db.WithContext(ctx).Order("name").Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return groups, nil
}

// ListGroupsPage returns one name-ordered page of groups and the total count,
// bounding both the row scan and the result size for callers (SCIM) that must not
// load the whole directory to serve a single page.
func (ls *LocalStorage) ListGroupsPage(ctx context.Context, offset, pageSize int) ([]*models.Group, int64, error) {
	var total int64
	if err := ls.db.WithContext(ctx).Model(&models.Group{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	var groups []*models.Group
	if err := ls.db.WithContext(ctx).Order("name").Offset(offset).Limit(pageSize).Find(&groups).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return groups, total, nil
}

// AddUserToGroup adds userID to groupID scoped to projectID; idempotent
// (existing (userID, groupID, projectID) membership is a no-op). projectID=0
// creates a global membership that applies in every project context.
func (ls *LocalStorage) AddUserToGroup(ctx context.Context, userID, groupID, projectID uint) error {
	if _, err := ls.GetUser(ctx, userID); err != nil {
		return err
	}
	if _, err := ls.GetGroup(ctx, groupID); err != nil {
		return err
	}
	var existing models.UserGroup
	err := ls.db.WithContext(ctx).
		Where("user_id = ? AND group_id = ? AND project_id = ?", userID, groupID, projectID).
		First(&existing).Error
	if err == nil {
		return nil // already a member with this scope
	}
	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	ug := models.UserGroup{UserID: userID, GroupID: groupID, ProjectID: projectID}
	if err := ls.db.WithContext(ctx).Create(&ug).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RemoveUserFromGroup removes the (userID, groupID, projectID) membership row.
// projectID must match the value used when the membership was created.
func (ls *LocalStorage) RemoveUserFromGroup(ctx context.Context, userID, groupID, projectID uint) error {
	result := ls.db.WithContext(ctx).
		Where("user_id = ? AND group_id = ? AND project_id = ?", userID, groupID, projectID).
		Delete(&models.UserGroup{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return nil
}

func (ls *LocalStorage) ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error) {
	if _, err := ls.GetGroup(ctx, groupID); err != nil {
		return nil, err
	}
	var users []*models.User
	err := ls.db.WithContext(ctx).Model(&models.User{}).
		Joins("JOIN user_groups ON user_groups.user_id = users.id").
		Where("user_groups.group_id = ?", groupID).
		Find(&users).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return users, nil
}

// ListGroupMembersByGroupIDs is the batch form of ListGroupMembers: the members of
// every group in groupIDs, keyed by group ID, in one query. Unlike ListGroupMembers
// this does not verify each group ID actually exists — callers already know the
// IDs are real (e.g. they came from existing share records) and want the member
// lookup batched, not a per-group existence check. Used by the rotation planner's
// risk-scoring batch (#409) instead of one ListGroupMembers call per group share,
// per candidate secret.
func (ls *LocalStorage) ListGroupMembersByGroupIDs(ctx context.Context, groupIDs []uint) (map[uint][]*models.User, error) {
	out := make(map[uint][]*models.User, len(groupIDs))
	if len(groupIDs) == 0 {
		return out, nil
	}
	type row struct {
		models.User
		GroupID uint
	}
	var rows []row
	err := ls.db.WithContext(ctx).Table("users").
		Select("users.*, user_groups.group_id AS group_id").
		Joins("JOIN user_groups ON user_groups.user_id = users.id").
		Where("user_groups.group_id IN ?", groupIDs).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for i := range rows {
		u := rows[i].User
		out[rows[i].GroupID] = append(out[rows[i].GroupID], &u)
	}
	return out, nil
}

// --- Password history (ADR-025) ---

// AddPasswordHistory records a bcrypt hash for the user.
func (ls *LocalStorage) AddPasswordHistory(ctx context.Context, userID uint, hash string, at time.Time) error {
	row := &models.PasswordHistory{UserID: userID, PasswordHash: hash, CreatedAt: at}
	if err := ls.db.WithContext(ctx).Create(row).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RecentPasswordHashes returns the most recent `limit` hashes (newest first).
func (ls *LocalStorage) RecentPasswordHashes(ctx context.Context, userID uint, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	var rows []models.PasswordHistory
	err := ls.db.WithContext(ctx).
		Where(sqlWhereUserID, userID).
		Order("created_at DESC").Limit(limit).
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	hashes := make([]string, len(rows))
	for i, r := range rows {
		hashes[i] = r.PasswordHash
	}
	return hashes, nil
}

// PrunePasswordHistory deletes all but the newest `keep` history rows for a user.
func (ls *LocalStorage) PrunePasswordHistory(ctx context.Context, userID uint, keep int) error {
	if keep < 0 {
		keep = 0
	}
	// Find the cutoff: the id of the keep-th newest row. Anything older is pruned.
	var ids []uint
	if err := ls.db.WithContext(ctx).Model(&models.PasswordHistory{}).
		Where(sqlWhereUserID, userID).
		Order("created_at DESC").Limit(keep).
		Pluck("id", &ids).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	q := ls.db.WithContext(ctx).Where(sqlWhereUserID, userID)
	if len(ids) > 0 {
		q = q.Where("id NOT IN ?", ids)
	}
	if err := q.Delete(&models.PasswordHistory{}).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}
