package core

// SCIM-TAILS-1 item 4: DeprovisionSCIMGroup and the PatchSCIMGroup member paths hand the
// SCIM handler errors it classifies with errors.Is (server/http/handlers/scim_errors.go),
// never by message text (the texts are i18n and change with the locale). These tests pin
// the sentinel each refusal carries and that a storage failure carries none of them, so
// a wrap that drops %w, or a refusal reworded into a plain string, fails here rather than
// turning an IdP's permanent refusal into a retried 500 or a missing group into a 409.

import (
	"context"
	"errors"
	"testing"

	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var errScimTypingInjected = errors.New("injected storage failure")

func newSCIMTypingCore(t *testing.T) (*KeyorixCore, *faultstorage.FaultyStorage, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Session{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{},
		&models.PersonalAccessToken{},
	))
	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	return NewKeyorixCore(fs), fs, db
}

// seedSCIMAdminGroup creates group 5 granting an admin-bypass role, with SCIM user 1 as
// its only member and the install's only route to admin authority.
func seedSCIMAdminGroup(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive, ExternalID: "okta|root"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Keyorix-Admins"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 5, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 5}).Error)
}

func TestSCIMGroupErrors_AreTypedForErrorsIs(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		setup func(t *testing.T, db *gorm.DB)
		do    func(c *KeyorixCore) error
		want  []error // errors.Is must hold for every one
		not   []error // and for none of these
	}{
		"deprovision: no such group": {
			do:   func(c *KeyorixCore) error { return c.DeprovisionSCIMGroup(ctx, 9, 404) },
			want: []error{storage.ErrGroupNotFound},
			not:  []error{ErrLastAdminGroupGuard, storage.ErrWouldStrandLastAdmin},
		},
		"deprovision: the last admin group": {
			setup: seedSCIMAdminGroup,
			do:    func(c *KeyorixCore) error { return c.DeprovisionSCIMGroup(ctx, 9, 5) },
			want:  []error{ErrLastAdminGroupGuard},
			not:   []error{storage.ErrGroupNotFound},
		},
		"patch: no such group": {
			do:   func(c *KeyorixCore) error { _, err := c.PatchSCIMGroup(ctx, 9, 404, nil, nil, nil); return err },
			want: []error{storage.ErrGroupNotFound},
			not:  []error{ErrSCIMMemberNotManaged, ErrSCIMGroupConfersAdmin},
		},
		"patch add: member that is not SCIM-managed": {
			setup: func(t *testing.T, db *gorm.DB) {
				require.NoError(t, db.Create(&models.User{ID: 1, Username: "native", IsActive: true, AccountState: AccountActive}).Error)
				require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Engineering"}).Error)
			},
			do:   func(c *KeyorixCore) error { _, err := c.PatchSCIMGroup(ctx, 9, 5, nil, []uint{1}, nil); return err },
			want: []error{ErrSCIMMemberNotManaged},
			not:  []error{storage.ErrGroupNotFound, storage.ErrUserNotFound, ErrSCIMGroupConfersAdmin},
		},
		"patch add: member that does not exist": {
			setup: func(t *testing.T, db *gorm.DB) {
				require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Engineering"}).Error)
			},
			do:   func(c *KeyorixCore) error { _, err := c.PatchSCIMGroup(ctx, 9, 5, nil, []uint{999}, nil); return err },
			want: []error{ErrSCIMMemberNotManaged},
			not:  []error{storage.ErrGroupNotFound},
		},
		"patch add: group that grants admin": {
			setup: func(t *testing.T, db *gorm.DB) {
				seedSCIMAdminGroup(t, db)
				require.NoError(t, db.Create(&models.User{ID: 2, Username: "newbie", IsActive: true, AccountState: AccountActive, ExternalID: "okta|newbie"}).Error)
			},
			do:   func(c *KeyorixCore) error { _, err := c.PatchSCIMGroup(ctx, 9, 5, nil, []uint{2}, nil); return err },
			want: []error{ErrSCIMGroupConfersAdmin},
			not:  []error{ErrSCIMMemberNotManaged, storage.ErrGroupNotFound},
		},
		"patch remove: the last admin member": {
			setup: seedSCIMAdminGroup,
			do:    func(c *KeyorixCore) error { _, err := c.PatchSCIMGroup(ctx, 9, 5, nil, nil, []uint{1}); return err },
			want:  []error{storage.ErrWouldStrandLastAdmin},
			not:   []error{storage.ErrGroupNotFound, ErrSCIMGroupConfersAdmin},
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, _, db := newSCIMTypingCore(t)
			if tc.setup != nil {
				tc.setup(t, db)
			}
			err := tc.do(c)
			require.Error(t, err)
			for _, w := range tc.want {
				assert.ErrorIs(t, err, w)
			}
			for _, n := range tc.not {
				assert.NotErrorIs(t, err, n)
			}
		})
	}
}

// TestSCIMGroupErrors_StorageFailureCarriesNoRefusalSentinel: a storage failure on any of
// these paths keeps its cause (errors.Is the injected error) and is none of the refusals,
// so the handler answers 500, not a 404/400/403/409 an IdP would never retry.
func TestSCIMGroupErrors_StorageFailureCarriesNoRefusalSentinel(t *testing.T) {
	ctx := context.Background()
	refusals := []error{
		storage.ErrGroupNotFound, storage.ErrUserNotFound, ErrNotSCIMManaged, ErrSCIMMemberNotManaged,
		ErrSCIMGroupConfersAdmin, ErrLastAdminGroupGuard, storage.ErrWouldStrandLastAdmin, storage.ErrDuplicateGroupName,
	}
	for name, tc := range map[string]struct {
		method string
		do     func(c *KeyorixCore) error
	}{
		"deprovision: GetGroup": {"GetGroup", func(c *KeyorixCore) error { return c.DeprovisionSCIMGroup(ctx, 9, 5) }},
		"deprovision: DeleteGroup": {"DeleteGroup", func(c *KeyorixCore) error {
			return c.DeprovisionSCIMGroup(ctx, 9, 6)
		}},
		"patch: GetGroup": {"GetGroup", func(c *KeyorixCore) error { _, err := c.PatchSCIMGroup(ctx, 9, 6, nil, nil, nil); return err }},
		"patch add: GetUser (the SCIM-managed check)": {"GetUser", func(c *KeyorixCore) error {
			_, err := c.PatchSCIMGroup(ctx, 9, 6, nil, []uint{2}, nil)
			return err
		}},
		"patch add: GetGroupRoles (the admin-group check)": {"GetGroupRoles", func(c *KeyorixCore) error {
			_, err := c.PatchSCIMGroup(ctx, 9, 6, nil, []uint{2}, nil)
			return err
		}},
		"patch remove: ListProjectRoleAssignments (the last-admin guard)": {"ListProjectRoleAssignments", func(c *KeyorixCore) error {
			_, err := c.PatchSCIMGroup(ctx, 9, 5, nil, nil, []uint{1})
			return err
		}},
	} {
		t.Run(name, func(t *testing.T) {
			c, fs, db := newSCIMTypingCore(t)
			seedSCIMAdminGroup(t, db)
			require.NoError(t, db.Create(&models.Group{ID: 6, Name: "Engineering"}).Error)
			require.NoError(t, db.Create(&models.User{ID: 2, Username: "u2", IsActive: true, AccountState: AccountActive, ExternalID: "okta|u2"}).Error)

			fs.Arm(&faultstorage.FaultSpec{Method: tc.method, NthCall: 1, Kind: faultstorage.KindError, Err: errScimTypingInjected})
			err := tc.do(c)
			require.True(t, fs.Fired(), "the armed %s fault must have fired", tc.method)
			fs.Arm(nil)

			require.Error(t, err)
			assert.ErrorIs(t, err, errScimTypingInjected, "the storage cause must stay reachable through the wrapping")
			for _, r := range refusals {
				assert.NotErrorIs(t, err, r)
			}
		})
	}
}
