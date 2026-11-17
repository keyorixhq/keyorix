package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestSuspendedActorRefusedAtEntryPoints: the entry points REVIEW-4336-DEEP-1 F1
// found unchecked refuse a suspended human actor with ErrPermissionDenied before
// they read or write anything else (#4159). The mock answers only GetUser, so any
// other storage call (the share or role write among them) fails the test:
// the assertion is on the absence of the effect, not only on the error.
func TestSuspendedActorRefusedAtEntryPoints(t *testing.T) {
	const actor uint = 42
	role := &models.Role{ID: 7, Name: "release-manager"}
	cases := map[string]func(c *KeyorixCore) error{
		"ShareSecret": func(c *KeyorixCore) error {
			_, err := c.ShareSecret(context.Background(), &ShareSecretRequest{SecretID: 1, RecipientID: 2, Permission: "read", SharedBy: actor})
			return err
		},
		"UpdateSharePermission": func(c *KeyorixCore) error {
			_, err := c.UpdateSharePermission(context.Background(), &UpdateShareRequest{ShareID: 1, Permission: "write", UpdatedBy: actor})
			return err
		},
		"SetUserRoles": func(c *KeyorixCore) error {
			return c.SetUserRoles(context.Background(), actor, 2, []uint{7}, Scope{}, false)
		},
		"AssignPermissionToRole": func(c *KeyorixCore) error {
			return c.AssignPermissionToRole(context.Background(), actor, 7, 3, false)
		},
		"AssignRoleToGroup": func(c *KeyorixCore) error {
			return c.AssignRoleToGroup(context.Background(), actor, 5, 7, Scope{}, false)
		},
		"UpdateRole": func(c *KeyorixCore) error {
			_, _, err := c.UpdateRole(context.Background(), actor, role, nil)
			return err
		},
		"DeleteRole": func(c *KeyorixCore) error {
			return c.DeleteRole(context.Background(), actor, 7)
		},
		"AddUserToGroup": func(c *KeyorixCore) error {
			return c.AddUserToGroup(context.Background(), actor, false, 2, 5, 0)
		},
		"CreateUserAudited": func(c *KeyorixCore) error {
			_, err := c.CreateUserAudited(context.Background(), &CreateUserRequest{Username: "u-new", Email: "u-new@example.invalid"}, actor, false)
			return err
		},
		"CreateUserWithAssignments": func(c *KeyorixCore) error {
			_, err := c.CreateUserWithAssignments(context.Background(), &CreateUserRequest{Username: "u-new", Email: "u-new@example.invalid"}, "", nil, actor, false)
			return err
		},
		"InviteGlobalWithLink": func(c *KeyorixCore) error {
			_, _, err := c.InviteGlobalWithLink(context.Background(), "u-new@example.invalid", "", nil, actor, 0)
			return err
		},
		"CreateOIDCBinding": func(c *KeyorixCore) error {
			_, err := c.CreateOIDCBinding(context.Background(), 1, 2, "https://issuer.example.invalid", "sub", actor)
			return err
		},
		"RestoreProject": func(c *KeyorixCore) error {
			return c.RestoreProject(context.Background(), actor, 1)
		},
		"RestoreEnvironment": func(c *KeyorixCore) error {
			return c.RestoreEnvironment(context.Background(), actor, 1, 2)
		},
		"RestoreGroup": func(c *KeyorixCore) error {
			_, err := c.RestoreGroup(context.Background(), actor, 5)
			return err
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := setupTestCore(t)
			m := c.storage.(*MockStorage)
			m.On("GetUser", mock.Anything, actor).Return(&models.User{ID: actor, IsActive: false, AccountState: AccountSuspended}, nil)
			err := func() (err error) {
				// An unexpected storage call panics in the mock: report it as this
				// entry point acting past the check, not as a crash of the binary.
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("acted past the account check: %v", r)
					}
				}()
				return call(c)
			}()
			require.ErrorIs(t, err, ErrPermissionDenied)
			m.AssertExpectations(t)
		})
	}
}
