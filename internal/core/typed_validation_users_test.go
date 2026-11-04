package core

// typed_validation_users_test.go — ERR-CLASS-LEFTOVERS-1 item 2.
//
// core/users.go field validation is typed (ErrValidation) so mapUserError answers
// InvalidArgument by sentinel instead of looking for "validation", "required",
// "invalid" or "must be" in the text.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypedValidation_UserFields(t *testing.T) {
	for name, err := range map[string]error{
		"username too short":   validateUsernameFormat("a"),
		"username charset":     validateUsernameCharset("bad name!#"),
		"email":                validateEmailFormat("not-an-email"),
		"display name too big": validateDisplayNameFormat(string(make([]byte, 500))),
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrValidation)
		})
	}

	c := &KeyorixCore{}
	for name, call := range map[string]func() error{
		"GetUserByEmail empty":      func() error { _, err := c.GetUserByEmail(context.Background(), ""); return err },
		"GetUserByUsername empty":   func() error { _, err := c.GetUserByUsername(context.Background(), ""); return err },
		"GetUserByExternalID empty": func() error { _, err := c.GetUserByExternalID(context.Background(), ""); return err },
		"GetUser id 0":              func() error { _, err := c.GetUser(context.Background(), 0); return err },
		"RestoreUser id 0":          func() error { return c.RestoreUser(context.Background(), 1, 0) },
		"DeleteUser id 0":           func() error { return c.DeleteUser(context.Background(), 1, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrValidation)
		})
	}
}
