package services

// family_mappers_sentinel_text_test.go — REVIEW-4214 L1. A family mapper's own text
// describes the sentinels the old per-family switch listed; any other sentinel of the
// same class answers the class code with the classifier's default text, so a project
// not-found under a group RPC never reads "group not found".

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/errclass"
)

func TestFamilyMappers_TextIsKeyedOnTheSentinel(t *testing.T) {
	cases := []struct {
		name   string
		mapper func(error) error
		err    error
		code   codes.Code
		text   string
	}{
		{"group: its own not-found", groupError, storage.ErrGroupNotFound, codes.NotFound, "group not found"},
		{"group: user not-found", groupError, storage.ErrUserNotFound, codes.NotFound, "user not found"},
		{"group: another entity's not-found", groupError, storage.ErrProjectNotFound, codes.NotFound, coreErrorDefaultText(errclass.NotFound, "")},
		{"group: its own conflict", groupError, storage.ErrDuplicateGroupName, codes.AlreadyExists, "group name already in use"},
		{"group: another conflict", groupError, storage.ErrDuplicateProjectName, codes.AlreadyExists, coreErrorDefaultText(errclass.Conflict, "")},
		{"group: last-admin guard", groupError, core.ErrLastAdminGroupGuard, codes.FailedPrecondition, "cannot remove the last administrator"},
		{"role: its own not-found", mapRoleError, storage.ErrRoleNotFound, codes.NotFound, "role not found"},
		{"role: another entity's not-found", mapRoleError, storage.ErrProjectNotFound, codes.NotFound, coreErrorDefaultText(errclass.NotFound, "")},
		{"project: its own not-found", mapProjectError, storage.ErrProjectNotFound, codes.NotFound, "project not found"},
		{"project: another entity's not-found", mapProjectError, storage.ErrUserNotFound, codes.NotFound, coreErrorDefaultText(errclass.NotFound, "")},
		{"project: its own conflict", mapProjectError, storage.ErrDuplicateProjectName, codes.AlreadyExists, "a project with this name already exists"},
		{"project: another conflict", mapProjectError, storage.ErrDuplicateGroupName, codes.AlreadyExists, coreErrorDefaultText(errclass.Conflict, "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.mapper(fmt.Errorf("op: %w", tc.err))
			st, _ := status.FromError(got)
			assert.Equal(t, tc.code, st.Code(), got.Error())
			assert.Equal(t, tc.text, st.Message())
		})
	}
}
