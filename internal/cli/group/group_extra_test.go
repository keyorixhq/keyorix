package group

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGroupCommandStructure(t *testing.T) {
	assert.Equal(t, "group", GroupCmd.Use)

	names := make([]string, 0)
	for _, c := range GroupCmd.Commands() {
		names = append(names, c.Use)
	}
	for _, expected := range []string{
		"create", "get", "update", "delete", "list",
		"add-member", "remove-member", "members",
	} {
		assert.Contains(t, names, expected, "expected subcommand %q", expected)
	}
}

func TestGroupCreateCmd_NameRequired(t *testing.T) {
	orig := createName
	defer func() { createName = orig }()
	createName = ""
	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestGroupGetCmd_IDRequired(t *testing.T) {
	orig := getGroupID
	defer func() { getGroupID = orig }()
	getGroupID = 0
	err := runGet(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group id is required")
}

func TestGroupUpdateCmd_IDRequired(t *testing.T) {
	orig := updateGroupID
	defer func() { updateGroupID = orig }()
	updateGroupID = 0
	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group id is required")
}

func TestGroupUpdateCmd_NoFieldsProvided(t *testing.T) {
	origID, origName, origDesc := updateGroupID, updateGroupName, updateGroupDescription
	defer func() {
		updateGroupID = origID
		updateGroupName = origName
		updateGroupDescription = origDesc
	}()
	updateGroupID = 1
	updateGroupName = ""
	updateGroupDescription = ""
	err := runUpdate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provide at least one of")
}

func TestGroupAddMemberCmd_BothIDsRequired(t *testing.T) {
	origG, origU := addMemberGroupID, addMemberUserID
	defer func() { addMemberGroupID = origG; addMemberUserID = origU }()

	addMemberGroupID = 0
	addMemberUserID = 0
	err := runAddMember(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--group-id and --user-id are required")

	addMemberGroupID = 5
	addMemberUserID = 0
	err = runAddMember(nil, nil)
	require.Error(t, err)

	addMemberGroupID = 0
	addMemberUserID = 3
	err = runAddMember(nil, nil)
	require.Error(t, err)
}

func TestGroupRemoveMemberCmd_BothIDsRequired(t *testing.T) {
	origG, origU := removeMemberGroupID, removeMemberUserID
	defer func() { removeMemberGroupID = origG; removeMemberUserID = origU }()

	removeMemberGroupID = 0
	removeMemberUserID = 0
	err := runRemoveMember(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--group-id and --user-id are required")
}

func TestGroupMembersCmd_IDRequired(t *testing.T) {
	orig := membersGroupID
	defer func() { membersGroupID = orig }()
	membersGroupID = 0
	err := runMembers(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group id is required")
}

func TestGroupDeleteCmd_IDRequired(t *testing.T) {
	orig := deleteGroupID
	defer func() { deleteGroupID = orig }()
	deleteGroupID = 0
	err := runDelete(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "group id is required")
}

func TestGroupDeleteCmd_HasForceFlag(t *testing.T) {
	f := deleteCmd.Flags().Lookup("force")
	require.NotNil(t, f)
	assert.Equal(t, "false", f.DefValue)
}
