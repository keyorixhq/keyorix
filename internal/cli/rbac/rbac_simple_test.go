package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRBACCommandsExist(t *testing.T) {
	// Test that the main RBAC command exists
	assert.NotNil(t, RbacCmd)
	assert.Equal(t, "rbac", RbacCmd.Use)
	assert.Contains(t, RbacCmd.Short, "Role-Based Access Control")

	// Test that subcommands exist
	subcommands := RbacCmd.Commands()
	commandNames := make([]string, len(subcommands))
	for i, cmd := range subcommands {
		commandNames[i] = cmd.Use
	}

	expectedCommands := []string{
		"assign-role",
		"remove-role",
		"list-roles",
		"list-user-roles",
		"list-permissions",
		"check-permission",
		"audit-logs",
	}

	for _, expected := range expectedCommands {
		assert.Contains(t, commandNames, expected, "Expected command %s to exist", expected)
	}
}

func TestAssignRoleCommandStructure(t *testing.T) {
	// Test that assign-role command has proper structure
	assert.NotNil(t, assignRoleCmd)
	assert.Equal(t, "assign-role", assignRoleCmd.Use)
	assert.Contains(t, assignRoleCmd.Short, "Assign a role")

	// Test that required flags exist
	userFlag := assignRoleCmd.Flags().Lookup("user")
	assert.NotNil(t, userFlag, "user flag should exist")

	roleFlag := assignRoleCmd.Flags().Lookup("role")
	assert.NotNil(t, roleFlag, "role flag should exist")
}

func TestListRolesCommandStructure(t *testing.T) {
	// Test that list-roles command has proper structure
	assert.NotNil(t, listRolesCmd)
	assert.Equal(t, "list-roles", listRolesCmd.Use)
	assert.Contains(t, listRolesCmd.Short, "List")
}

func TestRemoveRoleCommandStructure(t *testing.T) {
	// Test that remove-role command has proper structure
	assert.NotNil(t, removeRoleCmd)
	assert.Equal(t, "remove-role", removeRoleCmd.Use)
	assert.Contains(t, removeRoleCmd.Short, "Remove")
}
