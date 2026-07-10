package rotation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotationCmdStructure(t *testing.T) {
	assert.Equal(t, "rotation", RotationCmd.Use)
	assert.Contains(t, RotationCmd.Aliases, "rotate")
	names := make(map[string]bool)
	for _, c := range RotationCmd.Commands() {
		names[c.Name()] = true
	}
	for _, expected := range []string{"list", "create", "show", "delete", "status"} {
		assert.True(t, names[expected], "expected subcommand %q", expected)
	}
}

func TestScopeTarget_Project(t *testing.T) {
	id := uint(5)
	p := policyView{Scope: "project", ProjectID: &id}
	assert.Equal(t, "project=5", scopeTarget(p))
}

func TestScopeTarget_Environment(t *testing.T) {
	id := uint(12)
	p := policyView{Scope: "environment", EnvironmentID: &id}
	assert.Equal(t, "env=12", scopeTarget(p))
}

func TestScopeTarget_NilID(t *testing.T) {
	p := policyView{Scope: "project", ProjectID: nil}
	assert.Equal(t, "project", scopeTarget(p))
}

func TestCreateCmd_NameRequired(t *testing.T) {
	origN, origS, origI := cName, cScope, cInterval
	defer func() { cName = origN; cScope = origS; cInterval = origI }()
	cName = ""
	cScope = "project"
	cInterval = 30
	err := createCmd.RunE(createCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--name is required")
}

func TestCreateCmd_BadScope(t *testing.T) {
	origN, origS, origI := cName, cScope, cInterval
	defer func() { cName = origN; cScope = origS; cInterval = origI }()
	cName = "my-policy"
	cScope = "workspace"
	cInterval = 30
	err := createCmd.RunE(createCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--scope must be")
}

func TestCreateCmd_IntervalOutOfRange(t *testing.T) {
	origN, origS, origI := cName, cScope, cInterval
	defer func() { cName = origN; cScope = origS; cInterval = origI }()
	cName = "my-policy"
	cScope = "project"
	cInterval = 0
	err := createCmd.RunE(createCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--interval-days must be between 1 and 365")

	cInterval = 400
	err = createCmd.RunE(createCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--interval-days must be between 1 and 365")
}

func TestCreateCmd_ProjectIDRequiredForProjectScope(t *testing.T) {
	origN, origS, origI, origP := cName, cScope, cInterval, cProject
	defer func() { cName = origN; cScope = origS; cInterval = origI; cProject = origP }()
	cName = "my-policy"
	cScope = "project"
	cInterval = 30
	cProject = 0
	err := createCmd.RunE(createCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project-id is required")
}

func TestCreateCmd_EnvIDRequiredForEnvScope(t *testing.T) {
	origN, origS, origI, origE := cName, cScope, cInterval, cEnv
	defer func() { cName = origN; cScope = origS; cInterval = origI; cEnv = origE }()
	cName = "my-policy"
	cScope = "environment"
	cInterval = 30
	cEnv = 0
	err := createCmd.RunE(createCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--environment-id is required")
}

func TestShowCmd_InvalidID(t *testing.T) {
	err := showCmd.RunE(showCmd, []string{"not-an-id"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy id")
}

func TestDeleteCmd_InvalidID(t *testing.T) {
	err := deleteCmd.RunE(deleteCmd, []string{"abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy id")
}

func TestRotationCmdFlags(t *testing.T) {
	assert.NotNil(t, listCmd.Flags().Lookup("project-id"))
	assert.NotNil(t, listCmd.Flags().Lookup("environment-id"))
	assert.NotNil(t, statusCmd.Flags().Lookup("project-id"))
}
