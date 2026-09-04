// dependencies_rune_test.go — exercises the depsList/depsAdd/depsRemove/depsImpact
// RunE closures directly (dependencies_remote_test.go only tests the extracted
// fetch/print helpers, never the command wiring).
package secret

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDepsListCmd_Success(t *testing.T) {
	_, done := depsStub(t)
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := depsListCmd.RunE(depsListCmd, []string{"7"})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "db-password")
	assert.Contains(t, out, "edge-cert")
}

func TestDepsListCmd_InvalidArg(t *testing.T) {
	err := depsListCmd.RunE(depsListCmd, []string{"0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret id")
}

func TestDepsListCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := depsListCmd.RunE(depsListCmd, []string{"7"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestDepsListCmd_FetchError(t *testing.T) {
	_, done := depsStub(t)
	defer done()
	err := depsListCmd.RunE(depsListCmd, []string{"9999"})
	require.Error(t, err)
}

func TestDepsAddCmd_Success(t *testing.T) {
	_, done := depsStub(t)
	defer done()

	origNote := depNote
	t.Cleanup(func() { depNote = origNote })
	depNote = "derives from"

	out := captureStdoutForFolder(t, func() {
		err := depsAddCmd.RunE(depsAddCmd, []string{"7", "2"})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "Added")
}

func TestDepsAddCmd_InvalidFirstArg(t *testing.T) {
	err := depsAddCmd.RunE(depsAddCmd, []string{"0", "2"})
	require.Error(t, err)
}

func TestDepsAddCmd_InvalidSecondArg(t *testing.T) {
	err := depsAddCmd.RunE(depsAddCmd, []string{"7", "0"})
	require.Error(t, err)
}

func TestDepsAddCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := depsAddCmd.RunE(depsAddCmd, []string{"7", "2"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestDepsAddCmd_APIError(t *testing.T) {
	_, done := depsStub(t)
	defer done()
	err := depsAddCmd.RunE(depsAddCmd, []string{"999", "2"})
	require.Error(t, err)
}

func TestDepsRemoveCmd_Success(t *testing.T) {
	_, done := depsStub(t)
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := depsRemoveCmd.RunE(depsRemoveCmd, []string{"7", "12"})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "Removed dependency edge 12")
}

func TestDepsRemoveCmd_InvalidFirstArg(t *testing.T) {
	err := depsRemoveCmd.RunE(depsRemoveCmd, []string{"0", "12"})
	require.Error(t, err)
}

func TestDepsRemoveCmd_InvalidSecondArg(t *testing.T) {
	err := depsRemoveCmd.RunE(depsRemoveCmd, []string{"7", "0"})
	require.Error(t, err)
}

func TestDepsRemoveCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := depsRemoveCmd.RunE(depsRemoveCmd, []string{"7", "12"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestDepsRemoveCmd_APIError(t *testing.T) {
	_, done := depsStub(t)
	defer done()
	err := depsRemoveCmd.RunE(depsRemoveCmd, []string{"999", "12"})
	require.Error(t, err)
}

func TestDepsImpactCmd_Success(t *testing.T) {
	_, done := depsStub(t)
	defer done()

	out := captureStdoutForFolder(t, func() {
		err := depsImpactCmd.RunE(depsImpactCmd, []string{"7"})
		require.NoError(t, err)
	})
	assert.Contains(t, out, "app-token")
	assert.Contains(t, out, "edge-cert")
}

func TestDepsImpactCmd_InvalidArg(t *testing.T) {
	err := depsImpactCmd.RunE(depsImpactCmd, []string{"0"})
	require.Error(t, err)
}

func TestDepsImpactCmd_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := depsImpactCmd.RunE(depsImpactCmd, []string{"7"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestDepsImpactCmd_FetchError(t *testing.T) {
	_, done := depsStub(t)
	defer done()
	err := depsImpactCmd.RunE(depsImpactCmd, []string{"9999"})
	require.Error(t, err)
}

// TestPrintImpact_NoAffected covers the zero-affected branch of printImpact,
// which the stub's fixture data never reaches (it always has 2 affected secrets).
func TestPrintImpact_NoAffected(t *testing.T) {
	v := &impactView{SecretID: 3, SecretName: "standalone", Affected: nil}
	out := captureStdoutForFolder(t, func() { printImpact(v) })
	assert.Contains(t, out, "affects no other secrets")
}

// TestPrintDependencies_WithNotes covers the noteSuffix branch when a note is
// present (the "  — <note>" suffix on each edge line).
func TestPrintDependencies_WithNotes(t *testing.T) {
	v := &depsView{
		SecretID: 7,
		DependsOn: []depEdgeView{
			{ID: 1, SecretID: 2, SecretName: "db", Note: "derives from"},
		},
		Dependents: []depEdgeView{
			{ID: 2, SecretID: 3, SecretName: "cert"},
		},
	}
	out := captureStdoutForFolder(t, func() { printDependencies(v) })
	assert.Contains(t, out, "— derives from")
}
