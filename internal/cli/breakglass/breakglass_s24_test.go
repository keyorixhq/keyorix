package breakglass

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestActivate_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	bgProject, bgJustify = 5, "reason"
	t.Cleanup(func() { bgProject, bgJustify = 0, "" })
	require.ErrorContains(t, activateCmd.RunE(nil, nil), "not connected")
}

func TestList_MissingProjectID(t *testing.T) {
	bgProject = 0
	t.Cleanup(func() { bgProject = 0 })
	require.ErrorContains(t, listCmd.RunE(nil, nil), "--project-id is required")
}

func TestList_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	bgProject = 5
	t.Cleanup(func() { bgProject = 0 })
	require.ErrorContains(t, listCmd.RunE(nil, nil), "not connected")
}

func TestRevoke_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	bgProject, bgActivation = 5, 9
	t.Cleanup(func() { bgProject, bgActivation = 0, 0 })
	require.ErrorContains(t, revokeCmd.RunE(nil, nil), "not connected")
}
