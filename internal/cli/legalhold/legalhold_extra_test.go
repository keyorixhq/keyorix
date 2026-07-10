package legalhold

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLegalHoldCmdStructure(t *testing.T) {
	assert.Equal(t, "legal-hold", LegalHoldCmd.Use)
	names := make(map[string]bool)
	for _, c := range LegalHoldCmd.Commands() {
		names[c.Name()] = true
	}
	for _, expected := range []string{"status", "place", "lift"} {
		assert.True(t, names[expected], "expected subcommand %q", expected)
	}
}

func TestPlaceCmd_ReasonRequired(t *testing.T) {
	orig := placeReason
	defer func() { placeReason = orig }()
	placeReason = ""
	err := placeCmd.RunE(placeCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--reason is required")
}

func TestLiftCmd_ReasonRequired(t *testing.T) {
	origR, origY := liftReason, liftYes
	defer func() { liftReason = origR; liftYes = origY }()
	liftReason = ""
	liftYes = true
	cmd := &cobra.Command{}
	err := liftCmd.RunE(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--reason is required")
}

func TestLiftCmd_HasYesFlag(t *testing.T) {
	f := liftCmd.Flags().Lookup("yes")
	require.NotNil(t, f)
	assert.Equal(t, "false", f.DefValue)
}

func TestPlaceCmd_HasReasonFlag(t *testing.T) {
	assert.NotNil(t, placeCmd.Flags().Lookup("reason"))
}
