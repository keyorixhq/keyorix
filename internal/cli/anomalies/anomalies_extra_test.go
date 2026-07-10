package anomalies

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnomaliesCmdStructure(t *testing.T) {
	names := make(map[string]bool)
	for _, c := range AnomaliesCmd.Commands() {
		names[c.Name()] = true
	}
	for _, expected := range []string{"list", "acknowledge"} {
		assert.True(t, names[expected], "expected subcommand %q", expected)
	}
}

func TestAnomaliesCmdListFlag(t *testing.T) {
	assert.NotNil(t, listCmd.Flags().Lookup("unacknowledged"))
}

func TestAcknowledgeCmd_BadID(t *testing.T) {
	// ParseUint rejects non-numeric input before any network call.
	err := acknowledgeCmd.RunE(acknowledgeCmd, []string{"not-a-number"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid alert ID")
}
