package core

// legacy_role_project_grants_control_chars_test.go — LEGACY-ROLES-TAILS-1 item 3:
// the upgrade check puts database names (principal, project, environment, role)
// into startup and `admin validate --posture` lines. A name holding a newline or
// an ANSI escape must not forge a second log line or drive the terminal.

import (
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"
)

// hostileName is a name with a line break (a forged second log line) and an ANSI
// colour sequence (terminal control).
const hostileName = "evil\nWARNING: forged\r\x1b[31mred\x07\x00"

func requireNoControl(t *testing.T, s, what string) {
	t.Helper()
	for _, r := range s {
		require.Falsef(t, unicode.IsControl(r), "%s holds control character %U: %q", what, r, s)
	}
}

func TestLegacyRoleProjectGrantDescribe_NamesCarryNoControlCharacters(t *testing.T) {
	for _, ptype := range []string{"user", "group", "machine"} {
		g := LegacyRoleProjectGrant{PrincipalType: ptype, PrincipalID: 7, Principal: hostileName, RoleName: "viewer",
			Replacement: "project_viewer", ProjectID: 2, Project: hostileName, EnvironmentID: 5, Environment: hostileName}
		got := g.Describe()
		requireNoControl(t, got, ptype+" Describe()")
		// Escaped, not dropped: the operator can still tell which name it is.
		require.Contains(t, got, `evil\nWARNING: forged\r\x1b[31mred`, ptype)
		require.Contains(t, got, ptype+" ", ptype)
		require.Contains(t, got, "holds viewer on project ", ptype)

		hint := g.ReplaceHint()
		requireNoControl(t, hint, ptype+" ReplaceHint()")
		require.NotContains(t, hint, "keyorix ", "a command naming a name that cannot be pasted is not offered: "+ptype)
		require.Contains(t, hint, "through the API", ptype)
	}
}

func TestLegacyRoleProjectGrantReport_HostileNamesStayOnOneLine(t *testing.T) {
	grants := []LegacyRoleProjectGrant{
		{PrincipalType: "user", PrincipalID: 1, Principal: hostileName, RoleName: "viewer", Replacement: "project_viewer",
			ProjectID: 2, Project: "payments"},
		{PrincipalType: "group", PrincipalID: 2, Principal: "devs", RoleName: "editor", Replacement: "project_developer",
			ProjectID: 2, Project: hostileName, EnvironmentID: 5, Environment: hostileName},
	}
	lines := LegacyRoleProjectGrantReport(grants, 0)
	require.Len(t, lines, 3, "a heading and one line per grant, whatever the names hold")
	for i, line := range lines {
		requireNoControl(t, line, "report line")
		require.False(t, strings.HasPrefix(line, "WARNING: forged"), "line %d: a name must not start a line of its own", i)
	}

	// A name that needs no escaping renders exactly as before.
	clean := LegacyRoleProjectGrant{PrincipalType: "user", PrincipalID: 1, Principal: "a@example.com", RoleName: "viewer",
		Replacement: "project_viewer", ProjectID: 2, Project: "payments"}
	require.Equal(t, "user a@example.com holds viewer on project payments", clean.Describe())
}
