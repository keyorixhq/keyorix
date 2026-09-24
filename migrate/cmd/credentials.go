package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// warnInsecureFlag mirrors cli/cmd/secret.go's warnInsecureFlag (itself mirroring the old
// CLI's internal/cli/common.WarnInsecureFlag): warns to stderr when a credential-bearing flag
// was passed directly on the command line (visible to other local users via ps/proc, and
// saved in shell history). It names the FLAG only — it must never print the flag's value.
// PR #2077 review item 2.
func warnInsecureFlag(cmd *cobra.Command, flagName, advice string) {
	if cmd.Flags().Changed(flagName) {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: passing --%s on the command line is insecure (visible to other local users via ps/proc, and saved in shell history); %s\n", flagName, advice)
	}
}

// resolveCredential applies the precedence: the plain flag (warns if used), then a
// --*-file flag (path, or "-" for stdin), then the documented-default env var. PR #2077 review
// item 2: "support reading them from a file or stdin ... env vars the documented default."
func resolveCredential(cmd *cobra.Command, flagName string, flagVal string, fileFlagVal string, envVar string) (string, error) {
	if flagVal != "" {
		warnInsecureFlag(cmd, flagName, fmt.Sprintf("use --%s-file instead (a path, or \"-\" for stdin), or set $%s", flagName, envVar))
		return flagVal, nil
	}
	if fileFlagVal != "" {
		return readCredentialFile(fileFlagVal)
	}
	return os.Getenv(envVar), nil
}

// readCredentialFile reads a credential from path, or from stdin when path is "-". Trailing
// whitespace/newline (the common shape of `echo $TOKEN > file` or a heredoc) is trimmed.
func readCredentialFile(path string) (string, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path) // #nosec G304 -- operator-supplied credential file path, a CLI flag, not user/network input
	}
	if err != nil {
		return "", fmt.Errorf("read credential from %q: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}
