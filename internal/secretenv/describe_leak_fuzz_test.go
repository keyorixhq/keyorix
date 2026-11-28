package secretenv

// FuzzDescribeFileNoRelativePathLeak pins the secret-non-disclosure property of
// DescribeFile and FileError.Error() (describe.go, SECRETENV-REVIEW-1 F4): when a
// secret-file path is RELATIVE it may itself be the secret
// (KEYORIX_DB_PASSWORD_FILE=hunter2 -> "no such file"), so the path value must
// never appear in any message. The path, label and wrapped error are all
// untrusted operator input.
//
// ORACLE (fail-closed non-disclosure, one-directional -- cannot false-positive):
//
//	A fixed canary token is embedded in the PATH only (never in the label or the
//	wrapped error). For every RELATIVE path, neither DescribeFile(label, path)
//	nor FileError{label, path, err}.Error() may contain the canary.
//
// Because the canary is placed solely in the path and the inputs that are
// legitimately echoed (label, err text) are required canary-free before the
// assertion runs, a canary in the output can ONLY have come from the path -- so
// the assertion fires exactly when a relative path leaks, and never otherwise.
// Absolute paths are deliberately shown (the operator needs them to fix the
// mount) and are skipped.
//
// WHAT THIS DOES NOT VERIFY:
//   - It does not check the secret VALUE (file contents) non-disclosure; that is
//     readSecretFileJudged / NewFileError-at-the-read-site behaviour, covered by
//     the mutation suite and the server-side "never echoed" tests named in
//     describe.go. This target is only about the path echo.
//   - It does not verify the exact wording of the "(a relative path, not shown)"
//     message, only that the path itself is absent.
//   - It does not cover the out-of-package copies (cli describeSecretFile,
//     entrypoint _rs_describe); those have their own equality tests.

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

const describeCanary = "CANARY_7f3a9e_SECRET"

func FuzzDescribeFileNoRelativePathLeak(f *testing.F) {
	// seeds: (label, pathPrefix, pathSuffix, errMsg)
	f.Add("KEYORIX_DB_PASSWORD_FILE", "", "", "no such file or directory")
	f.Add("secret file", "sub/", "/more", "permission denied")
	f.Add("server.http.metrics_token_file", "./", "", "is not a regular file")
	f.Add("", "", "", "")
	f.Add("weird label with spaces", "a", "b", "boom")

	f.Fuzz(func(t *testing.T, label, pathPrefix, pathSuffix, errMsg string) {
		// Keep the canary out of the inputs that are legitimately echoed, so any
		// canary in the output provably came from the path.
		if strings.Contains(label, describeCanary) || strings.Contains(errMsg, describeCanary) {
			t.Skip()
		}
		path := pathPrefix + describeCanary + pathSuffix
		if filepath.IsAbs(path) {
			t.Skip() // absolute paths are shown by design
		}

		if out := DescribeFile(label, path); strings.Contains(out, describeCanary) {
			t.Fatalf("DescribeFile leaked a relative path: label=%q path=%q -> %q", label, path, out)
		}
		fe := NewFileError(label, path, errors.New(errMsg))
		if out := fe.Error(); strings.Contains(out, describeCanary) {
			t.Fatalf("FileError.Error leaked a relative path: label=%q path=%q -> %q", label, path, out)
		}
	})
}
