package admin

import (
	"strings"
	"testing"
)

// TestAcceptLossHelp_ResumeSealSentenceIsNotBroken pins the --resume-seal
// paragraph of `admin audit accept-loss --help`. It used to wrap as
// "A resume never writes without\n--resume-seal: a\nseal you did not just run ...",
// leaving a two-word line dangling in the middle of a sentence (REVIEW-4092-DEEP-1).
func TestAcceptLossHelp_ResumeSealSentenceIsNotBroken(t *testing.T) {
	long := acceptLossCmd.Long
	for _, want := range []string{
		"--resume-seal: a seal you did not just run is a rollback of the database until\nproven otherwise.",
	} {
		if !strings.Contains(long, want) {
			t.Errorf("accept-loss --help lost the resume-seal sentence %q", want)
		}
	}
	if strings.Contains(long, "--resume-seal: a\n") {
		t.Errorf("accept-loss --help has a dangling %q line wrap", "--resume-seal: a")
	}
}
