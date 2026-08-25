// g80_triage_doc_closure_guard_test.go — Task 0b's guard: a "FIXED" claim in
// the G80 triage docs (docs/g80-raw-storage-bypass-triage.md,
// docs/g80-documented-exception-sweep-findings.md) that references a PR
// number is not itself evidence the fix reached `main` — see this session's
// own headline finding: PRs #1563-#1566 all showed "Merged" on GitHub while
// each was actually merged into the PREVIOUS PR's feature branch, never
// `main` (CLAUDE.md's "a merge badge is not a merge").
//
// IMPORTANT scope note (corrected 2026-08-25, see CLAUDE.md's fuller
// correction): `git merge-base --is-ancestor <sha> HEAD` is sound HERE
// because every claim below names one specific, already-resolved commit SHA
// -- checking whether a known object is included in HEAD's history is a
// valid question regardless of squash-merge. It would NOT be sound to run
// `--is-ancestor <branch-tip> origin/main` instead: this repo squash-merges
// every PR, minting a brand-new commit, so a correctly-landed branch's own
// pre-squash commits are never ancestors of that squash commit either --
// that check returns false unconditionally, landed or not. This guard never
// does that; it only ever checks named, resolved SHAs, never a branch ref.
//
// This is NOT a claim that every referenced commit fixes what it says it
// fixes -- that's the triage doc's own job. This guard only checks the
// narrower, mechanical fact a merge badge cannot be trusted to report:
// is the commit actually reachable from HEAD.
//
// Entries with no single commit to point at (the #1563-#1566 + ADR-085
// content, re-applied as one flat diff onto a fresh branch rather than
// individually-attributable commits -- see this file's own registry entry
// below for the full reasoning) are listed explicitly with a stated reason,
// not silently exempted from this file's registry -- a missing entry would
// look identical to "nothing more to verify," which is exactly the kind of
// silent gap this guard exists to prevent.
package http

import (
	"os/exec"
	"strings"
	"testing"
)

// g80ClosureClaim is one triage-doc reference this guard verifies (or
// explicitly declines to, with a stated reason).
type g80ClosureClaim struct {
	// label identifies the claim for a failure message -- doc + PR reference,
	// not a full description of what the PR does (the triage docs own that).
	label string
	// sha is the full commit hash the claim rests on. Empty means "no single
	// commit exists" -- noSingleCommitReason must be set instead.
	sha string
	// noSingleCommitReason is set (and sha left empty) when the referenced
	// fix does not correspond to one attributable commit -- e.g. content
	// re-applied as a flat diff after a tangled branch-into-branch merge
	// chain. Reading this field IS the explicit statement Task 0b requires;
	// it is not a silent exemption because it appears in this file's
	// registry and is asserted non-empty by the test below.
	noSingleCommitReason string
}

// g80TriageClosureClaims is the registry TestG80TriageDocClosuresAreAncestorsOfHEAD
// checks. Add an entry here whenever a triage doc records a new "FIXED"
// claim against a real commit; add a noSingleCommitReason entry instead when
// the fix has no single commit to point at.
var g80TriageClosureClaims = []g80ClosureClaim{
	// docs/g80-raw-storage-bypass-triage.md "Fix wave complete (2026-08-25)"
	// section, verified against origin/main by this same correction pass
	// (2026-08-25) -- see that section's own "Corrections from an
	// independent verification session" subsection.
	{label: "docs/g80-raw-storage-bypass-triage.md: PR #1557 (CreateAccessRequestProxy/UpdateAccessRequestProxy dual-control bypass)",
		sha: "2b888df72c322563030dbd7a7b996c022cf08061"},
	{label: "docs/g80-raw-storage-bypass-triage.md: PR #1558 (CreateInvitationProxy/UpdateInvitationProxy escalation-by-proxy bypass)",
		sha: "28b52cfbeec5a1acd2bf2d81e32afb42328e4590"},
	{label: "docs/g80-raw-storage-bypass-triage.md: PR #1559 (SoD policy and risk-exception authority gaps)",
		sha: "f83d63c63a03a6bedc79a4440eb84def3805a471"},
	{label: "docs/g80-raw-storage-bypass-triage.md: PR #1560 (DeleteOIDCBindingProxy direct-caller routing)",
		sha: "33eaf8df9dd5faaac77d11979b3e65c267ca9ca4"},
	{label: "docs/g80-raw-storage-bypass-triage.md: PR #1561 (UpdateUser PAT/session-revocation residual)",
		sha: "10fdb34ab705448bd6bdf6f6e0193a1555dad430"},
	{label: "docs/g80-raw-storage-bypass-triage.md: PR #1562 (RemoveGlobalAdminRoleGuardedProxy actor-authority gap)",
		sha: "cb26f4f0baed17ffe0c89a9fc93635d613ae6307"},
	// PRs #1563-#1566 (server/http proxy Tier-2 fixes) and the ADR-085
	// node-credential-arm removal: an independent verification session's
	// headline finding (2026-08-25) is that all four PRs showed
	// "Merged" on GitHub while none were ancestors of origin/main -- each
	// was merged into the previous PR's feature branch. The content was
	// recovered from the worktree it existed in only as uncommitted work and
	// re-applied as ONE flat diff (`git apply`) onto a fresh branch off
	// origin/main, because the squash-merge history made the original
	// per-PR commits unrecoverable as individually-attributable objects (a
	// pre-squash commit is never an ancestor of its own post-squash
	// equivalent). There is no single commit that represents "PR #1563's
	// fix" (or #1564/#1565/#1566's) anymore, distinct from the whole
	// re-applied stack -- stated explicitly here, not silently exempted.
	{label: "PRs #1563-#1566 + ADR-085 node-credential-arm removal",
		noSingleCommitReason: "re-applied as one flat diff onto a fresh branch (git apply, not a rebase) after " +
			"the original branch-into-branch merge chain was found to never reach main and the pre-squash " +
			"commits were confirmed unrecoverable as ancestors of their post-squash equivalents; verify this " +
			"content's presence by reading the diff/tests it introduced, not by any single commit hash"},
}

// TestG80TriageDocClosuresAreAncestorsOfHEAD is Task 0b's guard: every claim
// in g80TriageClosureClaims that names a commit must be an ancestor of HEAD
// (git merge-base --is-ancestor <sha> HEAD) -- a merge badge, a PR's
// "Merged" label, or an approval is never sufficient evidence on its own.
// Every claim with no single commit must say so via noSingleCommitReason,
// not be silently absent from this registry.
func TestG80TriageDocClosuresAreAncestorsOfHEAD(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available on PATH")
	}
	var notAncestor []string
	var malformed []string
	for _, c := range g80TriageClosureClaims {
		if c.sha == "" {
			if strings.TrimSpace(c.noSingleCommitReason) == "" {
				malformed = append(malformed, c.label+" (neither sha nor noSingleCommitReason set)")
			} else {
				t.Logf("NO SINGLE COMMIT for %q: %s", c.label, c.noSingleCommitReason)
			}
			continue
		}
		if c.noSingleCommitReason != "" {
			malformed = append(malformed, c.label+" (both sha and noSingleCommitReason set -- pick one)")
			continue
		}
		cmd := exec.Command("git", "merge-base", "--is-ancestor", c.sha, "HEAD")
		out, err := cmd.CombinedOutput()
		if err != nil {
			notAncestor = append(notAncestor, c.label+" (commit "+c.sha+"): "+strings.TrimSpace(string(out))+" ["+err.Error()+"]")
		}
	}
	if len(malformed) > 0 {
		t.Errorf("%d closure claim(s) malformed in this file's registry: %v", len(malformed), malformed)
	}
	if len(notAncestor) > 0 {
		t.Errorf("%d closure claim(s) reference a commit that is NOT an ancestor of HEAD -- a merge badge or PR "+
			"label is not evidence of a merge, verify with git merge-base --is-ancestor before trusting a FIXED "+
			"claim: %v", len(notAncestor), notAncestor)
	}
}
