#!/usr/bin/env bash
# scripts/ci/check-tool-versions.sh -- drift check between
# scripts/ci/tool-versions.env and the tool versions the workflows pin
# (TOOLCHAIN-UNIFY-1).
#
# Exit 0: every pin matches. Exit 1: drift (a workflow pins a listed tool at a
# version other than the env file's, a listed tool is no longer pinned in any
# workflow, or a pin goes through a variable the check cannot follow). Exit 2:
# the check could not run (unreadable or malformed env file, unknown or missing
# key, no workflow files, a KEY: entry whose value is not a literal). It never
# reports green on input it could not parse.
#
# Scanned: .github/workflows/*.yml|*.yaml and .github/actions/**/action.y*ml
# under --root. Full-line YAML comments are skipped. What it recognises, per
# key (this list is the whole of it; a pin written in any other shape is NOT
# seen, so add the shape here before using it in a workflow):
#   - env entries `KEY: value` (job, step or workflow level) and shell
#     assignments `KEY=value`, for every *_VERSION key except GOVULNCHECK and
#     SEMGREP;
#   - `go install <module>@<ver>` paths of golangci-lint, gosec, go-licenses,
#     govulncheck, nuclei, actionlint, kubeconform, kube-score;
#   - GitHub release download URLs (<owner>/<repo>/releases/download/<ver>) of
#     gitleaks, trivy, nuclei, actionlint, checkov, kubeconform, kube-score,
#     and any releases/latest URL of those repos (always drift: unpinned);
#   - container images: semgrep/semgrep and returntocorp/semgrep (tag AND
#     @sha256 digest required), aquasec/trivy, zricethezav/gitleaks,
#     ghcr.io/gitleaks/gitleaks, rhysd/actionlint, bridgecrew/checkov;
#   - `pip install checkov==` / `semgrep==`;
#   - the `version:` input of golangci/golangci-lint-action (a step using the
#     action without `version:` is drift: the action would pick one).
# A recognised pin whose version is a variable must name the tool's own key
# (${KEY}, $KEY or ${{ env.KEY }}); the KEY: entries are what get compared.
# Version strings compare with a leading "v" ignored, so a release URL's
# ".../download/v${X}" and "X: v1.2.3" agree.
#
# Not checked: action refs (uses: owner/repo@sha), Go itself (go.mod and
# setup-go), tools outside the env file; see reports/SESSION-TOOLCHAIN-UNIFY-1.md
# for the follow-up list.
#
# Usage: scripts/ci/check-tool-versions.sh [--root DIR] [--env FILE]
#   --root  repository root to scan (default: two levels above this script)
#   --env   tool-versions file (default: <this dir>/tool-versions.env)
# Self-test: scripts/ci/check-tool-versions-test.sh.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root="$here/../.."
envf="$here/tool-versions.env"
while [ $# -gt 0 ]; do
	case $1 in
	--root)
		root=${2:?--root needs a directory}
		shift 2
		;;
	--env)
		envf=${2:?--env needs a file}
		shift 2
		;;
	*)
		echo "check-tool-versions: unknown argument: $1" >&2
		exit 2
		;;
	esac
done

if [ ! -r "$envf" ]; then
	echo "check-tool-versions: cannot read $envf" >&2
	exit 2
fi
if [ ! -d "$root/.github" ]; then
	echo "check-tool-versions: $root/.github is not a directory" >&2
	exit 2
fi

files=()
while IFS= read -r f; do
	files+=("$f")
done < <(
	find "$root/.github/workflows" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null
	if [ -d "$root/.github/actions" ]; then
		find "$root/.github/actions" -type f \( -name 'action.yml' -o -name 'action.yaml' \)
	fi
)
if [ "${#files[@]}" -eq 0 ]; then
	echo "check-tool-versions: no workflow files under $root/.github" >&2
	exit 2
fi
for f in "${files[@]}"; do
	if [ ! -r "$f" ]; then
		echo "check-tool-versions: cannot read $f" >&2
		exit 2
	fi
done

# POSIX awk only (mawk on the runners, BSD awk on a Mac): no gensub, no
# match() array, no regex intervals.
awk -v envf="$envf" -v root="$root/" '
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
function nov(s) { sub(/^v/, "", s); return s }
function rel(f) { return index(f, root) == 1 ? substr(f, length(root) + 1) : f }
function drift(msg) { print "DRIFT " rel(FILENAME) ":" FNR ": " msg; ndrift++ }
function perr(msg) { print "ERROR " rel(FILENAME) ":" FNR ": " msg; nerr++ }

# token(s): the version token at the start of s: ${{ env.X }}, ${X}, $X or a
# literal run of version characters ("" when there is none).
function token(s,   e) {
	if (substr(s, 1, 3) == "${{") { e = index(s, "}}"); return e ? substr(s, 1, e + 1) : "" }
	if (substr(s, 1, 2) == "${") { e = index(s, "}"); return e ? substr(s, 1, e) : "" }
	if (match(s, /^\$[A-Za-z_][A-Za-z0-9_]*/)) return substr(s, 1, RLENGTH)
	if (match(s, /^[0-9A-Za-z][0-9A-Za-z._+-]*/)) return substr(s, 1, RLENGTH)
	return ""
}
# refname(tok): the variable a token names, "" for a literal.
function refname(tok,   s) {
	if (substr(tok, 1, 1) != "$") return ""
	s = tok
	sub(/^\$\{\{[ \t]*(env\.)?/, "", s); sub(/^\$\{?/, "", s)
	match(s, /^[A-Za-z_][A-Za-z0-9_]*/)
	return RLENGTH > 0 ? substr(s, 1, RLENGTH) : "?"
}
# pin(key, tok, what): one recognised pin of key.
function pin(key, tok, what,   r) {
	if (tok == "") { perr(key ": " what ": no version after the pin"); return }
	r = refname(tok)
	if (r != "") {
		if (r != key) drift(key ": " what " takes its version from " tok ", not from " key " (the check cannot follow it)")
		return
	}
	found[key]++
	if (nov(tok) != nov(want[key])) drift(key ": " what " pins " tok ", tool-versions.env has " want[key])
}
# scan(line, key, rx, what, isimg): every match of rx in line is a pin of key.
function scan(line, key, rx, what, isimg,   rest, tok, after, dg) {
	rest = line
	while (match(rest, rx)) {
		rest = substr(rest, RSTART + RLENGTH)
		tok = token(rest)
		pin(key, tok, what)
		if (isimg == "digest") {
			after = substr(rest, length(tok) + 1)
			if (match(after, /^@sha256:[0-9a-f]+/) && RLENGTH == 72) {
				dg = substr(after, 2, RLENGTH - 1)
				found["SEMGREP_IMAGE_DIGEST"]++
				if (dg != want["SEMGREP_IMAGE_DIGEST"]) drift("SEMGREP_IMAGE_DIGEST: " what " digest " dg ", tool-versions.env has " want["SEMGREP_IMAGE_DIGEST"])
			} else {
				drift("SEMGREP_IMAGE_DIGEST: " what ":" tok " is not pinned to a @sha256 digest")
			}
		}
	}
}

BEGIN {
	# envkeys: checked through their KEY: entries; every key in known must be
	# in the env file, and the env file may hold no other key.
	nek = split("GOLANGCI_LINT_VERSION GOSEC_VERSION GITLEAKS_VERSION TRIVY_VERSION NUCLEI_VERSION ACTIONLINT_VERSION CHECKOV_VERSION KUBECONFORM_VERSION KUBE_SCORE_VERSION GO_LICENSES_VERSION", envkey, " ")
	for (i = 1; i <= nek; i++) known[envkey[i]] = 1
	known["GOVULNCHECK_VERSION"] = 1
	known["SEMGREP_VERSION"] = 1
	known["SEMGREP_IMAGE_DIGEST"] = 1

	# inline patterns: rx (ending right before the version), key, label.
	n = 0
	P[++n] = "golangci-lint(/v[0-9]+)?/cmd/golangci-lint@";       K[n] = "GOLANGCI_LINT_VERSION"; L[n] = "go install golangci-lint"
	P[++n] = "securego/gosec(/v[0-9]+)?(/cmd/gosec)?@";            K[n] = "GOSEC_VERSION";         L[n] = "go install/get gosec"
	P[++n] = "google/go-licenses(/v[0-9]+)?@";                     K[n] = "GO_LICENSES_VERSION";   L[n] = "go install go-licenses"
	P[++n] = "golang\\.org/x/vuln/cmd/govulncheck@";              K[n] = "GOVULNCHECK_VERSION";   L[n] = "go install govulncheck"
	P[++n] = "projectdiscovery/nuclei(/v[0-9]+)?/cmd/nuclei@";     K[n] = "NUCLEI_VERSION";        L[n] = "go install nuclei"
	P[++n] = "rhysd/actionlint/cmd/actionlint@";                   K[n] = "ACTIONLINT_VERSION";    L[n] = "go install actionlint"
	P[++n] = "yannh/kubeconform/cmd/kubeconform@";                 K[n] = "KUBECONFORM_VERSION";   L[n] = "go install kubeconform"
	P[++n] = "zegl/kube-score/cmd/kube-score@";                    K[n] = "KUBE_SCORE_VERSION";    L[n] = "go install kube-score"
	nrel = split("gitleaks/gitleaks=GITLEAKS_VERSION aquasecurity/trivy=TRIVY_VERSION projectdiscovery/nuclei=NUCLEI_VERSION rhysd/actionlint=ACTIONLINT_VERSION bridgecrewio/checkov=CHECKOV_VERSION yannh/kubeconform=KUBECONFORM_VERSION zegl/kube-score=KUBE_SCORE_VERSION", rels, " ")
	for (i = 1; i <= nrel; i++) {
		split(rels[i], kv, "=")
		rx = kv[1]; gsub(/\./, "\\.", rx)
		P[++n] = rx "/releases/download/v?"; K[n] = kv[2]; L[n] = kv[1] " release download"
		latest[rx "/releases/latest"] = kv[2]
	}
	P[++n] = "(^|[^A-Za-z0-9_./-])aquasec/trivy:";                K[n] = "TRIVY_VERSION";         L[n] = "image aquasec/trivy"
	P[++n] = "(zricethezav|ghcr\\.io/gitleaks)/gitleaks:";        K[n] = "GITLEAKS_VERSION";      L[n] = "image gitleaks"
	P[++n] = "(^|[^A-Za-z0-9_./-])rhysd/actionlint:";             K[n] = "ACTIONLINT_VERSION";    L[n] = "image rhysd/actionlint"
	P[++n] = "bridgecrew/checkov:";                                K[n] = "CHECKOV_VERSION";       L[n] = "image bridgecrew/checkov"
	P[++n] = "checkov==";                                          K[n] = "CHECKOV_VERSION";       L[n] = "pip install checkov"
	P[++n] = "semgrep==";                                          K[n] = "SEMGREP_VERSION";       L[n] = "pip install semgrep"
	np = n
	SEMRX = "(semgrep|returntocorp)/semgrep:"

	# The env file, before any workflow.
	while ((rc = (getline line < envf)) > 0) {
		ln++
		sub(/\r$/, "", line)
		if (line ~ /^[ \t]*(#|$)/) continue
		if (line !~ /^[A-Z][A-Z0-9_]*=[^ \t"\047]+$/) { print "ERROR " envf ":" ln ": not KEY=value: " line; nerr++; continue }
		k = substr(line, 1, index(line, "=") - 1); v = substr(line, index(line, "=") + 1)
		if (!(k in known)) { print "ERROR " envf ":" ln ": unknown key " k " (check-tool-versions.sh does not know where to find it)"; nerr++; continue }
		if (k in want) { print "ERROR " envf ":" ln ": duplicate key " k; nerr++; continue }
		want[k] = v; order[++nk] = k
	}
	if (rc < 0) { print "ERROR cannot read " envf; nerr++ }
	for (k in known) if (!(k in want)) { print "ERROR " envf ": missing key " k; nerr++ }
	if (nerr) { bad = 1; exit 2 }
	if (want["SEMGREP_IMAGE_DIGEST"] !~ /^sha256:[0-9a-f]+$/ || length(want["SEMGREP_IMAGE_DIGEST"]) != 71) { print "ERROR " envf ": SEMGREP_IMAGE_DIGEST is not sha256:<64 hex>"; bad = 1; exit 2 }
}

FNR == 1 {
	if (gl) { print "DRIFT " rel(lastfile) ":" glline ": GOLANGCI_LINT_VERSION: golangci/golangci-lint-action step has no version: input"; ndrift++ }
	gl = 0; lastfile = FILENAME
}
{
	line = $0
	sub(/\r$/, "", line)
	if (line ~ /^[ \t]*#/) next

	# golangci-lint-action: its version: input, until the step ends (the
	# first non-blank line indented less than the keys of the step).
	if (gl && line !~ /^[ \t]*$/) {
		match(line, /^[ \t]*/)
		if (RLENGTH < glind) {
			drift("GOLANGCI_LINT_VERSION: golangci/golangci-lint-action step (line " glline ") has no version: input")
			gl = 0
		}
	}
	if (match(line, /uses:[ \t]*["\047]?golangci\/golangci-lint-action@/)) { gl = 1; glline = FNR; glind = RSTART - 1 }
	else if (gl && match(line, /^[ \t]*version:[ \t]*/)) {
		v = trim(substr(line, RLENGTH + 1)); sub(/[ \t]+#.*$/, "", v); gsub(/["\047]/, "", v)
		pin("GOLANGCI_LINT_VERSION", token(v), "golangci-lint-action version:")
		gl = 0
	}

	# KEY: value entries and KEY=value assignments.
	t = line; sub(/^[ \t]*(-[ \t]+)?/, "", t)
	for (i = 1; i <= nek; i++) {
		k = envkey[i]
		if (index(t, k ":") == 1) {
			v = trim(substr(t, length(k) + 2)); sub(/[ \t]+#.*$/, "", v)
			if (v ~ /^".*"$/ || v ~ /^\047.*\047$/) v = substr(v, 2, length(v) - 2)
			if (v !~ /^[0-9A-Za-z][0-9A-Za-z._+-]*$/) { perr(k ": value " (v == "" ? "(empty)" : v) " is not a literal version"); continue }
			found[k]++
			if (v != want[k]) drift(k ": " v ", tool-versions.env has " want[k])
		}
		rest = line
		while (match(rest, "(^|[^A-Za-z0-9_])" k "=")) {
			rest = substr(rest, RSTART + RLENGTH)
			s = rest; if (substr(s, 1, 1) == "\"" || substr(s, 1, 1) == "\047") s = substr(s, 2)
			pin(k, token(s), "shell assignment " k "=")
		}
	}

	for (i = 1; i <= np; i++) scan(line, K[i], P[i], L[i], "")
	scan(line, "SEMGREP_VERSION", SEMRX, "image semgrep/semgrep", "digest")
	for (rx in latest) if (match(line, rx)) drift(latest[rx] ": " substr(line, RSTART, RLENGTH) " is unpinned")
}

END {
	if (bad) exit 2
	if (gl) { print "DRIFT " rel(lastfile) ":" glline ": GOLANGCI_LINT_VERSION: golangci/golangci-lint-action step has no version: input"; ndrift++ }
	for (k in want) {
		if (found[k] + 0 == 0) { print "DRIFT " k ": not pinned in any workflow (remove it from tool-versions.env, or restore the pin)"; ndrift++ }
	}
	if (nerr) { print "check-tool-versions: ERROR -- " nerr " unparseable pin(s); not reporting green"; exit 2 }
	if (ndrift) { print "check-tool-versions: FAILED -- " ndrift " drift finding(s) against " envf; exit 1 }
	print "check-tool-versions: OK -- " nk " keys, every workflow pin matches " envf
	for (i = 1; i <= nk; i++) { k = order[i]; printf "  %-22s %-14s %d pin(s)\n", k, (k == "SEMGREP_IMAGE_DIGEST" ? substr(want[k], 1, 19) "..." : want[k]), found[k] }
}
' "${files[@]}"
