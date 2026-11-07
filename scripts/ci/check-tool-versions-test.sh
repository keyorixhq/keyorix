#!/usr/bin/env bash
# scripts/ci/check-tool-versions-test.sh -- offline calibration for
# check-tool-versions.sh, both directions: green on an untouched copy of this
# repo's workflows and tool-versions.env (and on pins it must ignore), red on
# every drift shape it claims to catch, and exit 2 (never green) on input it
# cannot parse. Each case mutates a fresh copy of the REAL workflows, using the
# versions read from the real tool-versions.env, so the cases keep testing the
# live pins after a version bump.
#
# Usage: scripts/ci/check-tool-versions-test.sh   (from anywhere)
#
# The workflow fixtures below are literal YAML: their ${...} must not expand.
# shellcheck disable=SC2016
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script="$here/check-tool-versions.sh"
src_root=$(cd "$here/../.." && pwd)
src_env="$here/tool-versions.env"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

pass=0
fail=0

val() { sed -n "s/^$1=//p" "$src_env"; }

# fresh: a new copy of the workflows and env file at $work/repo.
fresh() {
	rm -rf "$work/repo"
	mkdir -p "$work/repo/.github"
	cp -R "$src_root/.github/workflows" "$work/repo/.github/workflows"
	cp "$src_env" "$work/repo/tool-versions.env"
}

# edit FILE SED-EXPR: rewrites FILE (relative to the copy) and fails the case
# setup when the expression changed nothing, so a stale case cannot pass.
edit() {
	local f="$work/repo/$1"
	sed -e "$2" "$f" >"$f.new"
	if cmp -s "$f" "$f.new"; then
		echo "SETUP: '$2' changed nothing in $1" >&2
		exit 3
	fi
	mv "$f.new" "$f"
}

# add NAME CONTENT: a new workflow file in the copy.
add() { printf '%s\n' "$2" >"$work/repo/.github/workflows/$1"; }

# expect STATUS GREP DESC: runs the check on the copy; wants exit STATUS and,
# when GREP is not empty, an output line matching it.
expect() {
	local want=$1 rx=$2 desc=$3 got=0 out
	out=$(bash "$script" --root "$work/repo" --env "$work/repo/tool-versions.env" 2>&1) || got=$?
	if [ "$got" -ne "$want" ]; then
		fail=$((fail + 1))
		printf 'FAIL: %s: want exit %s, got %s\n%s\n' "$desc" "$want" "$got" "$out" >&2
	elif [ -n "$rx" ] && ! printf '%s\n' "$out" | grep -qE -- "$rx"; then
		fail=$((fail + 1))
		printf 'FAIL: %s: exit %s but no line matching /%s/\n%s\n' "$desc" "$got" "$rx" "$out" >&2
	else
		pass=$((pass + 1))
		printf 'ok   %-62s exit %s\n' "$desc" "$got"
	fi
}

gosec=$(val GOSEC_VERSION)
govuln=$(val GOVULNCHECK_VERSION)
semver=$(val SEMGREP_VERSION)
semdg=$(val SEMGREP_IMAGE_DIGEST)
for v in "$gosec" "$govuln" "$semver" "$semdg"; do
	[ -n "$v" ] || { echo "SETUP: a key is missing from $src_env" >&2; exit 3; }
done

# --- green ---------------------------------------------------------------------
fresh
expect 0 '^check-tool-versions: OK' "untouched copy of the workflows"

fresh
add ignored.yml 'jobs:
  x:
    runs-on: ubuntu-24.04
    steps:
      # GOSEC_VERSION: v0.0.1 and go install golang.org/x/vuln/cmd/govulncheck@v0.0.1
      - run: echo "${GOSEC_VERSION}" && go install "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}"
      - uses: golangci/golangci-lint-action@ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a
        with:
          version: ${{ env.GOLANGCI_LINT_VERSION }}'
expect 0 '^check-tool-versions: OK' "comments and own-key references are not pins"

# --- red: a workflow pin differs ------------------------------------------------
fresh
edit .github/workflows/ci.yml "s/^\([[:space:]]*GOSEC_VERSION:\) $gosec\$/\1 v0.0.0-drift/"
expect 1 '^DRIFT \.github/workflows/ci\.yml:[0-9]+: GOSEC_VERSION: v0\.0\.0-drift' "env entry GOSEC_VERSION drifted in ci.yml"

fresh
edit tool-versions.env "s/^TRIVY_VERSION=.*/TRIVY_VERSION=9.9.9/"
expect 1 'TRIVY_VERSION: .*tool-versions\.env has 9\.9\.9' "tool-versions.env drifted, workflows not"

fresh
edit .github/workflows/ci.yml "s#govulncheck@$govuln#govulncheck@v9.9.9#"
expect 1 'GOVULNCHECK_VERSION: go install govulncheck pins v9\.9\.9' "inline govulncheck@ version drifted"

fresh
edit .github/workflows/govulncheck-scheduled.yml "s#govulncheck@$govuln#govulncheck@latest#"
expect 1 'GOVULNCHECK_VERSION: .*pins latest' "govulncheck@latest"

fresh
edit .github/workflows/semgrep.yml "s#semgrep:$semver@#semgrep:1.0.0@#"
expect 1 'SEMGREP_VERSION: image semgrep/semgrep pins 1\.0\.0' "semgrep image tag drifted"

fresh
edit .github/workflows/semgrep.yml "s#@$semdg#@sha256:0000000000000000000000000000000000000000000000000000000000000000#"
expect 1 'SEMGREP_IMAGE_DIGEST: .*digest sha256:0000' "semgrep image digest drifted"

fresh
edit .github/workflows/semgrep.yml "s#@$semdg##"
expect 1 'SEMGREP_IMAGE_DIGEST: .*not pinned to a @sha256 digest' "semgrep image digest removed"

# --- red: a pin the env entries do not cover -------------------------------------
fresh
add extra.yml 'jobs:
  x:
    runs-on: ubuntu-24.04
    steps:
      - run: curl -fsSLO https://github.com/gitleaks/gitleaks/releases/download/v8.0.0/gitleaks_8.0.0_linux_x64.tar.gz'
expect 1 'GITLEAKS_VERSION: gitleaks/gitleaks release download pins 8\.0\.0' "second, literal gitleaks release URL"

fresh
add extra.yml 'jobs:
  x:
    runs-on: ubuntu-24.04
    steps:
      - run: curl -fsSLO https://github.com/aquasecurity/trivy/releases/latest/download/trivy.tar.gz'
expect 1 'TRIVY_VERSION: aquasecurity/trivy/releases/latest is unpinned' "releases/latest URL"

fresh
add extra.yml 'jobs:
  x:
    runs-on: ubuntu-24.04
    steps:
      - run: docker run --rm aquasec/trivy:0.1.0 image foo'
expect 1 'TRIVY_VERSION: image aquasec/trivy pins 0\.1\.0' "docker image aquasec/trivy with another tag"

fresh
add extra.yml 'jobs:
  x:
    runs-on: ubuntu-24.04
    env:
      MY_GOSEC: v2.0.0
    steps:
      - run: go install github.com/securego/gosec/v2/cmd/gosec@${MY_GOSEC}'
expect 1 'GOSEC_VERSION: .*takes its version from \$\{MY_GOSEC\}' "gosec pinned through a variable the check cannot follow"

fresh
add extra.yml 'jobs:
  x:
    runs-on: ubuntu-24.04
    steps:
      - run: GOSEC_VERSION=v2.0.0 scripts/ci/install-gosec.sh bin/gosec'
expect 1 'GOSEC_VERSION: shell assignment GOSEC_VERSION= pins v2\.0\.0' "shell assignment GOSEC_VERSION=<other>"

fresh
add extra.yml 'jobs:
  x:
    runs-on: ubuntu-24.04
    steps:
      - uses: golangci/golangci-lint-action@ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a
        with:
          version: v2.1.0
      - run: true'
expect 1 'GOLANGCI_LINT_VERSION: golangci-lint-action version: pins v2\.1\.0' "golangci-lint-action with another version"

fresh
add extra.yml 'jobs:
  x:
    runs-on: ubuntu-24.04
    steps:
      - name: lint
        uses: golangci/golangci-lint-action@ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a
        with:
          args: --timeout 5m
      - run: true'
expect 1 'golangci-lint-action step \(line 6\) has no version: input' "golangci-lint-action without version:"

fresh
edit .github/workflows/dast.yml '/^[[:space:]]*NUCLEI_VERSION:/d'
expect 1 '^DRIFT NUCLEI_VERSION: not pinned in any workflow' "listed tool no longer pinned anywhere"

# --- exit 2: cannot parse -> never green -------------------------------------------
fresh
edit .github/workflows/ci.yml "s/^\([[:space:]]*GOSEC_VERSION:\) $gosec\$/\1 \${{ vars.GOSEC }}/"
expect 2 'GOSEC_VERSION: value .* is not a literal version' "KEY: entry with an expression value"

fresh
printf 'this is not KEY=value\n' >>"$work/repo/tool-versions.env"
expect 2 'not KEY=value' "env file line that is not KEY=value"

fresh
printf 'SYFT_VERSION=1.0.0\n' >>"$work/repo/tool-versions.env"
expect 2 'unknown key SYFT_VERSION' "env file key the check does not know"

fresh
edit tool-versions.env '/^CHECKOV_VERSION=/d'
expect 2 'missing key CHECKOV_VERSION' "env file without a known key"

fresh
printf 'GOSEC_VERSION=%s\n' "$gosec" >>"$work/repo/tool-versions.env"
expect 2 'duplicate key GOSEC_VERSION' "env file with a duplicate key"

fresh
edit tool-versions.env 's/^SEMGREP_IMAGE_DIGEST=.*/SEMGREP_IMAGE_DIGEST=1.172.0/'
expect 2 'SEMGREP_IMAGE_DIGEST is not sha256' "env file digest not sha256:<hex>"

fresh
rm -rf "$work/repo/.github/workflows"
mkdir -p "$work/repo/.github/workflows"
expect 2 'no workflow files' "no workflow files"

echo "check-tool-versions-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
