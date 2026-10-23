#!/usr/bin/env bash
# run-tlc.sh — model-check the owed-audit TLA+ model (docs/formal/owed-audit/README.md).
#
#   docs/formal/owed-audit/run-tlc.sh                 # every configuration, expected verdicts checked
#   docs/formal/owed-audit/run-tlc.sh small.cfg       # one configuration, full TLC output
#
# Fetches the pinned TLA+ tools (v1.7.4, SHA-256 checked) into .scratch/tlc/ at the
# repository root on first use, or uses TLA2TOOLS_JAR if set. Needs Java 11 or newer
# (JAVA overrides the java binary). Not run by CI: a docs-only artefact.
set -euo pipefail

TLA_VERSION="v1.7.4"
TLA_SHA256="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
TLA_URL="https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "${here}/../../.." && pwd)"
work="${root}/.scratch/tlc"
java_bin="${JAVA:-java}"
jar="${TLA2TOOLS_JAR:-${work}/tla2tools-${TLA_VERSION}.jar}"

say() { printf '%s\n' "$*" >&2; }

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

mkdir -p "${work}"
if [[ ! -f "${jar}" ]]; then
	say "Fetching TLA+ tools ${TLA_VERSION} from ${TLA_URL} ..."
	curl -fsSL -o "${jar}.part" "${TLA_URL}"
	mv "${jar}.part" "${jar}"
fi
got="$(sha256 "${jar}")"
if [[ -z "${TLA2TOOLS_JAR:-}" && "${got}" != "${TLA_SHA256}" ]]; then
	say "ERROR: ${jar} has SHA-256 ${got}, expected ${TLA_SHA256}. Delete it and re-run, or set TLA2TOOLS_JAR."
	exit 1
fi
if ! "${java_bin}" -version >/dev/null 2>&1; then
	say "ERROR: no working Java runtime ('${java_bin} -version' failed). Install a JDK 11+ or set JAVA=/path/to/java."
	exit 1
fi

# run_one CFG -> prints TLC's output to the file named by $2, returns TLC's exit code.
run_one() {
	local cfg="$1" out="$2" name
	name="$(basename "${cfg}" .cfg)"
	(cd "${here}" && "${java_bin}" -Xmx3g -XX:+UseParallelGC -Djava.io.tmpdir="${work}" \
		-cp "${jar}" tlc2.TLC -workers auto -cleanup -metadir "${work}/states-${name}" \
		-config "${cfg}" MCOwedAudit.tla) >"${out}" 2>&1
}

if [[ $# -ge 1 ]]; then
	say "TLC: $1 (full output follows) ..."
	out="${work}/$(basename "$1" .cfg).out"
	set +e
	run_one "$1" "${out}"
	rc=$?
	set -e
	cat "${out}"
	exit "${rc}"
fi

# Expected verdict per configuration: "pass", the name of the invariant TLC must report
# as violated (a seeded bug, or a documented gap the model exists to show), or
# "temporal" for a configuration whose only PROPERTY must be violated.
expect=(
	"small.cfg:pass"
	"wide.cfg:pass"
	"wide_liveness.cfg:pass"
	"pendingfault_rest.cfg:pass"
	"pendingfault_gap.cfg:NoUnrecordedEffect"
	"pendingfault_silent.cfg:NoSilentLoss"
	"explore_effect_order.cfg:EffectOrderIsChainOrder"
	"bug_widen_owed.cfg:WideningFailClosed"
	"bug_mixed_fail_closed.cfg:temporal"
	"bug_claim_split.cfg:ChainValid"
	"bug_backfill_any_order.cfg:OwedOrderPreserved"
)

fail=0
printf '%-28s %-26s %-26s %12s %8s\n' "config" "expected" "got" "distinct" "seconds"
for e in "${expect[@]}"; do
	cfg="${e%%:*}"
	want="${e#*:}"
	out="${work}/$(basename "${cfg}" .cfg).out"
	say "TLC: ${cfg} (expect ${want}) ..."
	start=$(date +%s)
	set +e
	run_one "${cfg}" "${out}"
	set -e
	secs=$(($(date +%s) - start))
	got="pass"
	if ! grep -q "Model checking completed. No error has been found." "${out}"; then
		got="$(sed -n 's/^Error: Invariant \([A-Za-z]*\) is violated.*/\1/p' "${out}" | head -1)"
		if grep -q "^Error: Temporal properties were violated" "${out}"; then got="temporal"; fi
		[[ -z "${got}" ]] && got="error"
	fi
	distinct="$(grep -oE '[0-9]+ distinct states found' "${out}" | tail -1 | cut -d' ' -f1)"
	ok="ok"
	if [[ "${got}" != "${want}" ]]; then
		ok="MISMATCH"
		fail=1
	fi
	printf '%-28s %-26s %-26s %12s %8s  %s\n' "${cfg}" "${want}" "${got}" "${distinct:-?}" "${secs}" "${ok}"
done
if [[ "${fail}" -ne 0 ]]; then
	say "Some configurations did not give their expected verdict; TLC output is in ${work}/*.out"
	exit 1
fi
say "Done: every configuration gave its expected verdict. TLC output is in ${work}/*.out"
