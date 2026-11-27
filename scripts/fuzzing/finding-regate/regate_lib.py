"""regate_lib.py: finding-regate library — deterministic, no network, standard library only.

Mapping strategy (in priority order):
  1. Crasher-path decoding: crashers/keyorix/<module_enc>/<FuncName>/<hash>
     → strip the keyorix module prefix → repo-relative package path
     → look up FuncName in targets.d to validate the package (targets.d wins if present)
  2. repro.regression_test field: first whitespace-separated token that looks like a
     Go package path → package; Fuzz* words in the same value → func names
  3. fix_prs changed-files derivation: NOT implemented here — requires network or a
     git-log query. Documented as future work.

What this does NOT map:
- Upstream findings (scope != first-party, module != keyorix): logged, not run.
- Findings whose crashers live outside crashers/keyorix/ (e.g. hostile-backend,
  dashdiag): those fuzz targets are not in this repo's targets.d.
- Findings with no crasher and no reg_test with a recognisable package path.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Callable

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

KEYORIX_MODULE_ENC_PREFIX = "github.com_keyorixhq_keyorix_"
_PKG_RE = re.compile(r"^[a-z][a-z0-9/._-]*(?:/[a-z][a-z0-9/._-]*)*$")
_FUZZ_RE = re.compile(r"\bFuzz[A-Za-z0-9]+\b")


@dataclass
class Target:
    pkg: str       # repo-relative Go package path, e.g. "internal/connect"
    func: str      # Fuzz function name, e.g. "FuzzAWSSMConnectorResponse"


@dataclass
class FindingMeta:
    id: str
    title: str
    scope: str
    module: str
    disposition: str
    targets: list[Target] = field(default_factory=list)
    seed_names: list[str] = field(default_factory=list)   # entries in testdata/fuzz/<func>/


@dataclass
class RunResult:
    finding_id: str
    target: Target
    seed_name: str | None     # None → burst run
    ok: bool
    output: str
    error_msg: str = ""


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_target_map(targets_d: str) -> dict[str, str]:
    """Return {FuncName: package_path} from scripts/fuzzing/targets.d/*.conf files."""
    out: dict[str, str] = {}
    for fname in sorted(os.listdir(targets_d)):
        if not fname.endswith(".conf"):
            continue
        fpath = os.path.join(targets_d, fname)
        with open(fpath) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) < 2:
                    continue
                pkg, func = parts[0].strip(), parts[1].strip()
                if pkg and func:
                    out[func] = pkg
    return out


def derive_finding_targets(finding: dict, target_map: dict[str, str]) -> list[Target]:
    """Derive (pkg, func) pairs from a finding using the three derivation methods."""
    result: list[Target] = []
    seen: set[tuple[str, str]] = set()

    def add(pkg: str, func: str) -> None:
        key = (pkg, func)
        if key not in seen:
            seen.add(key)
            result.append(Target(pkg=pkg, func=func))

    # Method 1: crasher path decoding
    for crasher in finding.get("crashers", []):
        parts = crasher.split("/")
        # Format: crashers/keyorix/<module_enc>/<FuncName>/<hash>
        if len(parts) < 4:
            continue
        if parts[0] != "crashers" or parts[1] != "keyorix":
            continue
        module_enc = parts[2]
        func = parts[3]
        # Validate: func must look like Fuzz*
        if not func.startswith("Fuzz"):
            continue
        # targets.d takes precedence for the package path
        if func in target_map:
            add(target_map[func], func)
        elif module_enc.startswith(KEYORIX_MODULE_ENC_PREFIX):
            # Decode: strip prefix, replace _ with /
            suffix = module_enc[len(KEYORIX_MODULE_ENC_PREFIX):]
            pkg = suffix.replace("_", "/")
            add(pkg, func)

    # Method 2: repro.regression_test field
    reg = finding.get("repro", {}).get("regression_test", "") or ""
    if reg:
        # Must not look like a private ~/proj/ path
        if not reg.startswith("~/"):
            # Pass 2a: extract any Fuzz* names and look them up in targets.d first.
            # This catches "cli FuzzDotenvRoundTrip, ..." where "cli" alone has no slash
            # but the Fuzz* names are authoritative.
            funcs_in_reg = _FUZZ_RE.findall(reg)
            funcs_resolved = [f for f in funcs_in_reg if f in target_map]
            for func in funcs_resolved:
                add(target_map[func], func)

            # Pass 2b: first token that looks like a full Go package path (requires "/")
            first = reg.split()[0] if reg.split() else ""
            if first and _PKG_RE.match(first) and "/" in first:
                pkg = first
                if funcs_in_reg:
                    for func in funcs_in_reg:
                        # use targets.d pkg if available, else the stated pkg
                        actual_pkg = target_map.get(func, pkg)
                        add(actual_pkg, func)
                else:
                    # Package-only: add with empty func so the package is still watched
                    add(pkg, "")

    return result


def load_findings(registry_dir: str, target_map: dict[str, str]) -> list[FindingMeta]:
    """Load all findings from registry_dir and derive targets for each."""
    out: list[FindingMeta] = []
    for fname in sorted(os.listdir(registry_dir)):
        if not (fname.startswith("KFZ-") and fname.endswith(".json")):
            continue
        fpath = os.path.join(registry_dir, fname)
        with open(fpath) as fh:
            d = json.load(fh)
        targets = derive_finding_targets(d, target_map)
        fm = FindingMeta(
            id=d.get("id", fname[:-5]),
            title=d.get("title", ""),
            scope=d.get("scope", ""),
            module=d.get("module", ""),
            disposition=d.get("disposition", ""),
            targets=targets,
        )
        out.append(fm)
    return out


# ---------------------------------------------------------------------------
# Diff → package mapping
# ---------------------------------------------------------------------------

def changed_packages(diff_names: list[str]) -> set[str]:
    """Convert a list of repo-relative changed file paths to package prefixes.

    "internal/connect/connector.go" → "internal/connect"
    "cli/cmd/secret.go" → "cli/cmd"

    Only .go files are considered; generated files (*_generated.go) are included
    since a generation change can still re-introduce a bug.
    """
    pkgs: set[str] = set()
    for name in diff_names:
        name = name.strip()
        if not name.endswith(".go"):
            continue
        pkg = os.path.dirname(name)
        if pkg:
            pkgs.add(pkg)
    return pkgs


def git_diff_names(diff_range: str, repo_root: str) -> list[str]:
    """Run 'git diff --name-only <diff_range>' and return the lines."""
    result = subprocess.run(
        ["git", "diff", "--name-only", diff_range],
        capture_output=True, text=True, check=True,
        cwd=repo_root,
    )
    return [l for l in result.stdout.splitlines() if l]


def git_staged_names(repo_root: str) -> list[str]:
    """Return staged file names (for local testing)."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        capture_output=True, text=True, check=True,
        cwd=repo_root,
    )
    return [l for l in result.stdout.splitlines() if l]


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _pkg_matches(changed: set[str], target_pkg: str) -> bool:
    """True if any changed package is the target package or a sub-package of it."""
    # Exact match or changed pkg starts with target_pkg/
    for cpkg in changed:
        if cpkg == target_pkg or cpkg.startswith(target_pkg + "/"):
            return True
    return False


def match_findings(
    findings: list[FindingMeta],
    changed_pkgs: set[str],
) -> list[FindingMeta]:
    """Return findings with at least one target package overlapping with changed_pkgs."""
    matched: list[FindingMeta] = []
    for fm in findings:
        if fm.disposition != "active":
            continue
        for t in fm.targets:
            if t.pkg and _pkg_matches(changed_pkgs, t.pkg):
                matched.append(fm)
                break
    return matched


# ---------------------------------------------------------------------------
# Seed-corpus discovery
# ---------------------------------------------------------------------------

def find_seeds(repo_root: str, func_name: str) -> list[str]:
    """Return seed file names (not full paths) in testdata/fuzz/<func_name>/.

    Searches from the repo root recursively: some packages have testdata/fuzz/ at
    different depths.  Returns relative-to-repo-root paths like
    "internal/connect/testdata/fuzz/FuzzAWSSMConnectorResponse/abc123def456".
    """
    seeds: list[str] = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        # Skip hidden dirs and vendor
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d != "vendor"]
        base = os.path.basename(dirpath)
        parent = os.path.basename(os.path.dirname(dirpath))
        if base == func_name and parent == "fuzz":
            for fname in sorted(filenames):
                rel = os.path.relpath(os.path.join(dirpath, fname), repo_root)
                seeds.append(rel)
    return seeds


def check_seed_exists(repo_root: str, seed_rel: str) -> bool:
    """Return True if the seed file exists on disk."""
    return os.path.isfile(os.path.join(repo_root, seed_rel))


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------

GoTestRunner = Callable[[list[str], str], tuple[int, str]]
"""(cmd_args, cwd) → (returncode, combined_output)"""


def _default_runner(cmd: list[str], cwd: str) -> tuple[int, str]:
    # GOCACHE, GOMODCACHE and TMPDIR are the caller's business: go uses its own
    # defaults unless the calling environment sets them.
    env = os.environ.copy()
    env["GOMAXPROCS"] = "2"
    # Lower the priority when nice exists; run unwrapped otherwise.
    prefix = ["nice", "-n", "10"] if shutil.which("nice") else []
    result = subprocess.run(
        prefix + cmd,
        capture_output=True, text=True,
        cwd=cwd, env=env,
    )
    return result.returncode, result.stdout + result.stderr


def replay_seed(
    target: Target,
    seed_rel: str,         # repo-relative path to the seed file
    repo_root: str,
    runner: GoTestRunner = _default_runner,
) -> RunResult:
    """Replay a single seed corpus entry with go test -run 'FuzzXxx/seedname'."""
    seed_name = os.path.basename(seed_rel)
    pkg_dir = os.path.join(repo_root, target.pkg)
    run_flag = f"^{re.escape(target.func)}$/{re.escape(seed_name)}"
    cmd = ["go", "test", "-run", run_flag, "-v", "."]
    rc, out = runner(cmd, pkg_dir)
    # go test -run exits 0 with "no tests to run" when the pattern matches
    # nothing (renamed func, package without the target), so rc == 0 alone
    # would pass vacuously. Require the subtest's own PASS line.
    pass_line = re.compile(
        rf"^\s*--- PASS: {re.escape(target.func)}/{re.escape(seed_name)}(\s|$)",
        re.MULTILINE,
    )
    if rc != 0:
        ok, error_msg = False, f"exit {rc}"
    elif not pass_line.search(out):
        ok = False
        error_msg = (
            f"exit 0 but no '--- PASS: {target.func}/{seed_name}' line in the "
            "output: the seed was not replayed (func renamed or removed?)"
        )
    else:
        ok, error_msg = True, ""
    return RunResult(
        finding_id="",
        target=target,
        seed_name=seed_name,
        ok=ok,
        output=out,
        error_msg=error_msg,
    )


def run_burst(
    target: Target,
    fuzztime: str,         # e.g. "60s"
    repo_root: str,
    runner: GoTestRunner = _default_runner,
) -> RunResult:
    """Run a fuzz burst: go test -fuzz=FuzzXxx -fuzztime=N ./pkg."""
    pkg_dir = os.path.join(repo_root, target.pkg)
    cmd = [
        "go", "test",
        f"-fuzz=^{target.func}$",
        f"-fuzztime={fuzztime}",
        "-parallel=2",
        ".",
    ]
    rc, out = runner(cmd, pkg_dir)
    # go test -fuzz exits 0 when time expires normally.
    # It exits non-zero if a crash is found.
    ok = rc == 0
    return RunResult(
        finding_id="",
        target=target,
        seed_name=None,
        ok=ok,
        output=out,
        error_msg="" if ok else f"exit {rc}",
    )


# ---------------------------------------------------------------------------
# Public entry point (used by regate.py)
# ---------------------------------------------------------------------------

@dataclass
class GateConfig:
    registry_dir: str
    targets_d: str
    repo_root: str
    fuzztime: str = "60s"
    runner: GoTestRunner = _default_runner
    # If non-empty, only run these finding IDs (for --id filtering)
    only_ids: list[str] = field(default_factory=list)
    # If True, skip the burst step (replay only)
    no_burst: bool = False
    # If True, skip the replay step (burst only)
    no_replay: bool = False


@dataclass
class GateOutput:
    matched_findings: list[FindingMeta]
    rows: list[RunResult]


class RegistryError(Exception):
    pass


class ReproMissingError(Exception):
    """Raised when a registered seed file cannot be found on disk."""

    def __init__(self, finding_id: str, seed_path: str) -> None:
        self.finding_id = finding_id
        self.seed_path = seed_path
        super().__init__(
            f"Seed file for {finding_id} not found: {seed_path}\n"
            "The finding is registered with this seed but it is not committed in\n"
            "testdata/fuzz/. Add it as a regression seed or remove the reference."
        )


def run_gate(
    diff_names: list[str],
    cfg: GateConfig,
    registered_seeds: dict[str, list[str]] | None = None,
) -> GateOutput:
    """Run the full gate for the given diff.

    registered_seeds maps finding_id → list of seed file names (repo-relative).
    If provided, missing seed files raise ReproMissingError.  If None, seeds are
    discovered from the filesystem only.

    Returns GateOutput with the results.  The caller decides exit code.
    """
    if not os.path.isdir(cfg.registry_dir):
        raise RegistryError(f"Registry directory not found: {cfg.registry_dir!r}")
    if not os.path.isdir(cfg.targets_d):
        raise RegistryError(f"targets.d directory not found: {cfg.targets_d!r}")

    target_map = load_target_map(cfg.targets_d)
    findings = load_findings(cfg.registry_dir, target_map)

    if cfg.only_ids:
        id_set = set(cfg.only_ids)
        findings = [f for f in findings if f.id in id_set]

    changed_pkgs = changed_packages(diff_names)
    matched = match_findings(findings, changed_pkgs)

    rows: list[RunResult] = []

    for fm in matched:
        for t in fm.targets:
            if not t.func:
                # Package-only match: cannot run fuzz target, note it
                rows.append(RunResult(
                    finding_id=fm.id,
                    target=t,
                    seed_name=None,
                    ok=True,
                    output="",
                    error_msg="no fuzz func — package watched, burst skipped",
                ))
                continue

            # Seed replay
            if not cfg.no_replay:
                if registered_seeds is not None:
                    # Explicit seed list: check each exists, then replay
                    reg = registered_seeds.get(fm.id, [])
                    for seed_rel in reg:
                        if not check_seed_exists(cfg.repo_root, seed_rel):
                            raise ReproMissingError(fm.id, seed_rel)
                        rr = replay_seed(t, seed_rel, cfg.repo_root, cfg.runner)
                        rr.finding_id = fm.id
                        rows.append(rr)
                else:
                    # Discover seeds from filesystem
                    seeds = find_seeds(cfg.repo_root, t.func)
                    for seed_rel in seeds:
                        rr = replay_seed(t, seed_rel, cfg.repo_root, cfg.runner)
                        rr.finding_id = fm.id
                        rows.append(rr)

            # Burst
            if not cfg.no_burst:
                rr = run_burst(t, cfg.fuzztime, cfg.repo_root, cfg.runner)
                rr.finding_id = fm.id
                rows.append(rr)

    return GateOutput(matched_findings=matched, rows=rows)
