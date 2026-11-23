# devtools/vacuum

The OpenAPI linter for the `openapi-lint` CI job (`.github/workflows/ci.yml`) and
`make openapi-lint`: [vacuum](https://github.com/daveshanley/vacuum) (MIT), run with the
ruleset in the repository root's `.vacuum.yaml` against `server/http/handlers/openapi.yaml`.

- `VACUUM.pin`: the pinned release and the SHA-256 of its archive for each OS/arch the
  runners and developers use.
- `install.sh`: downloads that archive from the GitHub release, refuses it unless its
  SHA-256 equals the pin, and installs the binary at `.cache/vacuum/vacuum`. A cached
  archive that fails the check is deleted and downloaded once more; only a fresh download
  that also mismatches fails the run. A pin file with a duplicate key, a space or a quote
  is refused. `scripts/ci/vacuum-install-selftest.sh` proves these refusal paths offline.
- `canary-bad.yaml`: a deliberately broken spec. CI fails if vacuum accepts it, which
  proves the ruleset is loaded and its error rules fire.

## Taking a new vacuum version

A new vacuum release can change the findings: a new rule, or a fix that makes an
existing `.vacuum.yaml` line take effect. So treat a bump like a ruleset edit. Download
the candidate's archives and its `checksums.txt`. Check each archive against
`checksums.txt` and against the release page's asset digest. Then run the old and the
new binary over `server/http/handlers/openapi.yaml` and `canary-bad.yaml` with the same
`.vacuum.yaml`: `vacuum spectral-report` writes the findings as JSON, and
`vacuum lint --show-rules` lists the rules that run. Take the version only if the
error set is the same and every new warning is explained. Then change `version=` and
every `sha256_<os>_<arch>=` line in `VACUUM.pin` in one commit, and say in the PR what
the comparison showed. `install.sh` refuses an archive whose hash is wrong or missing,
so a half-updated pin fails CI instead of installing an unchecked binary.

### Preparing the pin edit: `scripts/ci/vacuum-pin-bump.py`

Dependabot does not track vacuum (the pin is a text file), so nothing proposes a new
version. `scripts/ci/vacuum-pin-bump.py` (Python standard library only) prepares the
edit; run it from the repository root, by hand or from a scheduler outside the repo. It
opens no pull request and is not wired into `.github`.

1. `scripts/ci/vacuum-pin-bump.py --dry-run` asks GitHub for the latest vacuum release and
   prints the diff it would make. It refuses a draft, a prerelease, a release older than
   the pin, and a release younger than 7 days (the former Dependabot cooldown; `--min-age-days`
   can only raise it). `--version X.Y.Z` takes a specific release instead of the latest.
2. It fetches the release's `checksums.txt` and checks it against the release's own asset
   digest, then each archive line against that archive's digest. Any disagreement, a missing
   platform, or a pin whose hashes differ from the checksums of the version it already names
   (a re-published asset) is a refusal with a message, and the pin is not touched.
3. Without `--dry-run` it rewrites `version=` and each `sha256_<os>_<arch>=` line of
   `VACUUM.pin` in place (comments and order stay) and prints the diff. The set of platforms
   is the pin's own: a platform is never added or dropped by the script.
4. Rerun the lint comparison above on the real spec (old and new binary, same
   `.vacuum.yaml`, `openapi.yaml` and `canary-bad.yaml`). The error set must stay identical,
   and every new warning must be explained in the PR. The script does not do this step.

The tests run offline against the real v0.42.3 release data (`--from-file` reads a saved
release instead of the network).

### vacuum must stay out of every go.mod

vacuum and the `github.com/pb33f/*` libraries it is built from are a CI tool, not a
product dependency. They run only as the pinned release binary. When they were a Go
module of this repository, Dependabot bumped vacuum's own dependency tree and broke
product dependencies (#4649). `TestNoToolModuleInGoModGuard` (`scripts/ci`) fails any
`go.mod` or `go.work` that requires, replaces or lists as a tool a module under
`github.com/daveshanley/` or `github.com/pb33f/`.
