# Continuous fuzzing (self-hosted)

Runs the repo's `func Fuzz*` targets (`internal/crypto`, `internal/core`,
`internal/rotation` as of this writing — see `targets.conf`) continuously on a
dedicated box, rotating between them for hours at a time. CI only runs these
as a quick regression pass over the seed corpus; deep fuzzing needs far more
wall-clock time than a CI job's budget affords, so it belongs on separate,
long-lived infrastructure — a small home-lab VM/LXC is a good fit.

## What you get

- A systemd service that cycles through every target in `targets.conf`,
  forever, pulling `main` fresh once per full cycle.
- A push notification (via [ntfy.sh](https://ntfy.sh), no account needed) the
  moment a target crashes — deduped, so a target that keeps re-failing
  against an already-known crasher doesn't re-alert every cycle.
- A daily heartbeat notification, so silence itself tells you the service (or
  the box) died, without you needing to check in manually.
- Any new corpus file (a crash reproduction, or a coverage-expanding
  "interesting" input the fuzzer found) gets committed and pushed to a
  dedicated `fuzz-corpus` branch automatically — review/merge what's
  interesting from there.

## One-time setup (on the LXC/VM)

Debian or Alpine, ~512MB RAM is plenty for a single-target-at-a-time rotation
(bump `MemoryMax` in `systemd/keyorix-fuzz.service` if you widen
`targets.conf` to run more in parallel — this setup deliberately runs targets
one at a time, not concurrently).

1. **Install Go** (same version as `go.mod` — check the repo's current
   `go.mod`/CI config for the exact version) and `git`, `rsync`, `curl`.

2. **Create a dedicated user** to run the service as (never run this as
   root):
   ```
   useradd -m -s /bin/bash fuzzer
   mkdir -p /opt/keyorix-fuzz /etc/keyorix-fuzz
   chown fuzzer:fuzzer /opt/keyorix-fuzz
   ```

3. **Generate an SSH deploy key** for this box, as the `fuzzer` user:
   ```
   sudo -u fuzzer ssh-keygen -t ed25519 -f /home/fuzzer/.ssh/id_ed25519 -N ""
   cat /home/fuzzer/.ssh/id_ed25519.pub
   ```
   Add the printed public key to the repo's GitHub settings under **Settings
   → Deploy keys → Add deploy key**, with **"Allow write access"** checked
   (needed to push the `fuzz-corpus` branch). Scope this key to *this repo
   only* — deploy keys are always single-repo, which is exactly the
   least-privilege shape you want here (unlike a personal PAT, which this
   setup deliberately avoids).

4. **Clone the repo twice** as the `fuzzer` user — once for fuzzing (stays on
   `main`), once as a worktree for the corpus branch:
   ```
   sudo -u fuzzer git clone git@github.com:keyorixhq/keyorix.git /opt/keyorix-fuzz/keyorix
   cd /opt/keyorix-fuzz/keyorix
   sudo -u fuzzer git worktree add ../keyorix-fuzz-corpus -b fuzz-corpus
   sudo -u fuzzer git -C ../keyorix-fuzz-corpus push -u origin fuzz-corpus
   ```

5. **Pick an ntfy.sh topic.** Topics are unauthenticated by default (anyone
   who guesses the name can read/publish to it), so generate something long
   and random rather than anything guessable:
   ```
   openssl rand -hex 16
   ```
   Subscribe to `https://ntfy.sh/<that-topic>` in the
   [ntfy app](https://ntfy.sh/#getting-started) (iOS/Android/web) so you
   actually see the pushes.

6. **Write the config file:**
   ```
   cp scripts/fuzzing/config.env.example /etc/keyorix-fuzz/config.env
   $EDITOR /etc/keyorix-fuzz/config.env   # fill in NTFY_TOPIC at minimum
   chmod 600 /etc/keyorix-fuzz/config.env
   chown fuzzer:fuzzer /etc/keyorix-fuzz/config.env
   ```

7. **Install the systemd units:**
   ```
   cp scripts/fuzzing/systemd/*.service scripts/fuzzing/systemd/*.timer /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now keyorix-fuzz.service
   systemctl enable --now keyorix-fuzz-heartbeat.timer
   ```

8. **Verify:**
   ```
   systemctl status keyorix-fuzz.service
   journalctl -u keyorix-fuzz.service -f
   ```
   You should see a target start fuzzing within a few seconds. The daily
   heartbeat can be triggered on demand to test notifications end-to-end
   without waiting for 09:00: `systemctl start keyorix-fuzz-heartbeat.service`.

## Day-to-day

- **Crash notification arrives** → SSH in, `cat
  /opt/keyorix-fuzz/state/last-<FuzzName>.log` for the full failure, or check
  the `fuzz-corpus` branch for the exact new failing-input file (it's a small
  Go-syntax file under `testdata/fuzz/<FuzzName>/`). Reproduce locally with
  `go test -run=<FuzzName>/<hash> ./<package>` once you've pulled that branch.
- **No heartbeat today** → the service or the box is down; check
  `systemctl status keyorix-fuzz.service` / whether the LXC itself is up.
- **Widening coverage** → add a line to `targets.conf`; no script changes
  needed. The service picks it up on its next full rotation cycle restart
  (`systemctl restart keyorix-fuzz.service` to pick it up immediately).

## Design notes

- The main clone (`KEYORIX_REPO`) is treated as disposable and dedicated
  solely to fuzzing — `run-rotation.sh` runs `git reset --hard origin/main`
  against it once per cycle. Don't use this clone for anything else.
- Corpus commits land on `fuzz-corpus`, never `main` — nothing here touches
  CI or requires a PR to keep running; you decide when (and whether) to open
  a PR merging an interesting find into `main`.
- Targets run one at a time, not concurrently, to keep resource usage
  predictable on modest home-lab hardware. If you want parallelism, run
  multiple instances of this whole setup (separate `KEYORIX_REPO`/
  `NOTIFIED_STATE_DIR`/systemd unit names) rather than modifying
  `run-rotation.sh` to fan out.
