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

## Resource limits

`systemd/keyorix-fuzz.service` caps this service to `CPUQuota=400%` (4 of an
assumed 8-core homelab box) and `MemoryMax=2G`, alongside `Nice=10`. `Nice`
only lowers this service's *relative* scheduling priority when something else
on the box wants the CPU too — on an otherwise-idle homelab box (which this
one mostly is), that does nothing to cap actual usage, so `CPUQuota=` is the
setting doing the real work of leaving headroom for everything else on the
box. Adjust both to fit your own hardware and how much of it you're willing
to dedicate.

**Important tradeoff to understand before tuning `CPUQuota`:** the
`-fuzztime` values in `targets.conf` (consumed by `run-rotation.sh`) are
**wall-clock** time, not CPU time — `go test -fuzz -fuzztime=3h` runs for 3
hours of real time regardless of how much CPU it actually gets scheduled.
Capping `CPUQuota` therefore does **not** change how long a rotation takes;
it only makes each rotation's mutation pass *shallower* — fewer inputs get
tried (throughput scales down roughly with the quota) in that same
wall-clock window. If you want both fast throughput and a hard resource
ceiling, lower `-fuzztime` instead of (or in addition to) `CPUQuota` so a
rotation cycle still completes in a reasonable amount of real time.

## One-time setup (on the LXC/VM)

Debian or Alpine, ~512MB RAM is plenty for a single-target-at-a-time rotation
(bump `MemoryMax` in `systemd/keyorix-fuzz.service` if you widen
`targets.conf` to run more in parallel — this setup deliberately runs targets
one at a time, not concurrently).

1. **Install Go** — matching whatever version `go.mod` currently declares, not
   whatever your distro's package manager ships (usually older). Install from
   the official tarball instead:
   ```
   curl -fsSL -o /tmp/go.tar.gz https://go.dev/dl/go<VERSION>.linux-amd64.tar.gz
   # verify the checksum against https://go.dev/dl/?mode=json first
   rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
   echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
   chmod +x /etc/profile.d/go.sh
   ```
   Also install `git`, `rsync`, `curl`, `ca-certificates`, `sudo`.

2. **Create a dedicated user** to run the service as (never run this as
   root):
   ```
   useradd -m -s /bin/bash fuzzer
   mkdir -p /opt/keyorix-fuzz /etc/keyorix-fuzz
   chown fuzzer:fuzzer /opt/keyorix-fuzz
   ```

3. **Get GitHub access for the `fuzzer` user.** Two things need separate
   authentication: `git push` (corpus commits) and `gh pr create` (crash
   reports). Set them up together:

   - **Deploy key + PAT (recommended):** Use a deploy key for `git push` and a
     fine-grained PAT for `gh`:
     - Generate a deploy key as the `fuzzer` user:
       ```
       sudo -u fuzzer ssh-keygen -t ed25519 -f /home/fuzzer/.ssh/id_ed25519 -N ""
       ```
       Add the public key under **Settings → Deploy keys → Add deploy key** with
       **"Allow write access"** checked. Clone via SSH (`git@github.com:...`).
     - Create a fine-grained PAT at **Settings → Developer settings → Personal
       access tokens → Fine-grained tokens**, scoped to this repo, with:
       - **Contents: Read** (to check branch state)
       - **Pull requests: Read and write** (to open/comment on crash-report PRs)

       Store it and add it to `config.env` (systemd `EnvironmentFile=` does not
       expand shell syntax, so paste the token value literally):
       ```
       echo "github_pat_..." > /etc/keyorix-fuzz-gh-token
       chown fuzzer:fuzzer /etc/keyorix-fuzz-gh-token
       chmod 600 /etc/keyorix-fuzz-gh-token
       ```
       Then set `GH_TOKEN=<paste token here>` in `/etc/keyorix-fuzz/config.env`
       (see step 6).

   - **Single PAT (simpler — use if deploy keys are disabled at the org
     level):** Create one PAT with both scopes and use it for everything:
     - **Contents: Read and write** (for `git push`)
     - **Pull requests: Read and write** (for `gh pr create`/`gh pr list`)

     Store it and wire it up for both `git push` and `gh`:
     ```
     echo "github_pat_..." > /etc/keyorix-fuzz-github-token
     chown fuzzer:fuzzer /etc/keyorix-fuzz-github-token
     chmod 600 /etc/keyorix-fuzz-github-token
     sudo -u fuzzer git config --global credential.'https://github.com'.helper \
       '!f() { echo username=x-access-token; echo password=$(cat /etc/keyorix-fuzz-github-token); }; f'
     ```
     Then set `GH_TOKEN=<paste token here>` in `/etc/keyorix-fuzz/config.env`
     (see step 6). Clone via HTTPS (`https://github.com/...`).

   > **Why two separate auth paths?** `git push` uses the git credential helper;
   > `gh pr create` uses the `gh` CLI which reads `GH_TOKEN` (or `GITHUB_TOKEN`)
   > from the environment — not from git's credential store. Without `GH_TOKEN`
   > in `config.env`, the systemd service cannot authenticate `gh` and crash
   > reports are silently lost.

4. **Clone the repo twice** as the `fuzzer` user — once for fuzzing (stays on
   `main`), once as a worktree for the corpus branch. Use whichever URL scheme
   matches the auth method from step 3:
   ```
   sudo -u fuzzer git clone https://github.com/keyorixhq/keyorix.git /opt/keyorix-fuzz/keyorix
   sudo -u fuzzer git config --global --add safe.directory /opt/keyorix-fuzz/keyorix
   cd /opt/keyorix-fuzz/keyorix
   sudo -u fuzzer git worktree add ../keyorix-fuzz-corpus -b fuzz-corpus
   sudo -u fuzzer git config --global --add safe.directory /opt/keyorix-fuzz/keyorix-fuzz-corpus
   sudo -u fuzzer git -C ../keyorix-fuzz-corpus push -u origin fuzz-corpus
   ```
   (`safe.directory` avoids git's "dubious ownership" refusal, which fires
   whenever the directory owner and invoking user's default checks disagree —
   harmless here since `fuzzer` owns these clones outright.)

5. **Pick an ntfy.sh topic.** Topics are unauthenticated by default (anyone
   who guesses the name can read/publish to it), so generate something long
   and random rather than anything guessable:
   ```
   openssl rand -hex 16
   ```
   Subscribe to `https://ntfy.sh/<that-topic>` in the
   [ntfy app](https://ntfy.sh/#getting-started) (iOS/Android/web) so you
   actually see the pushes.

6. **Write the config file.** Systemd's `EnvironmentFile=` does NOT source
   `/etc/profile.d/`, so `PATH` needs `/usr/local/go/bin` added explicitly or
   the service will fail with "go: command not found". Also set `GH_TOKEN` here
   (the `gh` CLI reads it; without it crash-report PRs fail silently):
   ```
   cp scripts/fuzzing/config.env.example /etc/keyorix-fuzz/config.env
   $EDITOR /etc/keyorix-fuzz/config.env   # set GH_TOKEN and optionally NTFY_TOPIC
   echo 'PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' \
     >> /etc/keyorix-fuzz/config.env
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
   **If this is an unprivileged Proxmox LXC**, check `systemctl status
   systemd-journald` first — a fresh Debian 13 template can fail to start
   journald entirely (`code=exited, status=243/CREDENTIALS`) because its
   shipped unit has `ImportCredential=journal.*`, a credential-import feature
   this container's kernel namespace doesn't support. If you see that, this
   silently breaks BOTH `journalctl` for every service on the box AND swallows
   `keyorix-fuzz.service`'s own progress echoes (though the underlying `go
   test` output still lands in real log files under `$NOTIFIED_STATE_DIR`, so
   fuzzing itself isn't affected — only visibility is). Fix with a drop-in
   that clears the directive, then restart both journald and the fuzz service
   so its output gets captured from the start:
   ```
   mkdir -p /etc/systemd/system/systemd-journald.service.d
   printf '[Service]\nImportCredential=\n' > /etc/systemd/system/systemd-journald.service.d/override.conf
   systemctl daemon-reload
   systemctl restart systemd-journald
   systemctl restart keyorix-fuzz.service
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
- **`gh` notification failed** → check `journalctl -u keyorix-fuzz.service -n 50`
  for "GitHub notification failed" lines, then read the corresponding
  `gh-error-<func>-<hash>.log` in `$NOTIFIED_STATE_DIR` for the actual error
  (auth failure, missing PAT scope, branch not pushed yet, etc.). Fix `GH_TOKEN`
  in `/etc/keyorix-fuzz/config.env`, then clear the stale dedup markers so the
  next rotation retries:
  ```
  ls /opt/keyorix-fuzz/state/notified-*   # see which crashes were never reported
  rm /opt/keyorix-fuzz/state/notified-<FuzzName>-<hash>
  systemctl restart keyorix-fuzz.service
  ```
- **Widening coverage** → add a line to `targets.conf`; no script changes
  needed. The service picks it up on its next full rotation cycle restart
  (`systemctl restart keyorix-fuzz.service` to pick it up immediately).

## Design notes

- The main clone (`KEYORIX_REPO`) is treated as disposable and dedicated
  solely to fuzzing — `run-rotation.sh` runs `git reset --hard origin/main`
  against it before every target (not just once per cycle — this repo merges
  dozens of commits a day, so a once-per-cycle pull could leave a target
  fuzzing code that was already stale for most of a ~14h rotation by the time
  it ran). Don't use this clone for anything else.
- Corpus commits land on `fuzz-corpus`, never `main` — nothing here touches
  CI or requires a PR to keep running; you decide when (and whether) to open
  a PR merging an interesting find into `main`.
- Targets run one at a time, not concurrently, to keep resource usage
  predictable on modest home-lab hardware. If you want parallelism, run
  multiple instances of this whole setup (separate `KEYORIX_REPO`/
  `NOTIFIED_STATE_DIR`/systemd unit names) rather than modifying
  `run-rotation.sh` to fan out.
