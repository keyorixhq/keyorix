#!/usr/bin/env python3
"""Move devtools/vacuum/VACUUM.pin to a newer vacuum release (VACUUM-FOLLOWUP-1).

Dependabot no longer tracks vacuum (the pin is a text file, not a Go module), so
this is the freshness mechanism. Run it by hand or from a scheduler outside the
repo; it opens no PR and is not wired into .github.

    scripts/ci/vacuum-pin-bump.py [--pin FILE] [--version X.Y.Z] [--dry-run]
                                  [--min-age-days N] [--from-file FIXTURE.json]

What it does:
  1. reads the pin (same strict format as devtools/vacuum/install.sh: KEY=value
     lines, no spaces, no duplicate keys);
  2. asks GitHub for the latest daveshanley/vacuum release (or --version);
  3. refuses a draft, a prerelease, a release older than the pin and a release
     younger than 7 days (the Dependabot cooldown; --min-age-days can only raise it);
  4. fetches the release's checksums.txt and checks it against the release's
     own asset digest, and every archive line against that asset's digest;
  5. rewrites `version=` and each `sha256_<os>_<arch>=` line of the pin in place
     (comments and order stay), printing a unified diff; --dry-run prints only.
The set of sha256_ keys is the pin's: a platform is never added or dropped here.

If the release is the one already pinned it changes nothing, but still fails when
the pin's hashes differ from the release's checksums.txt (a re-published asset).

A new vacuum release can change the findings. After running this, do the lint
comparison described in devtools/vacuum/README.md on the real spec; the error set
must stay identical.

--from-file FIXTURE.json reads {"release": <GitHub release JSON>, "checksums":
<checksums.txt text>} instead of the network; the tests use it (no network in
tests). --now ISO8601 fixes the clock for the age check (tests only).

Exit status: 0 bumped / already current, 1 refused or failed, 2 usage error.
Standard library only.
"""
import argparse
import datetime
import difflib
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_PIN = os.path.join(REPO_ROOT, "devtools", "vacuum", "VACUUM.pin")
API = "https://api.github.com/repos/daveshanley/vacuum/releases"
DOWNLOAD_PREFIX = "https://github.com/daveshanley/vacuum/releases/download/"
COOLDOWN_DAYS = 7  # same as the Dependabot cooldown this replaces
MAX_BODY = 8 * 1024 * 1024

LINE_RE = re.compile(r"^([a-z0-9_]+)=(\S+)$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
HEX_RE = re.compile(r"^[0-9a-f]{64}$")
CHECKSUM_RE = re.compile(r"^([0-9a-f]{64}) [ *](\S+)$")


class Refused(Exception):
    """A reason to stop with exit status 1."""


def parse_pin(text, name):
    """Return (version, {key: hash}); same rules as install.sh."""
    version = None
    hashes = {}
    seen = set()
    for n, line in enumerate(text.splitlines(), 1):
        if line == "" or line.startswith("#"):
            continue
        m = LINE_RE.match(line)
        if not m:
            raise Refused(f"{name}:{n}: not a KEY=value line (no spaces, no quotes)")
        key, value = m.groups()
        if key in seen:
            raise Refused(f"{name}:{n}: duplicate key {key}")
        seen.add(key)
        if key == "version":
            if not VERSION_RE.match(value):
                raise Refused(f"{name}:{n}: version must be X.Y.Z")
            version = value
        elif key.startswith("sha256_"):
            if not HEX_RE.match(value):
                raise Refused(f"{name}:{n}: {key} must be 64 lowercase hex digits")
            hashes[key] = value
        else:
            raise Refused(f"{name}:{n}: unknown key {key}")
    if version is None:
        raise Refused(f"{name} has no version line")
    if not hashes:
        raise Refused(f"{name} has no sha256_ lines")
    return version, hashes


def vtuple(v):
    return tuple(int(p) for p in v.split("."))


def parse_time(s):
    try:
        return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        raise Refused(f"cannot parse timestamp {s!r} (want YYYY-MM-DDTHH:MM:SSZ)")


def parse_checksums(text):
    sums = {}
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip() == "":
            continue
        m = CHECKSUM_RE.match(line)
        if not m:
            raise Refused(f"checksums.txt:{n}: unexpected line {line!r}")
        digest, name = m.groups()
        if name in sums:
            raise Refused(f"checksums.txt:{n}: {name} listed twice")
        sums[name] = digest
    return sums


def asset_digest(release, name):
    """sha256 hex from the release asset's own digest field, or None."""
    for a in release.get("assets", []):
        if a.get("name") == name:
            d = a.get("digest")
            if d is None:
                return None
            if not isinstance(d, str) or not d.startswith("sha256:") or not HEX_RE.match(d[7:]):
                raise Refused(f"asset {name}: unusable digest {d!r}")
            return d[7:]
    raise Refused(f"release has no asset {name}")


def plan(release, checksums_text, pin_version, pin_hashes, now, min_age_days):
    """Return (new_version, new_hashes, notes). Raises Refused."""
    tag = release.get("tag_name", "")
    version = tag[1:] if tag.startswith("v") else tag
    if not VERSION_RE.match(version):
        raise Refused(f"release tag {tag!r} is not vX.Y.Z")
    if release.get("draft"):
        raise Refused(f"release {tag} is a draft")
    if release.get("prerelease"):
        raise Refused(f"release {tag} is a prerelease")
    if vtuple(version) < vtuple(pin_version):
        raise Refused(f"release {tag} is older than the pinned {pin_version}; not downgrading")

    notes = []
    published = parse_time(release.get("published_at"))
    age = now - published
    if version != pin_version and age < datetime.timedelta(days=min_age_days):
        eligible = published + datetime.timedelta(days=min_age_days)
        raise Refused(
            f"release {tag} was published {published:%Y-%m-%d %H:%M}Z, {age.days}d {age.seconds // 3600}h ago; "
            f"younger than {min_age_days} days (eligible from {eligible:%Y-%m-%d %H:%M}Z)"
        )

    want = asset_digest(release, "checksums.txt")
    got = hashlib.sha256(checksums_text.encode("utf-8")).hexdigest()
    if want is None:
        notes.append("checksums.txt has no release asset digest to compare with (not cross-checked)")
    elif want != got:
        raise Refused(f"checksums.txt hashes to {got}, but the release lists {want} for it")
    else:
        notes.append("checksums.txt matches the release asset digest")

    sums = parse_checksums(checksums_text)
    new_hashes = {}
    for key in pin_hashes:
        platform = key[len("sha256_"):]
        asset = f"vacuum_{version}_{platform}.tar.gz"
        if asset not in sums:
            raise Refused(f"checksums.txt has no line for {asset} (pin key {key})")
        digest = sums[asset]
        listed = asset_digest(release, asset)
        if listed is None:
            notes.append(f"{asset}: no release asset digest to compare with (not cross-checked)")
        elif listed != digest:
            raise Refused(f"{asset}: checksums.txt says {digest}, the release asset digest says {listed}")
        new_hashes[key] = digest

    if version == pin_version and new_hashes != pin_hashes:
        changed = sorted(k for k in pin_hashes if pin_hashes[k] != new_hashes[k])
        raise Refused(
            f"release {tag} is already pinned but {', '.join(changed)} differ from its checksums.txt "
            "(a re-published asset, or a wrong pin): investigate before touching the pin"
        )
    return version, new_hashes, notes


def rewrite(text, version, hashes):
    out = []
    for line in text.splitlines(keepends=True):
        m = LINE_RE.match(line.rstrip("\n"))
        if m and m.group(1) == "version":
            line = f"version={version}\n"
        elif m and m.group(1) in hashes:
            line = f"{m.group(1)}={hashes[m.group(1)]}\n"
        out.append(line)
    return "".join(out)


def http_get(url, accept):
    if not url.startswith(("https://api.github.com/", DOWNLOAD_PREFIX)):
        raise Refused(f"refusing to fetch {url}")
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "keyorix-vacuum-pin-bump"})
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        req.add_header("Authorization", f"Bearer {token}")
    try:
        # url is checked against the two GitHub prefixes above, never user input.
        with urllib.request.urlopen(req, timeout=60) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            body = resp.read(MAX_BODY + 1)
    except OSError as e:
        raise Refused(f"cannot fetch {url}: {e}")
    if len(body) > MAX_BODY:
        raise Refused(f"{url} is larger than {MAX_BODY} bytes")
    return body.decode("utf-8")


def fetch(version):
    path = "latest" if version is None else f"tags/v{version}"
    release = json.loads(http_get(f"{API}/{path}", "application/vnd.github+json"))
    for a in release.get("assets", []):
        if a.get("name") == "checksums.txt":
            return release, http_get(a.get("browser_download_url", ""), "application/octet-stream")
    raise Refused(f"release {release.get('tag_name')} has no checksums.txt asset")


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--pin", default=DEFAULT_PIN)
    ap.add_argument("--version", help="take this release instead of the latest")
    ap.add_argument("--dry-run", action="store_true", help="print the diff, do not write the pin")
    ap.add_argument("--min-age-days", type=int, default=COOLDOWN_DAYS, help=f"cooldown, at least {COOLDOWN_DAYS}")
    ap.add_argument("--from-file", help="read the release from FIXTURE.json instead of the network (tests)")
    ap.add_argument("--now", help="ISO8601 UTC clock for the age check (tests)")
    args = ap.parse_args(argv)

    if args.min_age_days < COOLDOWN_DAYS:
        print(f"vacuum-pin-bump: --min-age-days can only raise the cooldown (minimum {COOLDOWN_DAYS})", file=sys.stderr)
        return 2
    if args.version is not None and not VERSION_RE.match(args.version):
        print("vacuum-pin-bump: --version must be X.Y.Z", file=sys.stderr)
        return 2

    try:
        now = parse_time(args.now) if args.now else datetime.datetime.now(datetime.timezone.utc)
        with open(args.pin, encoding="utf-8") as f:
            old_text = f.read()
        pin_version, pin_hashes = parse_pin(old_text, args.pin)
        print(f"vacuum-pin-bump: pinned vacuum {pin_version} ({len(pin_hashes)} platforms)", file=sys.stderr)

        if args.from_file:
            with open(args.from_file, encoding="utf-8") as f:
                fixture = json.load(f)
            release, checksums = fixture["release"], fixture["checksums"]
        else:
            print("vacuum-pin-bump: querying GitHub for the vacuum release", file=sys.stderr)
            release, checksums = fetch(args.version)
        print(f"vacuum-pin-bump: release {release.get('tag_name')} published {release.get('published_at')}", file=sys.stderr)

        version, hashes, notes = plan(release, checksums, pin_version, pin_hashes, now, args.min_age_days)
    except (Refused, OSError, ValueError, KeyError) as e:
        print(f"vacuum-pin-bump: refused: {e}", file=sys.stderr)
        return 1

    for n in notes:
        print(f"vacuum-pin-bump: {n}", file=sys.stderr)
    if version == pin_version:
        print(f"vacuum-pin-bump: already at {version}, hashes match checksums.txt; nothing to do", file=sys.stderr)
        return 0

    new_text = rewrite(old_text, version, hashes)
    sys.stdout.writelines(difflib.unified_diff(
        old_text.splitlines(keepends=True), new_text.splitlines(keepends=True),
        fromfile=args.pin, tofile=args.pin + " (new)"))
    if args.dry_run:
        print("vacuum-pin-bump: --dry-run, pin not written", file=sys.stderr)
        return 0

    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(args.pin)), prefix=".VACUUM.pin.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_text)
        os.chmod(tmp, os.stat(args.pin).st_mode & 0o777)
        os.replace(tmp, args.pin)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    print(f"vacuum-pin-bump: wrote {args.pin}: {pin_version} -> {version}", file=sys.stderr)
    print("vacuum-pin-bump: next, rerun the lint comparison on the real spec (devtools/vacuum/README.md); "
          "the error set must stay identical", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
