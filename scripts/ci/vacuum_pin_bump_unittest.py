"""Unit tests for vacuum-pin-bump.py (VACUUM-FOLLOWUP-1).

Run by scripts/ci/vacuum_pin_test.go (or: python3 scripts/ci/vacuum_pin_bump_unittest.py
from the repo root). No network: every case runs the script with --from-file.

Calibration both ways:
  * testdata/vacuum-pin-bump/release-0.42.3.json is REAL data: the GitHub release
    JSON (trimmed to tag, flags, date and asset names/digests) and the checksums.txt
    of daveshanley/vacuum v0.42.3, fetched 2026-11-23. The repo's own VACUUM.pin
    must be "already current" against it, and a pin with one wrong hash must fail.
  * A newer release does not exist yet, so the cases that bump build one from the
    real file (version renamed through the asset names, hashes made up, the release
    digest of checksums.txt recomputed). The age cases move the --now clock.
"""
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
# VACUUM_PIN_BUMP points the tests at a mutated copy (mutation proof only).
SCRIPT = os.environ.get("VACUUM_PIN_BUMP") or os.path.join(HERE, "vacuum-pin-bump.py")
REAL = os.path.join(HERE, "testdata", "vacuum-pin-bump", "release-0.42.3.json")
REPO_PIN = os.path.join(HERE, "..", "..", "devtools", "vacuum", "VACUUM.pin")

PUBLISHED = "2026-11-21T21:48:39Z"
EXACTLY_7D = "2026-11-28T21:48:39Z"
JUST_UNDER_7D = "2026-11-28T21:48:38Z"

OLD_PIN = """# header comment
# second comment line
version=0.42.3
sha256_linux_x86_64=31d647c75daa4924f5d5b2fe48b3be8e54a910494d5f278039899a36653037f7
sha256_linux_arm64=597c2b74e4f19a7ee1aead1c968a2bf2a6b409581721bef9c298b5c660af6860
sha256_darwin_x86_64=775cb522b2d2c3d6b1ee380f10dfecba9660fbd8b5d01e625fb709b2d067a127
sha256_darwin_arm64=c851191eaa0e9464be97d9f0a2a7c4a4904f834a3a9c420f604e2f1e339275e6
"""
PLATFORMS = ["linux_x86_64", "linux_arm64", "darwin_x86_64", "darwin_arm64"]


def fake_hash(version, platform):
    return hashlib.sha256(f"{version}/{platform}".encode()).hexdigest()


def newer_release(version="0.43.0", published=PUBLISHED, platforms=PLATFORMS, **flags):
    """A fixture dict for `version`, derived from the real 0.42.3 file."""
    with open(REAL, encoding="utf-8") as f:
        real = json.load(f)
    lines = []
    assets = [a for a in real["release"]["assets"] if a["name"] == "checksums.txt"]
    for p in platforms:
        name = f"vacuum_{version}_{p}.tar.gz"
        digest = fake_hash(version, p)
        lines.append(f"{digest}  {name}")
        assets.append({"name": name, "digest": "sha256:" + digest, "browser_download_url": ""})
    text = "\n".join(lines) + "\n"
    assets[0]["digest"] = "sha256:" + hashlib.sha256(text.encode()).hexdigest()
    release = {"tag_name": "v" + version, "draft": False, "prerelease": False, "published_at": published, "assets": assets}
    release.update(flags)
    return {"release": release, "checksums": text}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.pin = os.path.join(self.tmp.name, "VACUUM.pin")
        self.write_pin(OLD_PIN)

    def write_pin(self, text):
        with open(self.pin, "w", encoding="utf-8") as f:
            f.write(text)

    def read_pin(self):
        with open(self.pin, encoding="utf-8") as f:
            return f.read()

    def fixture(self, data):
        path = os.path.join(self.tmp.name, "fixture.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return path

    def run_bump(self, fixture, now, *extra):
        p = subprocess.run(
            [sys.executable, "-I", SCRIPT, "--pin", self.pin, "--from-file", fixture, "--now", now, *extra],
            capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout, p.stderr

    def assertRefused(self, fixture, now, rx, *extra):
        before = self.read_pin()
        code, out, err = self.run_bump(fixture, now, *extra)
        self.assertEqual(code, 1, err)
        self.assertRegex(err, rx)
        self.assertEqual(out, "", "a refusal must print no diff")
        self.assertEqual(self.read_pin(), before, "a refusal must not touch the pin")


class RealData(Base):
    def test_repo_pin_is_current_against_the_real_release(self):
        with open(REPO_PIN, encoding="utf-8") as f:
            real_pin = f.read()
        self.write_pin(real_pin)
        code, out, err = self.run_bump(REAL, "2026-11-23T00:00:00Z")
        self.assertEqual(code, 0, err)
        self.assertIn("already at 0.42.3", err)
        self.assertIn("checksums.txt matches the release asset digest", err)
        self.assertEqual(out, "")
        self.assertEqual(self.read_pin(), real_pin)

    def test_one_wrong_hash_at_the_same_version_is_refused(self):
        self.write_pin(OLD_PIN.replace("597c2b74", "697c2b74"))
        self.assertRefused(REAL, "2026-11-23T00:00:00Z", "sha256_linux_arm64 differ from its checksums.txt")

    def test_real_checksums_with_one_byte_changed_fail_the_release_digest(self):
        with open(REAL, encoding="utf-8") as f:
            data = json.load(f)
        data["checksums"] = data["checksums"].replace("c851191e", "d851191e")
        self.assertRefused(self.fixture(data), "2026-11-23T00:00:00Z", "checksums.txt hashes to")


class Bump(Base):
    def test_bump_rewrites_version_and_hashes_and_keeps_the_rest(self):
        fx = self.fixture(newer_release())
        code, out, err = self.run_bump(fx, EXACTLY_7D)
        self.assertEqual(code, 0, err)
        want = OLD_PIN.replace("0.42.3", "0.43.0")
        for p in PLATFORMS:
            old = [l for l in OLD_PIN.splitlines() if l.startswith(f"sha256_{p}=")][0]
            want = want.replace(old, f"sha256_{p}={fake_hash('0.43.0', p)}")
        self.assertEqual(self.read_pin(), want)
        self.assertIn("-version=0.42.3", out)
        self.assertIn("+version=0.43.0", out)
        self.assertEqual(out.count("\n+sha256_"), 4)
        self.assertIn("# header comment", self.read_pin())
        self.assertIn("lint comparison", err)

    def test_dry_run_prints_the_diff_and_writes_nothing(self):
        fx = self.fixture(newer_release())
        code, out, err = self.run_bump(fx, EXACTLY_7D, "--dry-run")
        self.assertEqual(code, 0, err)
        self.assertIn("+version=0.43.0", out)
        self.assertEqual(self.read_pin(), OLD_PIN)

    def test_a_platform_is_never_added_or_dropped(self):
        self.write_pin(OLD_PIN.replace("sha256_darwin_x86_64=775cb522b2d2c3d6b1ee380f10dfecba9660fbd8b5d01e625fb709b2d067a127\n", ""))
        fx = self.fixture(newer_release())
        code, _, err = self.run_bump(fx, EXACTLY_7D)
        self.assertEqual(code, 0, err)
        new = self.read_pin()
        self.assertNotIn("sha256_darwin_x86_64", new)
        self.assertEqual(new.count("sha256_"), 3)


class Cooldown(Base):
    def test_exactly_seven_days_is_allowed(self):
        code, _, err = self.run_bump(self.fixture(newer_release()), EXACTLY_7D)
        self.assertEqual(code, 0, err)

    def test_one_second_under_seven_days_is_refused(self):
        self.assertRefused(self.fixture(newer_release()), JUST_UNDER_7D, "younger than 7 days")

    def test_a_fresh_release_is_refused_and_says_when_it_is_eligible(self):
        self.assertRefused(self.fixture(newer_release()), "2026-11-23T00:00:00Z", "eligible from 2026-11-28 21:48Z")

    def test_the_cooldown_can_be_raised_but_not_lowered(self):
        fx = self.fixture(newer_release())
        self.assertRefused(fx, EXACTLY_7D, "younger than 14 days", "--min-age-days", "14")
        code, _, err = self.run_bump(fx, EXACTLY_7D, "--min-age-days", "3")
        self.assertEqual(code, 2, err)
        self.assertIn("can only raise", err)


class Refusals(Base):
    def test_draft_and_prerelease(self):
        self.assertRefused(self.fixture(newer_release(draft=True)), EXACTLY_7D, "is a draft")
        self.assertRefused(self.fixture(newer_release(prerelease=True)), EXACTLY_7D, "is a prerelease")

    def test_older_release_is_not_a_downgrade(self):
        self.assertRefused(self.fixture(newer_release("0.41.9")), EXACTLY_7D, "older than the pinned 0.42.3")

    def test_tag_must_be_x_y_z(self):
        data = newer_release()
        data["release"]["tag_name"] = "v0.43.0-rc1"
        self.assertRefused(self.fixture(data), EXACTLY_7D, "is not vX.Y.Z")

    def test_missing_platform_in_checksums(self):
        fx = self.fixture(newer_release(platforms=PLATFORMS[:3]))
        self.assertRefused(fx, EXACTLY_7D, "no line for vacuum_0.43.0_darwin_arm64.tar.gz")

    def test_checksums_disagree_with_the_release_asset_digest(self):
        data = newer_release()
        for a in data["release"]["assets"]:
            if a["name"] == "vacuum_0.43.0_linux_arm64.tar.gz":
                a["digest"] = "sha256:" + "0" * 64
        self.assertRefused(self.fixture(data), EXACTLY_7D, "linux_arm64.tar.gz: checksums.txt says")

    def test_checksums_file_does_not_match_its_own_digest(self):
        data = newer_release()
        data["checksums"] = data["checksums"].replace("\n", "\n\n", 1)
        self.assertRefused(self.fixture(data), EXACTLY_7D, "checksums.txt hashes to")

    def test_malformed_and_duplicate_checksum_lines(self):
        for mutate, rx in (
            (lambda t: t + "not a checksum line\n", "unexpected line"),
            (lambda t: t + t.splitlines()[0] + "\n", "listed twice"),
        ):
            data = newer_release()
            data["checksums"] = mutate(data["checksums"])
            # keep the digest consistent so the refusal is the parser's, not the digest check
            data["release"]["assets"][0]["digest"] = "sha256:" + hashlib.sha256(data["checksums"].encode()).hexdigest()
            self.assertRefused(self.fixture(data), EXACTLY_7D, rx)

    def test_a_bad_pin_is_refused_before_anything_is_read(self):
        fx = self.fixture(newer_release())
        for text, rx in (
            (OLD_PIN + "version=0.1.0\n", "duplicate key version"),
            (OLD_PIN + OLD_PIN.splitlines()[3] + "\n", "duplicate key sha256_linux_x86_64"),
            (OLD_PIN.replace("version=", "version = "), "not a KEY=value line"),
            (OLD_PIN + "colour=blue\n", "unknown key colour"),
        ):
            self.write_pin(text)
            self.assertRefused(fx, EXACTLY_7D, rx)

    def test_missing_asset_digest_is_noted_not_fatal(self):
        data = newer_release()
        for a in data["release"]["assets"][1:]:
            del a["digest"]
        code, _, err = self.run_bump(self.fixture(data), EXACTLY_7D)
        self.assertEqual(code, 0, err)
        self.assertIn("not cross-checked", err)


if __name__ == "__main__":
    unittest.main(verbosity=1)
