# triage-script-test-fixture.py -- THROWAWAY. Exists only to generate real,
# live code-scanning alerts to test scripts/triage-code-scanning-alert.sh's
# red/green paths against the actual GitHub API, per the task that added
# that script. Deleted in a follow-up commit within the same change once the
# test observations are recorded -- never meant to reach main.
import urllib.request


def properly_suppressed(url):
    """GREEN case: correctly suppressed, exact rule id -- the script must dismiss."""
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        return resp.read()


def unsuppressed(url):
    """RED case 1: no suppression at all -- the script must refuse (still fires)."""
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def bare_nosemgrep(url):
    """RED case 2: a bare nosemgrep (no rule id) -- semgrep itself suppresses
    this, but the script's exactness check must refuse it anyway, since it
    isn't a suppression naming this specific rule."""
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosemgrep
        return resp.read()
