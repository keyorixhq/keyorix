#!/usr/bin/env python3
"""Check internal links and file references in docs/**/*.md.

Reports, one per line as `file:line: message`:
  * a relative markdown link whose target file or directory does not exist;
  * a `#anchor` (same-file or cross-file) with no matching heading;
  * with --refs, a backticked repo path (`internal/x/y.go`, `docs/z.md`, ...)
    that does not exist.

External links (http, https, mailto) are not fetched. Fenced code blocks are
skipped. Exit status 1 if anything is reported.

A backticked path is looked up against the repo root and against the directory
of the file that mentions it (docs/ pages write `operator/x.md` for docs/operator/x.md).

Usage: scripts/check-doc-links.py [--refs] [paths...]   (default: docs/)
       scripts/check-doc-links.py --self-test
The link and anchor rules are enforced by `go test ./internal/docsdrift`
(links_test.go); this script remains the place for --refs and ad-hoc runs.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINK = re.compile(r"(?<!\!)\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
IMG = re.compile(r"!\[[^\]\n]*\]\(([^)\s]+)")
REF = re.compile(r"`((?:docs|internal|server|cli|web|scripts|deploy|operator|api|changelog\.d)/[A-Za-z0-9_./\-]+)`")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$")
FENCE = re.compile(r"^\s*(```|~~~)")


def slug(text):
    text = re.sub(r"`", "", text.strip().lower())
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


_anchor_cache = {}


def anchors(path):
    if path in _anchor_cache:
        return _anchor_cache[path]
    seen, out, fenced = {}, set(), False
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if FENCE.match(line):
                fenced = not fenced
                continue
            if fenced:
                continue
            m = HEADING.match(line)
            if m:
                s = slug(m.group(1))
                n = seen.get(s, 0)
                seen[s] = n + 1
                out.add(s if n == 0 else "%s-%d" % (s, n))
            for a in re.findall(r'<a\s+(?:name|id)="([^"]+)"', line):
                out.add(a)
    _anchor_cache[path] = out
    return out


def symbol_of_existing(p, base=None):
    """`internal/x.Func` or `internal/x/file.go:12` names something that exists.

    A reference resolves against the repo root, or (when base is given) against
    the referencing file's own directory, like a markdown link would.
    """
    p = re.sub(r":\d+(-\d+)?$", "", p)
    roots = [ROOT] if base is None else [ROOT, base]
    if any(os.path.exists(os.path.join(r, p)) for r in roots):
        return True
    head, dot, tail = p.rpartition(".")
    return bool(dot) and tail[:1].isalpha() and "/" not in tail and any(os.path.exists(os.path.join(r, head)) for r in roots)


# Historical records describe files that existed when they were written
# (deleted since, by design): their file references are not checked.
HISTORICAL = re.compile(r"(^|/)(adr-[^/]*\.md|findings/|g80-[^/]*|design-[^/]*|cli-split-inventory[^/]*|cli-migration[^/]*|security-review-[^/]*|binary-size-measurement[^/]*|air-gap-updates-design[^/]*|security-closures\.d/|specs/|security/threat-models/|state-map/|review-coverage)")


def check_file(path, refs, problems):
    base = os.path.dirname(path)
    rel = os.path.relpath(path, ROOT)
    fenced = False
    refs = refs and not HISTORICAL.search(rel)
    with open(path, encoding="utf-8", errors="replace") as f:
        for no, line in enumerate(f, 1):
            if FENCE.match(line):
                fenced = not fenced
                continue
            if fenced:
                continue
            prose = re.sub(r"`[^`\n]*`", "", line)  # a link inside a code span is a quotation
            for target in LINK.findall(prose) + IMG.findall(prose):
                if re.match(r"^[a-z][a-z0-9+.\-]*:", target) or target.startswith("//"):
                    continue
                file_part, _, frag = target.partition("#")
                if file_part:
                    dest = os.path.normpath(os.path.join(ROOT if file_part.startswith("/") else base, file_part.lstrip("/") if file_part.startswith("/") else file_part))
                else:
                    dest = path
                if not os.path.exists(dest):
                    problems.append("%s:%d: broken link target %s" % (rel, no, target))
                    continue
                if frag and dest.endswith(".md") and os.path.isfile(dest):
                    if frag.lower() not in {a.lower() for a in anchors(dest)}:
                        problems.append("%s:%d: no heading for anchor %s" % (rel, no, target))
            if refs:
                for r in REF.findall(line):
                    p = r.rstrip(".,:;")
                    if any(c in p for c in "*<>{}") or p.endswith("/"):
                        continue
                    if not symbol_of_existing(p, base):
                        problems.append("%s:%d: stale file reference %s" % (rel, no, p))


def self_test():
    """Calibration for the --refs resolution rule: red and green cases."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "docs", "operator"))
        open(os.path.join(d, "docs", "operator", "runbook.md"), "w").close()
        doc = os.path.join(d, "docs", "page.md")
        cases = [
            ("resolves only relative to the file's dir", "`operator/runbook.md`", 0),
            ("dangling reference still fails", "`operator/missing.md`", 1),
            ("dangling under the repo root still fails", "`docs/operator/missing.md`", 1),
        ]
        bad = 0
        for name, text, want in cases:
            with open(doc, "w") as f:
                f.write(text + "\n")
            problems = []
            check_file(doc, True, problems)
            got = len(problems)
            if got != want:
                print("self-test FAIL: %s: want %d problem(s), got %d: %s" % (name, want, got, problems))
                bad += 1
        # repo-root resolution is the other half of the rule
        probe = os.path.join(ROOT, "scripts", "check-doc-links.py")
        if not symbol_of_existing("scripts/check-doc-links.py", os.path.dirname(doc)) or not os.path.exists(probe):
            print("self-test FAIL: repo-root reference no longer resolves")
            bad += 1
    print("self-test: %s" % ("FAIL" if bad else "ok"), file=sys.stderr)
    return 1 if bad else 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    refs = "--refs" in argv
    targets = [a for a in argv if not a.startswith("--")] or [os.path.join(ROOT, "docs")]
    problems = []
    for t in targets:
        t = os.path.abspath(t)
        if os.path.isfile(t):
            check_file(t, refs, problems)
            continue
        for dirpath, _, names in os.walk(t):
            for n in sorted(names):
                if n.endswith(".md"):
                    check_file(os.path.join(dirpath, n), refs, problems)
    for p in problems:
        print(p)
    print("%d problem(s)" % len(problems), file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
