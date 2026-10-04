#!/usr/bin/env bash
# migrate-invariants-to-fragments.sh — move a package's invariant bullets out
# of <pkg>/INVARIANTS.md into one file per invariant, <pkg>/INVARIANTS.d/<ID>.md
# (convention and reasoning: docs/invariants-fragments.md; enforced by
# internal/statemap/invariants_fragments_guard_test.go).
#
# Usage:
#   scripts/ledgers/migrate-invariants-to-fragments.sh [--root DIR] [--dry-run] --all
#   scripts/ledgers/migrate-invariants-to-fragments.sh [--root DIR] [--dry-run] <pkg-dir>...
#     e.g.  ... internal/encryption server/http
#
# What it does, per package:
#   - every column-0 `- **INV-<PKG>-<id>** ...` bullet, with its indented
#     continuation lines, becomes INVARIANTS.d/<ID>.md, verbatim, followed by
#     one `<!-- section: <heading> -->` line naming the `## ` heading it sat
#     under (so grouping survives; the doc guard checks the heading exists);
#   - INVARIANTS.md keeps all prose, headings and non-invariant bullets, gains
#     a one-paragraph pointer under its `Format:` line (inserted once), and
#     runs of blank lines left by removed bullets are squeezed to one.
#
# Safety:
#   - Refuses (exit 1, NOTHING written in any package) if any target package
#     has a duplicate ID — within INVARIANTS.md, or against an existing
#     fragment — or an invariant definition in a shape it does not move
#     (indented, or a `*` bullet). It prints what to renumber.
#   - Idempotent: a package with no remaining bullets is a no-op, so a second
#     run changes nothing. Deterministic: output depends only on file content.
#   - Never touches docs/INVARIANTS.md (the index).
set -euo pipefail

ROOT=""
DRY=0
ALL=0
PKGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --all) ALL=1; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) PKGS+=("${1%/}"); shift ;;
  esac
done
if [ -z "$ROOT" ]; then
  ROOT="$(git rev-parse --show-toplevel)"
fi
cd "$ROOT"

if [ "$ALL" = 1 ]; then
  [ ${#PKGS[@]} -eq 0 ] || { echo "--all and explicit packages are exclusive" >&2; exit 2; }
  while IFS= read -r f; do
    d="${f%/INVARIANTS.md}"; d="${d#./}"
    [ "$d" = "docs" ] && continue
    PKGS+=("$d")
  done < <(find . \( -name node_modules -o -name .git -o -name vendor \) -prune -o -name INVARIANTS.md -type f -print | LC_ALL=C sort)
fi
[ ${#PKGS[@]} -gt 0 ] || { echo "usage: $0 [--root DIR] [--dry-run] (--all | <pkg-dir>...)" >&2; exit 2; }

DEF_ANY='^[[:space:]]*[-*][[:space:]]+\*\*INV-[^*[:space:]]+\*\*'
DEF_COL0='^- \*\*INV-[^*[:space:]]+\*\*'
NOTE_MARK='<!-- invariants-fragments: migrated -->'

# ---- phase 1: validate every target package; write nothing ---------------
fail=0
for p in "${PKGS[@]}"; do
  f="$p/INVARIANTS.md"
  if [ "$p" = "docs" ]; then echo "refuse: docs/INVARIANTS.md is the index, not a package" >&2; fail=1; continue; fi
  if [ ! -f "$f" ]; then echo "refuse: $f does not exist" >&2; fail=1; continue; fi
  if ! grep -qE '^Format: `INV-[A-Z]+-NN' "$f"; then
    echo "refuse: $f has no 'Format: \`INV-<PKG>-NN ...\`' line; cannot derive the package prefix" >&2; fail=1; continue
  fi
  odd=$(grep -nE "$DEF_ANY" "$f" | grep -vE "^[0-9]+:- \*\*INV-" || true)
  if [ -n "$odd" ]; then
    echo "refuse: $f has invariant definitions this script does not move (not a column-0 '- **ID**' bullet):" >&2
    echo "$odd" | sed 's/^/    /' >&2; fail=1
  fi
  ids=$( { grep -oE "$DEF_COL0" "$f" | sed -E 's/^- \*\*([^*]+)\*\*/\1/'
           if [ -d "$p/INVARIANTS.d" ]; then
             find "$p/INVARIANTS.d" -maxdepth 1 -name '*.md' -type f -exec basename {} .md \;
           fi; } | LC_ALL=C sort)
  dups=$(printf '%s\n' "$ids" | grep -v '^$' | uniq -d || true)
  if [ -n "$dups" ]; then
    fail=1
    for id in $dups; do
      echo "refuse: $id is defined more than once in $p (INVARIANTS.md and/or INVARIANTS.d/):" >&2
      grep -nF -- "- **$id**" "$f" | sed "s|^|    $f:|" >&2 || true
      [ -f "$p/INVARIANTS.d/$id.md" ] && echo "    $p/INVARIANTS.d/$id.md" >&2
      echo "  renumber all but one of them (give the newer rule a slug ID, e.g. ${id%-*}-<what-it-protects>)," >&2
      echo "  update any references to it, drop it from knownDuplicateInvariantIDs in" >&2
      echo "  internal/statemap/invariants_fragments_guard_test.go, then rerun." >&2
    done
  fi
done
if [ "$fail" != 0 ]; then
  echo "no changes made." >&2
  exit 1
fi

# ---- phase 2: migrate ------------------------------------------------------
for p in "${PKGS[@]}"; do
  f="$p/INVARIANTS.md"
  n=$(grep -cE "$DEF_COL0" "$f" || true)
  if [ "$n" = 0 ]; then
    echo "$p: nothing to migrate (already migrated)"
    continue
  fi
  if [ "$DRY" = 1 ]; then
    echo "$p: would migrate $n invariant(s):"; grep -oE "$DEF_COL0" "$f" | sed -E 's/^- \*\*([^*]+)\*\*/    \1/'
    continue
  fi
  tmp=$(mktemp -d)
  mkdir -p "$tmp/frag"
  awk -v fragdir="$tmp/frag" -v note_mark="$NOTE_MARK" '
    function flush() { if (cur != "") { if (sec != "") printf "<!-- section: %s -->\n", sec > (fragdir "/" cur ".md"); close(fragdir "/" cur ".md"); cur = "" } }
    function emit(l) {
      if (l == "") { if (lastblank) return; lastblank = 1 } else lastblank = 0
      print l
    }
    BEGIN { cur = ""; sec = ""; lastblank = 0; hasnote = 0 }
    index($0, note_mark) { hasnote = 1 }
    { lines[NR] = $0 }
    END {
      for (i = 1; i <= NR; i++) {
        l = lines[i]
        if (cur != "") {
          if (l != "" && l ~ /^[ \t]/ && l !~ /^[ \t]*[-*][ \t]+\*\*INV-/) { print l > (fragdir "/" cur ".md"); continue }
          flush()
        }
        if (match(l, /^- \*\*INV-[^* \t]+\*\*/)) {
          cur = substr(l, 5, RLENGTH - 6)
          print l > (fragdir "/" cur ".md")
          continue
        }
        if (l ~ /^## /) { sec = substr(l, 4); sub(/[ \t]+$/, "", sec) }
        emit(l)
        if (!hasnote && l ~ /^Format: `INV-[A-Z]+-NN/) {
          emit("")
          emit(note_mark)
          emit("Invariants in this package live one per file in `INVARIANTS.d/<ID>.md` (convention:")
          emit("`docs/invariants-fragments.md`). Each fragment ends with a `<!-- section: ... -->` line naming")
          emit("the heading below that it belongs under. To add one, create a new fragment with a slug ID")
          emit("(`INV-<PKG>-<what-it-protects>`); do not add bullets to this file.")
          hasnote = 1
        }
      }
      flush()
    }
  ' "$f" > "$tmp/INVARIANTS.md"
  mkdir -p "$p/INVARIANTS.d"
  for g in "$tmp"/frag/*.md; do
    b=$(basename "$g")
    [ -e "$p/INVARIANTS.d/$b" ] && { echo "internal error: $p/INVARIANTS.d/$b exists" >&2; exit 1; }
  done
  cp "$tmp"/frag/*.md "$p/INVARIANTS.d/"
  # drop a trailing blank line the squeeze may leave at EOF
  sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' "$tmp/INVARIANTS.md" > "$f"
  rm -rf "$tmp"
  echo "$p: migrated $n invariant(s) to $p/INVARIANTS.d/"
done
