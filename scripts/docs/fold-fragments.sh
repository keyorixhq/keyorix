#!/usr/bin/env bash
# fold-fragments.sh -- fold docs/configuration.d/*.md and docs/upgrading.d/*.md into
# docs/CONFIGURATION.md and docs/UPGRADING.md.
#
# Why: a feature or fix PR documents a new config key in docs/configuration.d/ and an
# upgrade note in docs/upgrading.d/ and never edits the two flat files (CLAUDE.md,
# "Docs: new config keys and upgrade notes go in docs/*.d/"). Only a dedicated
# documentation PR (branch docs/fold-* or docs/consolidate-*) edits them directly, and it
# runs this script to do the folding so nobody pastes by hand.
#
#   scripts/docs/fold-fragments.sh --dry-run
#       Print where each fragment would go and change nothing. Exit 1 if a fragment
#       cannot be placed (the same checks as --check).
#
#   scripts/docs/fold-fragments.sh --check
#       Change nothing, print nothing on success. Exit 0 when every fragment can be
#       placed and every rule of the map file names an existing heading; exit 1 (with
#       one line per problem) when a fragment cannot be placed or a rule is stale. Having
#       fragments is NOT a problem: they are the normal state between folds.
#
#   scripts/docs/fold-fragments.sh
#       Fold: append each fragment into the flat file and delete the fragment file, then
#       print the placement of each. Everything is computed first; if any fragment cannot
#       be placed nothing is written and nothing is deleted (exit 1). Afterwards run
#       `go test ./internal/docsdrift/`.
#
#   scripts/docs/fold-fragments.sh --self-test
#       Run the script against a throw-away copy of its inputs (placement by parent
#       heading, by map rule, by first segment, an unplaceable fragment that must fail,
#       the next upgrading section number). Exit 1 on a mismatch.
#
# Config fragments (docs/configuration.d/<key with dots as __>.md), in file-name order.
# The text is appended at the end of the first section that matches, first hit wins:
#   1. a heading of any level that names the key's parent in backticks, longest parent
#      first (storage__database__fdatasync.md -> a heading containing `storage.database`,
#      else one containing `storage`);
#   2. the "## <heading>" that scripts/docs/fold-fragments.map gives for the key's prefix
#      (longest whole-segment prefix);
#   3. the "## <first segment of the key>" section.
# The fragment text is inserted as written; the section ends at the next heading of the
# same or a higher level. Headings inside fenced code blocks are not headings.
#
# Upgrading fragments (docs/upgrading.d/<slug>.md), in file-name order: the fragment must
# start with an unnumbered "## <title>" heading. It gets the next free section number
# (one past the highest letter-only id 6<letters> in UPGRADING.md, ordered by length then
# alphabet: 6z -> 6za -> 6zb) and is inserted after the last "## 6..." section, before
# the first later "## " heading (## 7. Rollback ...). Cross-references inside the
# fragment text are not rewritten: read the folded text once.
#
# It never edits anything else. The flat-file sections 6x and the renamed-settings table
# stay as they are; wording corrections of existing text are made by hand in the
# dedicated documentation PR, not through a fragment (no reader accepts a fragment that
# names no new key).
#
# Environment (self-test): FOLD_CONFIG_DOC, FOLD_UPGRADING_DOC, FOLD_CONFIG_DIR,
# FOLD_UPGRADING_DIR, FOLD_MAP override the paths.
# shellcheck disable=SC2016  # awk programs and markdown samples are literal, not shell expansions
set -euo pipefail
# Byte-order glob expansion and string comparison: identical output on macOS and the
# Linux CI runner regardless of locale collation.
export LC_ALL=C

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

CONFIG_DOC="${FOLD_CONFIG_DOC:-docs/CONFIGURATION.md}"
UPGRADING_DOC="${FOLD_UPGRADING_DOC:-docs/UPGRADING.md}"
CONFIG_DIR="${FOLD_CONFIG_DIR:-docs/configuration.d}"
UPGRADING_DIR="${FOLD_UPGRADING_DIR:-docs/upgrading.d}"
MAP_FILE="${FOLD_MAP:-scripts/docs/fold-fragments.map}"

die() { echo "fold-fragments: $*" >&2; exit 1; }

fragments() { # <dir>: fragment paths in file-name order, README.md excluded
  local f
  for f in "$1"/*.md; do
    [ -e "$f" ] || continue
    [ "$(basename "$f")" = "README.md" ] && continue
    echo "$f"
  done
}

# place_config <doc-in> <doc-out> <report> <fragment> <strategies>
# Strategies: one "P<TAB><level><TAB><text>" (heading naming `text`) or
# "H<TAB><level><TAB><text>" (exact "## text" heading) per line, tried in order.
# Fragments live one directory below the flat files (docs/upgrading.d/ vs docs/), so a
# relative link written for the fragment ("../CONFIGURATION.md#x") loses one "../" when the
# text moves up (TestDocLinksResolve). Lines inside code fences are left alone.
REWRITE_AWK='
function rewrite(s) {
  gsub(/\]\(\.\.\//, "](", s)
  if (s ~ /^[ \t]*\[[^]]*\]:[ \t]+\.\.\//) sub(/\.\.\//, "", s)
  return s
}
function load_fragment(fn,   line, f) {
  nf = 0
  while ((getline line < fn) > 0) {
    if (line ~ /^[ \t]*(```|~~~)/) { f = !f; F[++nf] = line; continue }
    F[++nf] = f ? line : rewrite(line)
  }
  close(fn)
  while (nf > 0 && F[nf] ~ /^[ \t]*$/) nf--
}'

PLACE_CONFIG_AWK=$REWRITE_AWK'
BEGIN { ns = split(ENVIRON["FOLD_STRATEGIES"], S, "\n") }
{
  L[++n] = $0
  H[n] = 0
  if ($0 ~ /^[ \t]*(```|~~~)/) { fence = !fence; next }
  if (!fence && match($0, /^#+ /)) H[n] = RLENGTH - 1
}
END {
  tgt = 0
  for (s = 1; s <= ns && !tgt; s++) {
    split(S[s], P, "\t")
    for (i = 1; i <= n; i++) {
      if (!H[i]) continue
      if (P[1] == "P" && index(L[i], "`" P[3] "`")) { tgt = i; break }
      if (P[1] == "H" && H[i] == P[2] && L[i] == substr("######", 1, P[2]) " " P[3]) { tgt = i; break }
    }
  }
  if (!tgt) exit 3
  e = n + 1
  for (j = tgt + 1; j <= n; j++) if (H[j] && H[j] <= H[tgt]) { e = j; break }
  while (e - 1 > tgt && L[e - 1] ~ /^[ \t]*$/) e--
  load_fragment(ENVIRON["FOLD_FRAGMENT"])
  for (i = 1; i < e; i++) print L[i]
  print ""
  for (i = 1; i <= nf; i++) print F[i]
  for (i = e; i <= n; i++) print L[i]
  print "section line " tgt ": " L[tgt] > ENVIRON["FOLD_REPORT"]
}'

PLACE_UPGRADING_AWK=$REWRITE_AWK'
function nextid(m,   c, k) {
  if (m == "") return "a"
  c = substr(m, length(m))
  if (c == "z") return m "a"
  k = index("abcdefghijklmnopqrstuvwxyz", c)
  return substr(m, 1, length(m) - 1) substr("abcdefghijklmnopqrstuvwxyz", k + 1, 1)
}
{
  L[++n] = $0
  H2[n] = 0
  if ($0 ~ /^[ \t]*(```|~~~)/) { fence = !fence; next }
  if (fence || $0 !~ /^## /) next
  H2[n] = 1
  if ($0 ~ /^## 6([a-z]*)(\.[0-9]+)?[. ]/) {
    last6 = n
    id = $0; sub(/^## 6/, "", id); sub(/[^a-z].*$/, "", id)
    if (id != "" && (length(id) > length(maxid) || (length(id) == length(maxid) && id > maxid))) maxid = id
  }
}
END {
  if (!last6) exit 3
  e = n + 1
  for (j = last6 + 1; j <= n; j++) if (H2[j]) { e = j; break }
  while (e - 1 > last6 && L[e - 1] ~ /^[ \t]*$/) e--
  load_fragment(ENVIRON["FOLD_FRAGMENT"])
  first = 1
  while (first <= nf && F[first] ~ /^[ \t]*$/) first++
  if (first > nf || F[first] !~ /^## / || F[first] ~ /^## [0-9]/) exit 4
  new = "6" nextid(maxid)
  F[first] = "## " new ". " substr(F[first], 4)
  for (i = 1; i < e; i++) print L[i]
  print ""
  for (i = first; i <= nf; i++) print F[i]
  for (i = e; i <= n; i++) print L[i]
  print "as section " new " (after line " last6 ")" > ENVIRON["FOLD_REPORT"]
}'

# config_strategies <key>: print the strategy lines for a key.
config_strategies() {
  local key="$1" parent rest prefix head best bestlen=0 first
  parent="${key%.*}"
  while [ "$parent" != "$key" ] && [ -n "$parent" ]; do
    printf 'P\t0\t%s\n' "$parent"
    case "$parent" in *.*) parent="${parent%.*}" ;; *) break ;; esac
  done
  if [ -f "$MAP_FILE" ]; then
    while IFS=$'\t' read -r prefix head; do
      case "$prefix" in ''|'#'*) continue ;; esac
      case "$key." in "$prefix".*) ;; *) continue ;; esac
      if [ "${#prefix}" -gt "$bestlen" ]; then best="$head"; bestlen="${#prefix}"; fi
    done < "$MAP_FILE"
    [ "$bestlen" -gt 0 ] && printf 'H\t2\t%s\n' "$best"
  fi
  first="${key%%.*}"
  printf 'H\t2\t%s\n' "$first"
}

problems=()
report=()

# fold_one <kind: config|upgrading> <fragment>: apply to the working copy; record problems.
fold_one() {
  local kind="$1" frag="$2" src out rc=0 rep key base
  rep="$work/report"
  : > "$rep"
  base="$(basename "$frag" .md)"
  if [ "$kind" = config ]; then
    src="$work/config.md"; out="$work/config.next"
    key="${base//__/.}"
    case "$base" in
      *__*) ;;
      *) problems+=("$frag: name is not <key with dots as __>.md"); return ;;
    esac
    [ -s "$frag" ] || { problems+=("$frag: empty fragment"); return; }
    FOLD_STRATEGIES="$(config_strategies "$key")" FOLD_FRAGMENT="$frag" FOLD_REPORT="$rep" \
      awk "$PLACE_CONFIG_AWK" "$src" > "$out" || rc=$?
    if [ "$rc" -ne 0 ]; then
      problems+=("$frag: cannot place key $key: no heading names \`${key%.*}\` in backticks, $MAP_FILE has no rule for its prefix, and $CONFIG_DOC has no \"## ${key%%.*}\" section; add a rule to $MAP_FILE or fold it by hand")
      return
    fi
    mv "$out" "$src"
    report+=("$frag -> $CONFIG_DOC, $(cat "$rep")")
  else
    src="$work/upgrading.md"; out="$work/upgrading.next"
    FOLD_FRAGMENT="$frag" FOLD_REPORT="$rep" awk "$PLACE_UPGRADING_AWK" "$src" > "$out" || rc=$?
    case "$rc" in
      0) ;;
      3) problems+=("$frag: $UPGRADING_DOC has no \"## 6...\" section to insert after"); return ;;
      *) problems+=("$frag: must start with an unnumbered \"## <title>\" heading"); return ;;
    esac
    mv "$out" "$src"
    report+=("$frag -> $UPGRADING_DOC, $(cat "$rep")")
  fi
}

# map_problems: every rule's heading must exist in the config doc.
map_problems() {
  local prefix head
  [ -f "$MAP_FILE" ] || return 0
  while IFS=$'\t' read -r prefix head; do
    case "$prefix" in ''|'#'*) continue ;; esac
    [ -n "$head" ] || { problems+=("$MAP_FILE: rule for \"$prefix\" has no heading"); continue; }
    grep -qxF -- "## $head" "$CONFIG_DOC" || problems+=("$MAP_FILE: rule \"$prefix\" names \"## $head\", which is not a heading of $CONFIG_DOC")
  done < "$MAP_FILE"
}

run() { # <mode: fold|dry-run|check>
  local mode="$1" f
  [ -f "$CONFIG_DOC" ] || die "$CONFIG_DOC not found"
  [ -f "$UPGRADING_DOC" ] || die "$UPGRADING_DOC not found"
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  cp "$CONFIG_DOC" "$work/config.md"
  cp "$UPGRADING_DOC" "$work/upgrading.md"
  map_problems
  for f in $(fragments "$CONFIG_DIR"); do fold_one config "$f"; done
  for f in $(fragments "$UPGRADING_DIR"); do fold_one upgrading "$f"; done
  if [ "${#problems[@]}" -gt 0 ]; then
    printf 'fold-fragments: %s\n' "${problems[@]}" >&2
    exit 1
  fi
  [ "$mode" = check ] && return 0
  if [ "${#report[@]}" -eq 0 ]; then echo "fold-fragments: no fragments to fold"; return 0; fi
  if [ "$mode" = dry-run ]; then
    echo "fold-fragments: dry run, nothing written; would fold:"
  else
    cp "$work/config.md" "$CONFIG_DOC"
    cp "$work/upgrading.md" "$UPGRADING_DOC"
    for f in $(fragments "$CONFIG_DIR") $(fragments "$UPGRADING_DIR"); do rm -- "$f"; done
    echo "fold-fragments: folded and deleted; now run: go test ./internal/docsdrift/"
  fi
  printf '  %s\n' "${report[@]}"
}

self_test() {
  local fail=0
  t="$(mktemp -d)" # global: the EXIT trap runs after this function returns
  trap 'rm -rf "$t"' EXIT
  mkdir -p "$t/c" "$t/u"
  cat > "$t/CONFIG.md" <<'EOF'
# Cfg

## storage

Intro.

### Committing (`storage.database`)

Existing parent text.

```yaml
# not a heading
```

### Other

tail

## soft_delete & purge

Purge text.

## server

Server text.
EOF
  cat > "$t/UPGRADING.md" <<'EOF'
# Up

## 6y. Y

y

## 6z. Z

z

## 6za. ZA

za

## 7. Rollback

r
EOF
  printf '### `storage.database.fdatasync`\n\nSyncs.\n' > "$t/c/storage__database__fdatasync.md"
  printf '### `purge.schedule`\n\nCron.\n' > "$t/c/purge__schedule.md"
  printf '### `server.http.port`\n\nPort.\n' > "$t/c/server__http__port.md"
  printf '## New thing\n\nDo it, see [cfg](../CONFIGURATION.md#a).\n\n```\n[x](../keep.md)\n```\n' > "$t/u/new-thing.md"
  printf 'README\n' > "$t/c/README.md"
  printf 'x\n' > "$t/map"
  printf 'purge\tsoft_delete & purge\n' > "$t/map"
  export FOLD_CONFIG_DOC="$t/CONFIG.md" FOLD_UPGRADING_DOC="$t/UPGRADING.md" FOLD_CONFIG_DIR="$t/c" \
    FOLD_UPGRADING_DIR="$t/u" FOLD_MAP="$t/map"
  "${BASH_SOURCE[0]}" --check || { echo "self-test: --check failed on a placeable set" >&2; fail=1; }
  "${BASH_SOURCE[0]}" >/dev/null || { echo "self-test: fold failed" >&2; fail=1; }
  [ -z "$(fragments "$t/c")$(fragments "$t/u")" ] || { echo "self-test: fragments not deleted" >&2; fail=1; }
  awk '/^### Committing/{a=1} a&&/fdatasync/{ok=1} /^### Other/{a=0} END{exit !ok}' "$t/CONFIG.md" || { echo "self-test: parent-heading placement wrong" >&2; fail=1; }
  awk '/^## soft_delete/{a=1} a&&/purge.schedule/{ok=1} /^## server/{a=0} END{exit !ok}' "$t/CONFIG.md" || { echo "self-test: map placement wrong" >&2; fail=1; }
  awk '/^## server/{a=1} a&&/server.http.port/{ok=1} END{exit !ok}' "$t/CONFIG.md" || { echo "self-test: first-segment placement wrong" >&2; fail=1; }
  grep -qF '[cfg](CONFIGURATION.md#a)' "$t/UPGRADING.md" || { echo "self-test: relative link not rewritten" >&2; fail=1; }
  grep -qF '[x](../keep.md)' "$t/UPGRADING.md" || { echo "self-test: link inside a code fence must stay" >&2; fail=1; }
  grep -qx '## 6zb. New thing' "$t/UPGRADING.md" || { echo "self-test: next upgrading id should be 6zb" >&2; fail=1; }
  awk '/^## 6zb/{a=1} /^## 7\./{if(!a)exit 1; ok=1} END{exit !ok}' "$t/UPGRADING.md" || { echo "self-test: 6zb must precede ## 7." >&2; fail=1; }
  printf '### `client.endpoint`\n\nURL.\n' > "$t/c/client__endpoint.md"
  if "${BASH_SOURCE[0]}" --check 2>/dev/null; then echo "self-test: an unplaceable fragment passed --check" >&2; fail=1; fi
  [ -f "$t/c/client__endpoint.md" ] || { echo "self-test: --check must not delete" >&2; fail=1; }
  [ "$fail" -eq 0 ] || exit 1
  echo "fold-fragments: self-test ok"
}

case "${1:-}" in
  --check) run check ;;
  --dry-run) run dry-run ;;
  --self-test) self_test ;;
  "") run fold ;;
  *) die "usage: $0 [--dry-run | --check | --self-test]" ;;
esac
