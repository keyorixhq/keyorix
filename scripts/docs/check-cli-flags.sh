#!/usr/bin/env bash
# check-cli-flags.sh: fail when the documentation tells a reader to run a `keyorix` or
# `keyorix-server` command that the built binary does not accept.
#
# For every fenced code block in the scanned Markdown files, each command line that starts a
# command with `keyorix` or `keyorix-server` (also after `|`, `&&`, `;`, `$(`, `sudo`, env
# assignments, a leading `$ ` prompt, and across `\` continuations) is checked against the
# binary's own `--help`:
#   - the command path exists (`keyorix secret frobnicate` is reported);
#   - every `--flag` is listed in the Flags / Global Flags section of that command's `--help`.
# A flag that only the help PROSE mentions, or that the CLI hides and refuses (the secret flags
# such as `--mfa-code` and `--password`: the CLI answers with the safe form instead), is not in
# that list and is therefore reported as missing.
#
# What it does NOT check (so a clean run is not a proof): flag VALUES, short flags (-x) as
# names, commands that are not at command position (`docker exec c keyorix ...`, `xargs
# keyorix`, `watch keyorix`), fences in other languages (yaml, json, go, ...), prose and inline
# `code` spans outside a fence, and `keyorix-server` with no subcommand beyond what its --help
# lists. Positional arguments after a leaf command are not validated.
#
# Usage:
#   scripts/docs/check-cli-flags.sh [--cli BIN] [--server BIN] [--allow FILE] [PATH...]
#   scripts/docs/check-cli-flags.sh --self-test [--cli BIN] [--server BIN]
# PATH is a Markdown file or a directory searched for *.md (default: docs QUICK_START.md,
# relative to the repository root). BIN defaults to ./bin/keyorix and ./bin/keyorix-server
# (`make build`). Output: one `file:line: command: problem` per finding on stdout.
# Exit: 0 clean, 1 findings, 2 usage or setup error.
#
# Allow-list (default scripts/docs/check-cli-flags.allow, tab separated, `#` comments):
#   <file glob>  <--flag | cmd:<command words> | *>  <reason, required>
# A row silences one finding kind in the files its glob matches; `*` silences every finding in
# those files. A row without a reason is a setup error; a row that matched nothing is noted on
# stderr (it may be stale) but does not fail the run.
set -u

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$script_dir/../.." && pwd)

cli_bin="$repo_root/bin/keyorix"
server_bin="$repo_root/bin/keyorix-server"
allow_file="$script_dir/check-cli-flags.allow"
self_test=0
paths=()

while [ $# -gt 0 ]; do
  case "$1" in
    --cli) cli_bin="$2"; shift 2 ;;
    --server) server_bin="$2"; shift 2 ;;
    --allow) allow_file="$2"; shift 2 ;;
    --self-test) self_test=1; shift ;;
    -h|--help) sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --) shift; while [ $# -gt 0 ]; do paths+=("$1"); shift; done ;;
    -*) echo "check-cli-flags: unknown option $1" >&2; exit 2 ;;
    *) paths+=("$1"); shift ;;
  esac
done

for b in "$cli_bin" "$server_bin"; do
  if [ ! -x "$b" ]; then
    echo "check-cli-flags: $b is not an executable; build it first (make build) or pass --cli/--server" >&2
    exit 2
  fi
done

work=$(mktemp -d "${TMPDIR:-/tmp}/check-cli-flags.XXXXXX") || exit 2
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/help"

# ---------------------------------------------------------------------------------------------
# Stage 1 (awk): one record per command occurrence in a fenced block:
#   file:line <US> binary <US> token <US> token ...
# ---------------------------------------------------------------------------------------------
cat > "$work/extract.awk" <<'AWK'
function basename(s) { sub(/.*\//, "", s); return s }
function is_redirect(t) {
  return (t ~ /^[0-9]*>/ || t == "<" || t ~ /^<<-?["'A-Za-z_]/ || t ~ /^&>/)
}
function emit(  k, b, out, i) {
  k = 1
  while (k <= nt) {
    if (tk[k] ~ /^[A-Za-z_][A-Za-z0-9_]*=/ || tk[k] == "sudo" || tk[k] == "exec" || tk[k] == "time" || tk[k] == "nohup" || tk[k] == "env" || tk[k] == "command") k++
    else break
  }
  if (k > nt) return
  b = basename(tk[k])
  if (b != "keyorix" && b != "keyorix-server") return
  out = where US b
  for (i = k + 1; i <= nt; i++) {
    if (tk[i] == "") continue
    out = out US tk[i]
  }
  print out
}
function reset_seg() { nt = 0; stopped = 0 }
function end_tok() {
  if (!intok) return
  intok = 0
  if (stopped) { cur = ""; return }
  if (is_redirect(cur) && !quoted) { stopped = 1; cur = ""; return }
  sub(/^\[+/, "", cur); sub(/\]+$/, "", cur)
  nt++; tk[nt] = cur; cur = ""
}
function parse(s,   i, c, n, q, d) {
  reset_seg(); cur = ""; intok = 0; quoted = 0; q = ""
  n = length(s)
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (q != "") {
      if (c == q) { q = ""; continue }
      if (q == "\"" && c == "\\" && i < n) { i++; cur = cur substr(s, i, 1); continue }
      cur = cur c; continue
    }
    if (c == "'" || c == "\"") { q = c; intok = 1; quoted = 1; continue }
    if (c == " " || c == "\t") { end_tok(); quoted = 0; continue }
    if (c == "#" && !intok) break
    if (c == "|" || c == ";" || c == "`" || c == "(" || c == ")") {
      end_tok(); quoted = 0; emit(); reset_seg(); continue
    }
    if (c == "&") {
      d = substr(s, i + 1, 1)
      if (d == ">" ) { cur = cur c; intok = 1; continue }
      end_tok(); quoted = 0; emit(); reset_seg(); continue
    }
    if (c == "$" && substr(s, i + 1, 1) == "(") { end_tok(); quoted = 0; emit(); reset_seg(); i++; continue }
    if (c == "\\" && i < n) { i++; cur = cur substr(s, i, 1); intok = 1; continue }
    cur = cur c; intok = 1
  }
  end_tok(); emit()
}
function flush_logical() {
  if (logical == "") return
  l = logical; logical = ""
  sub(/^[ \t]*[$>][ \t]+/, "", l)
  where = FILENAME ":" start
  parse(l)
}
BEGIN { US = "\037" }
FNR == 1 { infence = 0; process = 0; logical = "" }
{
  line = $0
  if (line ~ /^[ \t]*(```|~~~)/) {
    if (infence) { flush_logical(); infence = 0; process = 0 }
    else {
      infence = 1
      lang = line; sub(/^[ \t]*(```|~~~)[ \t]*/, "", lang); sub(/[ \t{].*$/, "", lang)
      process = (lang == "" || lang ~ /^(bash|sh|shell|console|text|zsh|terminal|session|shell-session)$/)
    }
    next
  }
  if (!infence || !process) next
  if (logical == "") start = FNR
  if (line ~ /\\[ \t]*$/) { sub(/\\[ \t]*$/, " ", line); logical = logical line; next }
  logical = logical line
  flush_logical()
}
END { if (infence) flush_logical() }
AWK

# ---------------------------------------------------------------------------------------------
# Help parsing. help_file <bin-tag> <bin> <path words...> -> prints the cached help file name.
# ---------------------------------------------------------------------------------------------
help_file() {
  local tag="$1" bin="$2"; shift 2
  local key="$tag"
  local w
  for w in "$@"; do key="$key.$w"; done
  local f="$work/help/$key.txt"
  if [ ! -f "$f" ]; then
    "$bin" "$@" --help > "$f" 2>&1 < /dev/null || true
  fi
  printf '%s' "$f"
}

# subcommands of a help file, one per line
help_commands() {
  awk '/^([A-Za-z][A-Za-z ]* )?Commands:[ \t]*$/ { on = 1; next }
       on && /^[ \t]*$/ { on = 0 }
       on && /^[ \t]+[a-z]/ { print $1 }' "$1"
}

# flags of a help file: "name<TAB>V|B" (V = takes a value), from Flags / Global Flags sections only
help_flags() {
  awk '/^([A-Za-z][A-Za-z ]* )?Flags:[ \t]*$/ { on = 1; next }
       /^[A-Za-z]/ { on = 0 }
       on && /^[ \t]+(-[A-Za-z], )?--[A-Za-z0-9]/ {
         s = $0
         sub(/^[ \t]+(-[A-Za-z], )?--/, "", s)
         name = s; sub(/[^A-Za-z0-9_-].*$/, "", name)
         rest = substr(s, length(name) + 1)
         kind = "B"
         if (rest ~ /^ [^ ]/) kind = "V"
         print name "\t" kind
       }
       # keyorix-server with no subcommand uses Go'"'"'s flag package: "Usage of ...", then
       # "  -name type" lines (one or two dashes are both accepted by that parser).
       NR == 1 && /^Usage of / { gostyle = 1; next }
       gostyle && /^  -{1,2}[A-Za-z]/ {
         s = $0; sub(/^  -{1,2}/, "", s)
         n = split(s, w, " ")
         print w[1] "\t" (n > 1 ? "V" : "B")
       }' "$1"
}

# ---------------------------------------------------------------------------------------------
# Allow-list
# ---------------------------------------------------------------------------------------------
allow_glob=(); allow_what=(); allow_reason=(); allow_used=()
load_allow() {
  [ -f "$allow_file" ] || return 0
  local n=0 line g w r
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    case "$line" in ''|'#'*) continue ;; esac
    g=$(printf '%s' "$line" | awk -F '\t' '{print $1}')
    w=$(printf '%s' "$line" | awk -F '\t' '{print $2}')
    r=$(printf '%s' "$line" | awk -F '\t' '{print $3}')
    if [ -z "$g" ] || [ -z "$w" ] || [ -z "$(printf '%s' "$r" | tr -d ' ')" ]; then
      echo "check-cli-flags: $allow_file:$n: a row needs <file glob> <what> <reason>, tab separated, with a reason" >&2
      exit 2
    fi
    allow_glob+=("$g"); allow_what+=("$w"); allow_reason+=("$r"); allow_used+=(0)
  done < "$allow_file"
}

# allowed <file> <what>: 0 when an allow-list row silences it
allowed() {
  local file="$1" what="$2" i=0 g w
  while [ "$i" -lt "${#allow_glob[@]}" ]; do
    g="${allow_glob[$i]}"; w="${allow_what[$i]}"
    # shellcheck disable=SC2254
    case "$file" in
      $g) if [ "$w" = "*" ] || [ "$w" = "$what" ]; then allow_used[i]=1; return 0; fi ;;
    esac
    i=$((i + 1))
  done
  return 1
}

# ---------------------------------------------------------------------------------------------
# Stage 2: check one record.
# ---------------------------------------------------------------------------------------------
findings=0
report() { # report <where> <what-for-allowlist> <message>
  local where="$1" what="$2" msg="$3" file
  file="${where%:*}"
  if allowed "$file" "$what"; then return; fi
  printf '%s: %s\n' "$where" "$msg"
  findings=$((findings + 1))
}

check_record() {
  local where="$1" binname="$2"; shift 2
  local bin tag
  if [ "$binname" = "keyorix-server" ]; then bin="$server_bin"; tag="server"; else bin="$cli_bin"; tag="cli"; fi
  local path=() flags=() skip=0 stop_flags=0 t name hf kind word cmds cmdtext
  hf=$(help_file "$tag" "$bin")
  for t in "$@"; do
    if [ "$skip" -eq 1 ]; then skip=0; continue; fi
    if [ "$stop_flags" -eq 1 ]; then continue; fi
    case "$t" in
      --) stop_flags=1 ;;
      --*)
        name="${t#--}"; name="${name%%=*}"
        case "$name" in *'<'*|*'>'*|*'$'*|*'.'*|'') continue ;; esac
        flags+=("$name")
        case "$t" in
          *=*) ;;
          *) kind=$(help_flags "$hf" | awk -F '\t' -v n="$name" '$1 == n {print $2; exit}')
             if [ "$kind" = "V" ]; then skip=1; fi ;;
        esac ;;
      -*) ;;
      *)
        word="$t"
        cmds=$(help_commands "$hf")
        if [ "$tag" = "server" ] && [ "${#path[@]}" -eq 0 ] && [ "$word" = "admin" ]; then
          # `keyorix-server admin` is dispatched before flag parsing; its --help is cobra's.
          path+=("admin")
          hf=$(help_file "$tag" "$bin" "${path[@]}")
        elif [ -n "$cmds" ]; then
          if printf '%s\n' "$cmds" | grep -qx -- "$word"; then
            path+=("$word")
            hf=$(help_file "$tag" "$bin" "${path[@]}")
          else
            # A lowercase word that is not a listed subcommand is a typo or a removed command;
            # anything else (<placeholder>, $VAR, a path, a name with dots) is an argument.
            if printf '%s' "$word" | grep -Eq '^[a-z][a-z0-9-]*$'; then
              cmdtext="$binname"
              [ "${#path[@]}" -gt 0 ] && cmdtext="$binname ${path[*]}"
              report "$where" "cmd:${cmdtext#"$binname" }$word" "$cmdtext $word: unknown command \"$word\" (try: $cmdtext --help)"
              return
            fi
          fi
        fi ;;
    esac
  done
  # Validate the collected flags against the final command's help.
  local known
  cmdtext="$binname"
  [ "${#path[@]}" -gt 0 ] && cmdtext="$binname ${path[*]}"
  known=$(help_flags "$hf" | awk -F '\t' '{print $1}')
  for name in "${flags[@]+"${flags[@]}"}"; do
    [ "$name" = "help" ] && continue
    if ! printf '%s\n' "$known" | grep -qx -- "$name"; then
      report "$where" "--$name" "$cmdtext: unknown flag --$name (not in \`$cmdtext --help\`; a secret flag the CLI refuses counts as unknown)"
    fi
  done
}

scan() {
  local files=() p
  for p in "${paths[@]}"; do
    if [ -d "$p" ]; then
      while IFS= read -r f; do files+=("$f"); done < <(find "$p" -name '*.md' -type f | sort)
    elif [ -f "$p" ]; then
      files+=("$p")
    else
      echo "check-cli-flags: no such file or directory: $p" >&2; exit 2
    fi
  done
  [ "${#files[@]}" -gt 0 ] || return 0
  awk -f "$work/extract.awk" "${files[@]}" > "$work/records.txt"
  local rec
  while IFS= read -r rec || [ -n "$rec" ]; do
    local IFS_SAVE="$IFS"
    IFS=$'\037' read -r -a fields <<< "$rec"
    IFS="$IFS_SAVE"
    check_record "${fields[@]}"
  done < "$work/records.txt"
}

# ---------------------------------------------------------------------------------------------
# Self-test: a planted bad line in a temp copy must be reported, a good one must not.
# ---------------------------------------------------------------------------------------------
run_self_test() {
  local d="$work/selftest"
  mkdir -p "$d"
  cat > "$d/good.md" <<'EOF'
# good
```bash
keyorix login --server https://localhost:8080 --username alice
KEYORIX_X=1 ./bin/keyorix-server admin init --config ./keyorix.yaml
printf '%s' "$K" | keyorix-server admin recover-admin --user a@b.c --recovery-key - --config ./keyorix.yaml
keyorix audit logs --limit 20 \
  --event-type secret.read
keyorix secret create --name <name> --interactive   # a placeholder and a comment
```
EOF
  cat > "$d/bad.md" <<'EOF'
# bad
```bash
keyorix login --server https://localhost:8080 --username alice --mfa-code 123456
keyorix secret frobnicate --name x
keyorix-server admin init --no-such-flag
echo hi | keyorix audit logs \
  --bogus-flag 3
```
EOF
  paths=("$d/good.md"); allow_glob=(); allow_what=(); allow_reason=(); allow_used=(); findings=0
  scan > "$work/good.out"
  if [ "$findings" -ne 0 ]; then
    echo "self-test FAILED: the good file produced findings:" >&2; cat "$work/good.out" >&2; exit 1
  fi
  paths=("$d/bad.md"); findings=0
  scan > "$work/bad.out"
  local want rc=0
  for want in "bad.md:3: .*--mfa-code" "bad.md:4: .*unknown command \"frobnicate\"" "bad.md:5: .*--no-such-flag" "bad.md:6: .*--bogus-flag"; do
    if ! grep -q -- "$want" "$work/bad.out"; then
      echo "self-test FAILED: missing finding matching: $want" >&2; rc=1
    fi
  done
  if [ "$findings" -ne 4 ]; then
    echo "self-test FAILED: expected 4 findings, got $findings" >&2; rc=1
  fi
  if [ "$rc" -ne 0 ]; then cat "$work/bad.out" >&2; exit 1; fi
  echo "self-test ok: 4 planted problems reported, good file clean"
  exit 0
}

if [ "$self_test" -eq 1 ]; then run_self_test; fi

cd "$repo_root" || exit 2
full_scan=0
if [ "${#paths[@]}" -eq 0 ]; then
  full_scan=1
  for p in docs QUICK_START.md; do [ -e "$p" ] && paths+=("$p"); done
fi
load_allow
scan

i=0
while [ "$i" -lt "${#allow_glob[@]}" ]; do
  if [ "$full_scan" -eq 1 ] && [ "${allow_used[$i]}" -eq 0 ]; then
    echo "check-cli-flags: note: allow-list row for '${allow_glob[$i]}' '${allow_what[$i]}' matched nothing (stale?)" >&2
  fi
  i=$((i + 1))
done

if [ "$findings" -gt 0 ]; then
  echo "check-cli-flags: $findings finding(s). Fix the docs, or add a reason row to $allow_file for a placeholder." >&2
  exit 1
fi
echo "check-cli-flags: ok (no documented keyorix / keyorix-server command or flag is missing from the binary's --help)"
