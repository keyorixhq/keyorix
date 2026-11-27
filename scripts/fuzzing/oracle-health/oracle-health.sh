#!/usr/bin/env bash
# oracle-health.sh -- is each fuzz harness still able to see the defect it was
# red-proofed against? For every entry in entries.d/ it makes a throwaway copy of
# the tree, runs the harness unmodified (the control, must be green), applies the
# planted-defect patch, replays the harness's seed corpus (deterministic, no
# fuzzing time) and requires a FAIL that carries the entry's marker text.
# A harness that stays green on its planted defect has gone blind: exit 1.
#
# Usage: oracle-health.sh [--list] [--only id[,id...]] [--heavy] [--strict]
#                         [--ref REF] [--workdir DIR] [--tsv FILE] [--keep]
#                         [--root DIR] [--entries DIR]
#   --root     repo to test (default: the checkout this script lives in); a Go repo
#              such as dashdiag works the same way, patches apply to that tree
#   --entries  registry directory (default: entries.d next to this script)
#   --list     print the registry and exit
#   --only     run just these entries
#   --heavy    include entries marked HEAVY=1 (minutes; meant for the nightly host)
#   --strict   a SKIP (no Postgres, no superuser role, ...) fails the run (exit 3)
#   --ref      tree to test (default HEAD)
#   --workdir  where the throwaway trees go (default: a fresh mktemp -d)
#   --tsv      also write the result table, tab separated
#   --keep     keep the throwaway trees (debugging)
# Exit: 0 all entries healthy (SKIPs and KNOWN-BLIND are listed, not failed),
#       1 a control was red or a planted defect was missed, 2 usage, 3 only SKIPs
#       under --strict.
# Never edits the checkout it is run from; every plant lives in a copy. See
# scripts/fuzzing/README.md ("Oracle health") for the entry format.
set -u

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"
entries="$here/entries.d"

only="" heavy=0 strict=0 ref=HEAD workdir="" tsv="" keep=0 list=0 root_arg=""
while [ $# -gt 0 ]; do
	case $1 in
	--root) root_arg=$2; shift ;;
	--entries) entries=$2; shift ;;
	--list) list=1 ;;
	--only) only=$2; shift ;;
	--heavy) heavy=1 ;;
	--strict) strict=1 ;;
	--ref) ref=$2; shift ;;
	--workdir) workdir=$2; shift ;;
	--tsv) tsv=$2; shift ;;
	--keep) keep=1 ;;
	-h | --help) sed -n '2,27p' "${BASH_SOURCE[0]}"; exit 0 ;;
	*) echo "oracle-health: unknown argument $1" >&2; exit 2 ;;
	esac
	shift
done

# Resolve the registry once: plants and replay generators are used after `cd "$tree"`,
# where a relative --entries path no longer points anywhere.
[ -d "$entries" ] || { echo "oracle-health: no registry directory $entries" >&2; exit 2; }
entries=$(cd "$entries" && pwd) || exit 2

log() {
	local line
	line="$(date -u +%Y-%m-%dT%H:%M:%SZ) oracle-health: $*"
	echo "$line" >&2
	[ -z "${OH_LOG:-}" ] || echo "$line" >>"$OH_LOG"
}

ids=()
for f in "$entries"/*.conf; do
	[ -e "$f" ] || continue
	id=$(basename "$f" .conf)
	if [ -n "$only" ]; then
		case ",$only," in *",$id,"*) ;; *) continue ;; esac
	fi
	ids+=("$id")
done
if [ -n "$only" ]; then
	IFS=, read -r -a want <<<"$only"
	for w in "${want[@]}"; do
		[ -e "$entries/$w.conf" ] || { echo "oracle-health: no entry '$w'" >&2; exit 2; }
	done
fi

if [ $list = 1 ]; then
	for id in "${ids[@]}"; do
		oh_parse_conf "$entries/$id.conf" >/dev/null || { echo "$id: bad conf"; continue; }
		printf '%s\t%s\t%s\tneeds=%s\theavy=%s\t%s\n' "$id" "$OH_KIND" "${OH_FAMILY:-}" "$OH_NEEDS" "$OH_HEAVY" "${OH_KNOWN_BLIND:+known-blind $OH_KNOWN_BLIND}"
	done
	exit 0
fi

root=$(git -C "${root_arg:-$here}" rev-parse --show-toplevel 2>/dev/null) || { echo "oracle-health: not inside a git checkout" >&2; exit 2; }
sha=$(git -C "$root" rev-parse --short=12 "$ref") || { echo "oracle-health: unknown ref $ref" >&2; exit 2; }
if [ -z "$workdir" ]; then workdir=$(mktemp -d) || exit 2; fi
if ! mkdir -p "$workdir" || ! workdir=$(cd "$workdir" && pwd); then
	echo "oracle-health: cannot use workdir $workdir" >&2
	exit 2
fi
log "tree=$sha entries=${#ids[@]} workdir=$workdir strict=$strict heavy=$heavy"

goflags=${GOFLAGS:-}
goflags=${goflags//-trimpath/} # breaks tests that locate their own source

made=()
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
	[ "$keep" = 1 ] && { log "keeping trees under $workdir"; return; }
	local d
	for d in "${made[@]:-}"; do
		[ -n "$d" ] || continue
		git -C "$root" worktree remove --force "$d" >/dev/null 2>&1 || true
		rm -rf "$d" 2>/dev/null || log "could not remove $d (left for the janitor)"
	done
	git -C "$root" worktree prune >/dev/null 2>&1 || true
}
trap cleanup EXIT

# make_tree <dir>: a worktree of $ref, or a plain export when worktrees are not allowed.
make_tree() {
	local dir=$1
	if git -C "$root" worktree add --detach "$dir" "$ref" >/dev/null 2>&1; then
		log "worktree $dir"
	else
		made+=("$dir")
		mkdir -p "$dir" && git -C "$root" archive "$ref" | tar -x --exclude='.claude' --exclude='.mcp.json' -C "$dir" || return 1
		log "export $dir (git worktree unavailable here)"
		return 0
	fi
	made+=("$dir")
}

# run_go <tree> <logfile>: one `go test -v` of the current entry, prints the exit code.
run_go() {
	local tree=$1 out=$2 rc mod
	mod="$tree/$OH_MODULE_DIR"
	if [ "$OH_KIND" = selftest ]; then
		local tmo=()
		command -v timeout >/dev/null 2>&1 && tmo=(timeout "$OH_TIMEOUT")
		(cd "$mod" && GOFLAGS="$goflags" ${tmo[@]+"${tmo[@]}"} bash -c "$OH_CMD") >"$out" 2>&1
		return
	fi
	local genv=()
	[ "$OH_MODULE_DIR" = . ] || genv=(GOWORK=off)
	(cd "$mod" && env ${genv[@]+"${genv[@]}"} GOFLAGS="$goflags" go test "$OH_PKG" -run "$OH_RUN" -count=1 -v -timeout "${OH_TIMEOUT}s") >"$out" 2>&1
	rc=$?
	return $rc
}

install_replay() {
	local tree=$1 dest
	[ -n "${OH_REPLAY_DIR:-}${OH_REPLAY_GEN:-}" ] || return 0
	[ -n "${OH_TARGET:-}" ] || { log "entry $id: replay without TARGET"; return 1; }
	dest="$tree/$OH_MODULE_DIR/${OH_PKG#./}/testdata/fuzz/$OH_TARGET"
	mkdir -p "$dest"
	[ -z "${OH_REPLAY_DIR:-}" ] || cp "$entries/$OH_REPLAY_DIR"/* "$dest"/ || return 1
	[ -z "${OH_REPLAY_GEN:-}" ] || (cd "$tree" && bash "$entries/$OH_REPLAY_GEN" "$dest") || return 1
}

rows=()
bad=0 skips=0
for id in "${ids[@]}"; do
	if ! oh_parse_conf "$entries/$id.conf" >"$workdir/.parse.msg" 2>&1; then
		log "$(cat "$workdir/.parse.msg")"
		rows+=("$id|-|-|0|CONF-ERROR")
		bad=$((bad + 1))
		continue
	fi
	t0=$SECONDS
	control=NA planted=SKIP verdict="" why=""

	if [ "$OH_HEAVY" = 1 ] && [ $heavy = 0 ]; then
		verdict="SKIP ok"; why="heavy entry, pass --heavy"; control=- planted=-
	elif [ "$OH_NEEDS" != none ] && [ -z "${KEYORIX_TEST_PG_DSN:-}" ]; then
		verdict="SKIP ok"; why="needs KEYORIX_TEST_PG_DSN"; control=- planted=-
	fi

	if [ -z "$verdict" ]; then
		tree="$workdir/$id"
		if ! make_tree "$tree"; then
			verdict="PLANT-BROKEN bad"; why="could not create the tree"
		else
			log "$id: start (${OH_FAMILY:-})"
			if [ "$OH_KIND" = plant ]; then
				install_replay "$tree" || { verdict="PLANT-BROKEN bad"; why="replay install failed"; }
			fi
		fi
	fi

	if [ -z "$verdict" ]; then
		clog="$tree/.oh-control.log" plog="$tree/.oh-planted.log"
		if [ "$OH_KIND" = plant ]; then
			run_go "$tree" "$clog"; rc=$?
			control=$(oh_classify_run "$rc" "$clog")
			log "$id: control $control (rc=$rc)"
			if [ "$control" != PASS ]; then
				verdict=$(oh_verdict "$control" PASS "")
				[ "$control" = SKIP ] && why=$(grep -m1 -E '^\s+\S+\.go:[0-9]+: ' "$clog" | cut -c1-120)
			else
				patch="$entries/${OH_PATCH:-$id.patch}"
				if [ ! -f "$patch" ] || ! (cd "$tree" && git apply --whitespace=nowarn "$patch") 2>"$plog"; then
					planted=NOAPPLY; why="patch does not apply to $sha"
					log "$id: $why"
				else
					log "$id: planted defect applied ($(basename "$patch"))"
					run_go "$tree" "$plog"; rc=$?
					planted=$(oh_classify_run "$rc" "$plog")
					if [ "$planted" = FAIL ]; then
						if oh_markers_match "$plog" "$OH_MARKERS"; then planted=DETECTED; else planted=WRONGFAIL; fi
					fi
					log "$id: planted $planted (rc=$rc)"
					[ "$planted" != WRONGFAIL ] || why="failed without: $OH_MARKERS"
				fi
				verdict=$(oh_verdict "$control" "$planted" "${OH_KNOWN_BLIND:-}")
			fi
		else
			run_go "$tree" "$plog"; rc=$?
			planted=$(oh_classify_run "$rc" "$plog")
			case $planted in
			PASS)
				# A green self-test counts only when the tests it names ran and passed,
				# and none of them skipped part of the planted coverage.
				if ! oh_markers_match "$plog" "$OH_MARKERS"; then
					planted=WRONGFAIL; why="self-test passed without: $OH_MARKERS"
				elif skipped=$(grep -m1 -E '^[[:space:]]*--- SKIP' "$plog"); then
					planted=SKIP; why="self-test skipped: $(echo "$skipped" | sed -E 's/^[[:space:]]*--- SKIP: //' | cut -c1-80)"
				else
					planted=DETECTED
				fi
				;;
			FAIL) planted=PASS; why="self-test failed: see $plog" ;;
			esac
			log "$id: self-test $planted (rc=$rc)"
			verdict=$(oh_verdict NA "$planted" "")
		fi
		if [ "$planted" = PASS ] && [ -n "${OH_KNOWN_BLIND:-}" ]; then why="open finding $OH_KNOWN_BLIND"; fi
		if [ $keep = 0 ] && [ "${verdict##* }" = bad ]; then
			cp "$plog" "$workdir/$id.planted.log" 2>/dev/null && log "$id: planted-run log kept at $workdir/$id.planted.log"
		fi
	fi

	word=${verdict% *} flag=${verdict##* }
	[ "$flag" = bad ] && bad=$((bad + 1))
	[ "$word" = SKIP ] && skips=$((skips + 1))
	rows+=("$id|$control|$planted|$((SECONDS - t0))|$word${why:+  ($why)}")
done

printf '\n%-34s %-8s %-10s %5s  %s\n' ENTRY CONTROL PLANTED SECS VERDICT
for r in "${rows[@]:-}"; do
	[ -n "$r" ] || continue
	IFS='|' read -r a b c d e <<<"$r"
	printf '%-34s %-8s %-10s %5s  %s\n' "$a" "$b" "$c" "$d" "$e"
done
if [ -n "$tsv" ]; then
	{
		printf 'entry\tcontrol\tplanted\tsecs\tverdict\ttree\n'
		for r in "${rows[@]:-}"; do
			[ -n "$r" ] || continue
			IFS='|' read -r a b c d e <<<"$r"
			printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$a" "$b" "$c" "$d" "$e" "$sha"
		done
	} >"$tsv"
	log "table written to $tsv"
fi

code=$(oh_exit_code "$strict" "$bad" "$skips")
log "done tree=$sha entries=${#ids[@]} bad=$bad skipped=$skips exit=$code"
exit "$code"
