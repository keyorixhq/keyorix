#!/bin/sh
# Build keyorix-server from released tags for TestUpgradePathFuzz.
# usage: build-tags.sh <outdir> <tag>...   (run from any clone of the repo)
# Each tag is checked out into a throwaway worktree under <outdir>/.wt and built
# with the tag's own source; binaries land in <outdir>/<tag>.
set -u
out=$1; shift
mkdir -p "$out/.wt"
root=$(git rev-parse --show-toplevel) || exit 1
for tag in "$@"; do
  wt="$out/.wt/$tag"
  [ -d "$wt" ] || git -C "$root" worktree add --detach "$wt" "refs/tags/$tag" >/dev/null 2>&1 || { echo "FAILED $tag (checkout)"; continue; }
  if (cd "$wt" && CGO_ENABLED=${CGO_ENABLED:-0} go build -o "$out/$tag" ./server) >"$out/.wt/$tag.build.log" 2>&1; then
    echo "BUILT $tag"
  else
    echo "FAILED $tag (see $out/.wt/$tag.build.log)"
  fi
done
