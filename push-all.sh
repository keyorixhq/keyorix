#!/usr/bin/env bash
# push-all.sh — push unpushed commits in every Keyorix repo
# Usage: ./push-all.sh [--dry-run]

set -uo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
GREY='\033[0;90m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

pushed=0
skipped=0
failed=0
total=0

echo ""
echo -e "${BOLD}🔑 Keyorix push-all${NC} — base: $BASE_DIR"
$DRY_RUN && echo -e "${YELLOW}  DRY RUN — no changes will be pushed${NC}"
echo ""
echo -e "${GREY}────────────────────────────────────────────────────────${NC}"
echo ""

for dir in "$BASE_DIR"/*/; do
  [[ -d "$dir/.git" ]] || continue

  repo=$(basename "$dir")
  ((total++))

  # Fetch — warn but continue on failure
  fetch_warn=""
  if ! git -C "$dir" fetch --quiet 2>/dev/null; then
    fetch_warn="  ${YELLOW}⚠ fetch failed (using cached remote state)${NC}"
  fi

  branch=$(git -C "$dir" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  if [[ -z "$branch" || "$branch" == "HEAD" ]]; then
    echo -e "  repo ${BOLD}$repo${NC} — ${GREY}SKIPPED  detached HEAD${NC}"
    ((skipped++))
    continue
  fi

  upstream=$(git -C "$dir" rev-parse --abbrev-ref "@{u}" 2>/dev/null || echo "")
  if [[ -n "$upstream" ]]; then
    ahead=$(git -C "$dir" rev-list --count "$upstream..HEAD" 2>/dev/null || echo 0)
    behind=$(git -C "$dir" rev-list --count "HEAD..$upstream" 2>/dev/null || echo 0)
  else
    ahead=$(git -C "$dir" rev-list --count HEAD 2>/dev/null || echo 0)
    behind=0
  fi

  dirty=$(git -C "$dir" status --porcelain 2>/dev/null | wc -l | tr -d ' ')
  dirty_flag=""
  [[ "$dirty" -gt 0 ]] && dirty_flag="  ${YELLOW}⚠ $dirty uncommitted${NC}"

  if [[ "$ahead" -eq 0 ]]; then
    echo -e "  repo ${BOLD}$repo${NC} — ${GREEN}✓ SKIPPED  nothing to push${NC}  ${GREY}[$branch]${NC}$dirty_flag$fetch_warn"
    ((skipped++))
    continue
  fi

  # Has commits to push — show detail
  last=$(git -C "$dir" log -1 --format="%h %s" 2>/dev/null || echo "")
  behind_note=""
  [[ "$behind" -gt 0 ]] && behind_note="  ${RED}↓ $behind behind${NC}"

  echo -e "  repo ${BOLD}$repo${NC} — ${YELLOW}↑ PENDING  $ahead commit(s)${NC}  ${GREY}[$branch]${NC}$behind_note$dirty_flag$fetch_warn"
  echo -e "    ${GREY}last: $last${NC}"

  git -C "$dir" log --oneline "${upstream:+$upstream..}HEAD" 2>/dev/null \
    | head -10 \
    | while IFS= read -r line; do
        echo -e "      ${CYAN}$line${NC}"
      done

  if $DRY_RUN; then
    echo -e "    ${GREY}(dry-run) would push${NC}"
    ((skipped++))
    continue
  fi

  if git -C "$dir" push 2>&1 | sed 's/^/      /'; then
    echo -e "  repo ${BOLD}$repo${NC} — ${GREEN}✓ PUSHED   $ahead commit(s)${NC}"
    ((pushed++))
  else
    echo -e "  repo ${BOLD}$repo${NC} — ${RED}✗ FAILED   push error${NC}"
    ((failed++))
  fi

done

echo ""
echo -e "${GREY}────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "  ${BOLD}Summary${NC}  ($total repo(s) scanned)"
echo ""
echo -e "    ${GREEN}✓ pushed:   $pushed${NC}"
echo -e "    ${GREY}– skipped:  $skipped${NC}"
echo -e "    ${RED}✗ failed:   $failed${NC}"
echo ""
