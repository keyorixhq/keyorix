#!/usr/bin/env bash
# Checks that a PR titled fix(...)/fix: ... has filled in the "Bug origin"
# block from .github/PULL_REQUEST_TEMPLATE.md / COMMON-RULES.md's "Definition
# of done and bug-origin tracking": Introduced-by, Detected-by, Class,
# Severity. Reads PR_TITLE/PR_BODY from the environment (set by the calling
# workflow step from github.event.pull_request.title/.body) rather than
# argv/a script-text template, so untrusted PR content is never interpreted
# as shell syntax -- only ever read as data by bash's own regex/parameter
# expansion (never eval'd, never passed to a command whose output is reused
# as code).
#
# WARN-ONLY for the first week after this lands (2026-10-03 -- 2026-10-10):
# prints what's missing but always exits 0, so no PR is blocked while authors
# get used to the template. Flip to required with the ONE-LINE change marked
# below once that week is up.
#
# Parses PR_BODY with bash's own regex matching (no grep -P / sed dialect
# dependency -- GNU and BSD grep disagree on -P support, and this script
# must behave identically on ubuntu-latest CI and a contributor's Mac).
set -euo pipefail

: "${PR_TITLE:?PR_TITLE must be set}"
: "${PR_BODY:=}"

REQUIRED_FIELDS=(Introduced-by Detected-by Class Severity)

if ! [[ "$PR_TITLE" =~ ^fix(\(.+\))?: ]]; then
    echo "Not a fix(...)/fix: PR (title: \"$PR_TITLE\") -- Bug origin block not required."
    exit 0
fi

declare -A field_value=()
while IFS= read -r line; do
    for field in "${REQUIRED_FIELDS[@]}"; do
        if [[ -z "${field_value[$field]+x}" ]] && [[ "$line" =~ ^${field}:[[:space:]]*(.*)$ ]]; then
            field_value[$field]="${BASH_REMATCH[1]}"
        fi
    done
done <<<"$PR_BODY"

missing=()
for field in "${REQUIRED_FIELDS[@]}"; do
    value="${field_value[$field]:-}"
    # Trim surrounding whitespace (read -r doesn't; the regex's [[:space:]]*
    # only trims leading).
    value="${value%"${value##*[![:space:]]}"}"
    if [[ -z "$value" ]] || [[ "$value" == *'<!--'* ]] || [[ "${value,,}" == "todo" ]]; then
        missing+=("$field")
    fi
done

if [[ ${#missing[@]} -eq 0 ]]; then
    echo "OK: Bug origin block is filled in."
    exit 0
fi

echo "::warning::This fix(...) PR's Bug origin block is missing or unfilled for: ${missing[*]}. See .github/PULL_REQUEST_TEMPLATE.md and COMMON-RULES.md's \"Definition of done and bug-origin tracking\". Warn-only for now -- will become a required check."

# WARN-ONLY: exits 0 even with missing fields (see header). To make this
# REQUIRED once the warn-only week is up, change this single line to `exit 1`.
exit 0
