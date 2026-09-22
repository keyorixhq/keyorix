#!/usr/bin/env bash
# Parse Nuclei SARIF and ZAP JSON scan results, file GitHub issues for new
# findings -- except those matching accepted-exceptions.yaml, which are
# written to results/<sha>-accepted.txt instead.
#
# Usage: create-issues.sh [--dry-run] [nuclei.sarif|-] [zap.json|-]
#        With no positional args, uses the latest files in results/.
#        "-" means "skip this scanner". --dry-run: evaluate everything (incl.
#        accepted-exceptions matching) but never call gh and never write
#        results/<sha>-accepted.txt for real -- only print what would happen.
#
# Requires: jq, gh (GitHub CLI), GH_TOKEN in env or ~/.config/gh/
#
# Fails loudly: every gh call is unwrapped (no 2>/dev/null, no || true) — any
# gh error prints a line starting "DAST-ALERT" and exits the script non-zero,
# which the caller (scan-*.sh) propagates as its own exit code into cron.log
# and the heartbeat. A silently-swallowed 401 here is what let the token
# expire for over a week with zero visibility (2026-09-13 incident).
set -euo pipefail
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
WORKDIR="$(cd "$(dirname "$0")" && pwd)"
REPO="${GITHUB_REPO:-keyorixhq/keyorix}"
SCAN_DATE="$(date -u +%Y-%m-%d)"

# Load .env for GH_TOKEN (and NTFY_TOPIC, for lib-alert.sh) if present
if [ -f "$WORKDIR/.env" ]; then
    # shellcheck source=/dev/null
    set -a; . "$WORKDIR/.env"; set +a
fi
# shellcheck source=/dev/null
. "$WORKDIR/lib-alert.sh"

# ── --dry-run flag ───────────────────────────────────────────────────────────
DRY_RUN=0
ARGS=()
for arg in "$@"; do
    if [ "$arg" = "--dry-run" ]; then
        DRY_RUN=1
    else
        ARGS+=("$arg")
    fi
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

# ── accepted-exceptions.yaml ─────────────────────────────────────────────────
# Small hand-rolled parser (no YAML library on this box) for the flat
# "- key: value" shape accepted-exceptions.yaml is documented to use. Emits
# one compact JSON object per line; missing file -> zero exceptions, not an
# error (the mechanism must degrade gracefully, not become a hard dependency).
parse_exceptions_yaml() {
    local file="$1"
    local scanner="" plugin_id="" alert_ref="" param="" expected_risk="" url_regex="" reason="" reference=""
    local have=0
    emit_one() {
        if [ "$have" = "1" ]; then
            jq -nc --arg scanner "$scanner" --arg plugin_id "$plugin_id" --arg alert_ref "$alert_ref" \
                   --arg param "$param" --arg expected_risk "$expected_risk" --arg url_regex "$url_regex" \
                   --arg reason "$reason" --arg reference "$reference" \
                '{scanner:$scanner, plugin_id:$plugin_id, alert_ref:$alert_ref, param:$param, expected_risk:$expected_risk, url_regex:$url_regex, reason:$reason, reference:$reference}'
        fi
    }
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|'#'*) continue ;;
            '- '*)
                emit_one
                have=1
                scanner="" plugin_id="" alert_ref="" param="" expected_risk="" url_regex="" reason="" reference=""
                line="${line#- }"
                ;;
            '  '*)
                line="${line#  }"
                ;;
            *) continue ;;
        esac
        key="${line%%:*}"
        val="${line#*: }"
        case "$key" in
            scanner) scanner="$val" ;;
            plugin_id) plugin_id="$val" ;;
            alert_ref) alert_ref="$val" ;;
            param) param="$val" ;;
            expected_risk) expected_risk="$val" ;;
            url_regex) url_regex="$val" ;;
            reason) reason="$val" ;;
            reference) reference="$val" ;;
        esac
    done < "$file"
    emit_one
}

EXCEPTIONS_FILE="$WORKDIR/accepted-exceptions.yaml"
if [ -f "$EXCEPTIONS_FILE" ]; then
    EXCEPTIONS_JSON="$(parse_exceptions_yaml "$EXCEPTIONS_FILE" | jq -s '.')"
else
    EXCEPTIONS_JSON="[]"
fi

# check_exception <scanner> <plugin_id> <alert_ref> <risk_word> <params_json_array> <uris_json_array>
# Prints {"verdict":"suppress"|"escalate"|"none", "reason":..., "reference":...}
# Matching (ALL of the entry's set fields must match, most-specific ID wins):
#   - alert_ref exact match if the entry sets one; else falls back to plugin_id
#   - param, if the entry sets one, must be among the finding's instance params
#   - url_regex always applies against the finding's instance URIs
check_exception() {
    local scanner="$1" plugin_id="$2" alert_ref="$3" risk="$4" params_json="$5" uris_json="$6"
    printf '%s' "$EXCEPTIONS_JSON" | jq -c \
        --arg scanner "$scanner" --arg plugin_id "$plugin_id" --arg alert_ref "$alert_ref" \
        --arg risk "$risk" --argjson params "$params_json" --argjson uris "$uris_json" '
        def risk_rank(r): {"Informational":0,"Low":1,"Medium":2,"High":3}[r] // -1;
        (
          [ .[]
            | . as $e
            | select($e.scanner == $scanner)
            | select( ($e.alert_ref != "" and $e.alert_ref == $alert_ref)
                      or ($e.alert_ref == "" and $e.plugin_id == $plugin_id) )
            | select( $e.param == "" or ($params | any(. == $e.param)) )
            | select( $uris | any(test($e.url_regex)) )
            | $e
          ] | .[0]
        ) as $match
        | if $match == null then {verdict:"none"}
          elif risk_rank($risk) > risk_rank($match.expected_risk)
              then {verdict:"escalate", reason:$match.reason, reference:$match.reference}
          else {verdict:"suppress", reason:$match.reason, reference:$match.reference}
          end
    '
}

extract_sha() {
    basename "$1" 2>/dev/null | sed -nE 's/^.*-([0-9a-f]{12})\.[a-zA-Z0-9]+$/\1/p'
}

# run_gh <description> <gh...>
# Runs a gh command; stdout is captured and returned, stderr is folded into
# the alert message on failure. Never swallows an error. Not called at all
# in --dry-run mode.
run_gh() {
    local desc="$1"; shift
    local out rc=0
    out="$("$@" 2>&1)" || rc=$?
    if [ "$rc" -ne 0 ]; then
        dast_alert "gh $desc failed (exit $rc): $out"
        exit 1
    fi
    printf '%s\n' "$out"
}

if [ "$DRY_RUN" != "1" ]; then
    # Preflight — abort immediately if the token is bad, instead of discovering
    # it mid-run on the first issue-create call.
    if ! auth_out=$(gh auth status 2>&1); then
        dast_alert "gh auth status failed — $auth_out"
        exit 1
    fi
fi

NUCLEI_SARIF="${1:-}"
ZAP_JSON="${2:-}"
# "-" means "skip this scanner"; empty means "auto-discover latest"
if [ "$NUCLEI_SARIF" = "-" ]; then
    NUCLEI_SARIF=""
elif [ -z "$NUCLEI_SARIF" ]; then
    NUCLEI_SARIF=$(ls -t "$WORKDIR/results/nuclei-"*.sarif 2>/dev/null | head -1 || true)
fi
if [ "$ZAP_JSON" = "-" ]; then
    ZAP_JSON=""
elif [ -z "$ZAP_JSON" ]; then
    ZAP_JSON=$(ls -t "$WORKDIR/results/zap-"*.json 2>/dev/null | head -1 || true)
fi

SHA_FOR_RUN=""
[ -n "$NUCLEI_SARIF" ] && SHA_FOR_RUN="$(extract_sha "$NUCLEI_SARIF")"
if [ -z "$SHA_FOR_RUN" ] && [ -n "$ZAP_JSON" ]; then
    SHA_FOR_RUN="$(extract_sha "$ZAP_JSON")"
fi
[ -z "$SHA_FOR_RUN" ] && SHA_FOR_RUN="unknown"
ACCEPTED_OUT="$WORKDIR/results/${SHA_FOR_RUN}-accepted.txt"
ACCEPTED_COUNT=0

# file_issue <title> <body> <comma-labels>
# Checks for an existing open issue with the same title before creating.
# In --dry-run mode, never touches GitHub -- just reports the intended action.
file_issue() {
    local title="$1"
    local body="$2"
    local labels="$3"
    if [ "$DRY_RUN" = "1" ]; then
        echo "  [dry-run] would file: $title"
        return
    fi
    local existing
    existing=$(run_gh "issue list ($title)" gh issue list -R "$REPO" --label "dast" --state open \
        --search "\"$title\" in:title" --json number -q '.[0].number')
    if [ -n "$existing" ]; then
        echo "  skip (already open #$existing): $title"
        return
    fi
    local url number
    url=$(run_gh "issue create ($title)" gh issue create -R "$REPO" \
        --title "$title" \
        --label "$labels" \
        --body "$body")
    number="${url##*/}"
    echo "  filed #$number: $title"
}

echo "=== DAST → GitHub Issues ($SCAN_DATE)$([ "$DRY_RUN" = "1" ] && echo ' [DRY RUN]') ==="

if [ "$DRY_RUN" != "1" ]; then
    # Ensure labels exist (idempotent). Checked, not blindly created-and-ignored:
    # a create on an already-existing label is itself a gh error, and treating
    # that as fatal would false-alarm on every run after the first.
    existing_labels=$(run_gh "label list" gh label list -R "$REPO" --json name -q '.[].name')
    echo "$existing_labels" | grep -qx "dast" || \
        run_gh "label create dast" gh label create "dast" --description "DAST scan finding" --color "e11d48" -R "$REPO"
    echo "$existing_labels" | grep -qx "security" || \
        run_gh "label create security" gh label create "security" --description "Security finding" --color "d93f0b" -R "$REPO"
fi

# ── Nuclei SARIF ────────────────────────────────────────────────────────────
if [ -n "$NUCLEI_SARIF" ] && [ -f "$NUCLEI_SARIF" ]; then
    echo "Nuclei: $(basename "$NUCLEI_SARIF")"
    # SARIF levels: note=info/low, warning=medium, error=high/critical
    while IFS= read -r finding_json; do
        [ -z "$finding_json" ] && continue
        rule_id=$(jq -r '.rule_id' <<<"$finding_json")
        level=$(jq -r '.level' <<<"$finding_json")
        uri=$(jq -r '.uri' <<<"$finding_json")
        msg=$(jq -r '.msg' <<<"$finding_json")
        severity="Medium"; risk_word="Medium"
        if [ "$level" = "error" ]; then severity="High"; risk_word="High"; fi

        verdict_json=$(check_exception "nuclei" "$rule_id" "" "$risk_word" "[]" "$(jq -cn --arg u "$uri" '[$u]')")
        verdict=$(jq -r '.verdict' <<<"$verdict_json")
        title="[DAST] Nuclei/${rule_id}: ${msg:0:80}"

        if [ "$verdict" = "suppress" ]; then
            reason=$(jq -r '.reason' <<<"$verdict_json")
            if [ "$DRY_RUN" != "1" ]; then
                echo "$(date -u +%FT%TZ) nuclei rule_id=$rule_id uri=\"$uri\" risk=$risk_word reason=\"$reason\"" >> "$ACCEPTED_OUT"
            fi
            ACCEPTED_COUNT=$((ACCEPTED_COUNT + 1))
            echo "  suppressed (accepted exception): $title"
            continue
        fi
        if [ "$verdict" = "escalate" ]; then
            title="[exception risk escalated] $title"
        fi

        body="**Scanner**: Nuclei
**Severity**: $severity
**Rule**: \`$rule_id\`
**Target**: \`${uri:-unknown}\`
**Finding**: $msg
**Scan date**: $SCAN_DATE
**Report**: \`$(basename "$NUCLEI_SARIF")\`
> Filed automatically by the DAST rig."
        file_issue "$title" "$body" "dast,security"
    done < <(jq -c '.runs[0].results[] |
        select(.level == "warning" or .level == "error") |
        {
            rule_id: .ruleId,
            level,
            uri: (.locations[0].physicalLocation.artifactLocation.uri // ""),
            msg: (.message.text | gsub("\n";" ") | .[0:200])
        }' "$NUCLEI_SARIF" 2>/dev/null)
else
    echo "Nuclei: no SARIF found, skipping"
fi

# ── ZAP JSON ─────────────────────────────────────────────────────────────────
if [ -n "$ZAP_JSON" ] && [ -f "$ZAP_JSON" ]; then
    echo "ZAP: $(basename "$ZAP_JSON")"
    # riskcode: 0=info 1=low 2=medium 3=high  — file Low+ (>=1).
    # An alert filter (e.g. a stale ZAP-native hook) marks matching instances
    # False Positive by zeroing out .instances, but leaves the alert's own
    # riskcode/riskdesc unchanged — so also skip alerts with no real
    # instances left, or every scan re-files an issue that ZAP itself
    # already suppressed (#1249).
    while IFS= read -r finding_json; do
        [ -z "$finding_json" ] && continue
        plugin_id=$(jq -r '.plugin_id' <<<"$finding_json")
        alert_ref=$(jq -r '.alert_ref' <<<"$finding_json")
        name=$(jq -r '.name' <<<"$finding_json")
        riskdesc=$(jq -r '.riskdesc' <<<"$finding_json")
        cweid=$(jq -r '.cweid' <<<"$finding_json")
        desc=$(jq -r '.desc' <<<"$finding_json")
        solution=$(jq -r '.solution' <<<"$finding_json")
        params_json=$(jq -c '.params' <<<"$finding_json")
        uris_json=$(jq -c '.uris' <<<"$finding_json")
        risk_word="${riskdesc%% *}"

        verdict_json=$(check_exception "zap" "$plugin_id" "$alert_ref" "$risk_word" "$params_json" "$uris_json")
        verdict=$(jq -r '.verdict' <<<"$verdict_json")
        title="[DAST] ZAP/${plugin_id}: ${name}"

        if [ "$verdict" = "suppress" ]; then
            reason=$(jq -r '.reason' <<<"$verdict_json")
            if [ "$DRY_RUN" != "1" ]; then
                echo "$(date -u +%FT%TZ) zap plugin_id=$plugin_id alert_ref=$alert_ref name=\"$name\" risk=$risk_word reason=\"$reason\"" >> "$ACCEPTED_OUT"
            fi
            ACCEPTED_COUNT=$((ACCEPTED_COUNT + 1))
            echo "  suppressed (accepted exception): $title"
            continue
        fi
        if [ "$verdict" = "escalate" ]; then
            title="[exception risk escalated] $title"
        fi

        body="**Scanner**: OWASP ZAP
**Risk**: $riskdesc
**Plugin ID**: \`$plugin_id\`
**Alert Ref**: \`$alert_ref\`
**CWE**: ${cweid:-n/a}
**Description**: $desc
**Solution**: $solution
**Scan date**: $SCAN_DATE
**Report**: \`$(basename "$ZAP_JSON")\`
> Filed automatically by the DAST rig."
        file_issue "$title" "$body" "dast,security"
    done < <(jq -c '.site[].alerts[] |
        select((.riskcode | tonumber) >= 1) |
        select((.riskdesc | contains("False Positive")) | not) |
        select(((.instances // []) | length) > 0) |
        {
            plugin_id: (.pluginid | tostring),
            alert_ref: ((.alertRef // .pluginid) | tostring),
            name,
            riskdesc,
            cweid,
            desc: (.desc | gsub("<[^>]+>";"") | gsub("\n";" ") | .[0:300]),
            solution: (.solution | gsub("<[^>]+>";"") | gsub("\n";" ") | .[0:300]),
            params: ([ .instances[].param // "" ] | map(select(. != "")) | unique),
            uris: ([ .instances[].uri ] | unique)
        }' "$ZAP_JSON" 2>/dev/null)
else
    echo "ZAP: no JSON found, skipping"
fi

echo "$ACCEPTED_COUNT accepted exceptions suppressed"
echo "=== done ==="
