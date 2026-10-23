# CodeQL gate fixtures (real data)

Copied from the live repository on 2026-10-23 (CODEQL-PR-GATE-1), not written by hand.

- `main-go-server.sarif`: an excerpt of the SARIF of main's `/language:go-server`
  code-scanning analysis 2016612438 (CodeQL 2.27.3, commit 1a43c2dec), fetched with
  `gh api repos/keyorixhq/keyorix/code-scanning/analyses/2016612438 -H "Accept: application/sarif+json"`.
  All 7 results are kept. Trimmed: rule objects keep only `id` and the `security-severity` /
  `precision` properties; result `properties` are dropped; messages keep their first two lines;
  each code flow keeps its first two steps and its last one; `relatedLocations` keeps two.
  The merge-queue runs that motivated the change (40024087095, 40025800055) kept no artifact,
  so their own SARIF cannot be recovered; this is the same analysis on main.
- `main-javascript.sarif`: the same for main's `/language:javascript-typescript` analysis
  2016618512 (commit d5ec9da78): all 3 results, `partialFingerprints` also dropped, rules
  limited to the three the results use, each code flow kept to its first and last step. Its
  js/clear-text-logging result carries a real code flow (the Go export's does not).
- `main-alerts-open.tsv`, `main-alerts-dismissed.tsv`: main's open and dismissed CodeQL alerts
  at the same time, as the gate's own query prints them (`ruleId<TAB>path`, from
  `code-scanning/alerts?state=<state>&ref=refs/heads/main&tool_name=CodeQL`). Alert numbers,
  in order: open 1281 1280 1279 1278 1245 1209; dismissed 1247 1241 1178 1147 1116 1115 799
  788 781 605 604 20 17. Other tools' alerts (Semgrep, Scorecard, Trivy, ...) are left out:
  they never match a CodeQL rule id.

With both lists both SARIF files pass the gate (their five high results are alerts 1281, 1241,
799, 604 and 1247). Removing one alert from the baseline reproduces a "new high result" exactly as the
queue saw it.
