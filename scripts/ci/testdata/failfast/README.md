Recorded GitHub API responses for `failfast_cancel_test.go`, trimmed to the
fields `failfast-cancel.sh` reads.

- `runs-654613e1.json`: `GET repos/keyorixhq/keyorix/actions/runs?event=merge_group&head_sha=654613e1c08a3bdffa81816d0dee228c9bd4e6ad`
  on 2026-10-24 while that queue entry was running (CI and CodeQL in progress,
  DCO / Security Fix Regression Test / No attribution completed).
- `runs-mixed-queue.json`: the same response plus the two runs still in progress
  at that moment for the queue entry ahead of it (`9ae53ec1...`, from
  `GET .../actions/runs?event=merge_group`), as an unfiltered list would return
  them: those must never be cancelled.
