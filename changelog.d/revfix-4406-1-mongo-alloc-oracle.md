### Testing
- **MongoDB driver fuzz harness: allocation oracle scales with connection churn.** `FuzzMongoReply` oracle (a) now counts TCP dials and budgets a fixed 32 MiB plus 12 KiB per dial, replacing the 73 MB "48 MB read buffer" bound (KFZ-2026-130 is heartbeat reconnect churn, not a large read buffer). Guarded by `TestKFZ2026130ReconnectChurnWithinBudget` and `TestAllocOverBudget`.
