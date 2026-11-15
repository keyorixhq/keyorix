### Fixed
- **`GET /api/v1/dashboard/stats` no longer lists the scheduler's own `admin_job.*` heartbeats in `recentActivity`** (#4272). The array is built separately from the activity feed, so API and SDK consumers saw `admin_job.anomaly_alerts_run` every 15 s after #4184 had cleaned only the feed. An admin-triggered run is still listed; the audit log itself keeps every row.
