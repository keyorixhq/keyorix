### Fixed
- **Storage read faults no longer answer "not found" on more endpoints.** A database
  outage used to look like "does not exist" on `GET /secret-access-requests/{id}`,
  `POST /secret-access-requests`, `POST /anomalies/{id}/acknowledge`, the by-reference
  secret read (`?ref=`), the access-review campaign endpoints (and the CSV export),
  access-review revoke/attest, `POST /folders` (parent folder), membership transitions
  and `POST /secrets/{id}/copy`. They now answer `503 storage_unavailable` with
  `Retry-After` (or 500 where the endpoint has no 503 mapping yet), and a true
  not-found keeps its 404. The by-reference gate keeps the 403 for callers without the
  permission, exactly like the by-ID gate.
- **Not-found is matched by typed error, not by message text.** Notification mark-read,
  secret-ACL, risk-exception approve, group-member, project-member, folder and membership
  handlers, the access-review status mapping, the rotation-state read and the secret
  read-denial audit classification no longer treat any error whose text contains
  "not found" as a missing target; a driver error worded that way was a 404 or an idle
  rotation state. New sentinels: `ErrAccessReviewNotFound`, `ErrMembershipTargetNotFound`,
  `ErrAnomalyAlertNotFound`, `storage.ErrNotificationNotFound`.
