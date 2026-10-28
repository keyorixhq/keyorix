### Fixed

- The secret access-list, access-history, access-stats, audit-trail, access-log-export, read-summary and risk routes now answer from the kind of failure (`errors.Is` on a sentinel) instead of matching the translated error text. Under a non-English locale a real 404 or 403 on these routes is no longer a 500, and an unrelated error that says "permission denied" is no longer a 403. A storage failure while reading the secret on the export and risk routes is now a 5xx instead of a 404. An unsupported export format is a typed 400. Error texts are unchanged (ERRLOSS-SENTINELS-1).
