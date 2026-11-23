### Security

- Core now refuses a suspended or otherwise inactive acting account when approving a risk exception, revoking a break-glass activation early or closing an access-review campaign, as it already did for the other mutating entry points. REST answers this refusal 403 for approve and revoke (400 for campaign close, as for its other refusals), and a failed read of the account 503 (#4546). The transports already refused such an account at authentication; this is defence in depth.
- Bulk secret deletion by a machine identity now checks, for each secret, that the machine holds `secrets.delete` at that secret's own scope, the same rule a single delete applies. It used to rely only on the route's project-wide gate (#4546).
